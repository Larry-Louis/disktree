//! Read-only, versioned SSH scan protocol.
//!
//! Paths travel as JSON on stdin,
//! never as shell arguments. Postorder records avoid JSON recursion limits
//! and stream without making a second serialized copy of the whole tree.

use std::io::{self, BufRead, BufReader, Read as _, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};

use serde::{Deserialize, Serialize};

use crate::scan::ScanOptions;
#[cfg(not(unix))]
use crate::scan::scan;
use crate::space::{SpaceInfo, space_info, volume_root_for};
use crate::tree::{Node, NodeKind, aggregate};

const VERSION: u32 = 1;
const MAX_LINE: u64 = 1 << 20;
const MAX_DIAGNOSTICS: usize = 16 << 10;

// Non-interactive shells often omit ~/.local/bin. Do not require users to
// edit the server's startup files after the documented user-local install.
const REMOTE_COMMAND: &str = r#"if command -v disktree-scan >/dev/null 2>&1; then
exec disktree-scan --stdio-v1
elif [ -x "$HOME/.local/bin/disktree-scan" ]; then
exec "$HOME/.local/bin/disktree-scan" --stdio-v1
else
echo 'disktree-scan is not installed on this server.' >&2
echo 'On the server, run make install-scan from the disktree checkout.' >&2
exit 127
fi"#;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub root: Option<PathBuf>,
    pub disk: bool,
    pub options: ScanOptions,
}

// Old helpers ignore this extra field. Old clients may still half-close
// stdin; only clients opting in promise to keep it open during the scan.
#[derive(Serialize, Deserialize)]
struct SessionRequest {
    #[serde(flatten)]
    request: Request,
    #[serde(default)]
    watch_disconnect: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    version: u32,
    pub root: PathBuf,
    pub home: Option<PathBuf>,
    pub disk_root: Option<PathBuf>,
    pub space: Option<SpaceInfo>,
    pub platform: String,
    #[serde(default)]
    pub identity: Option<crate::identity::HostIdentity>,
}

#[derive(Debug)]
pub struct Snapshot {
    pub header: Header,
    pub tree: Node,
}

// Children are already on the receiver's stack; counts preserve empty dirs
// and deduplicated leaves without transmitting derived subtree totals.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Record(
    pub String,
    pub u8,
    pub u64,
    pub u64,
    pub i64,
    pub bool,
    pub usize,
);

fn json_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

pub(crate) fn send(
    out: &mut impl Write,
    value: &impl Serialize,
) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(json_error)?;
    out.write_all(b"\n")
}

fn receive<T: serde::de::DeserializeOwned>(
    input: &mut impl BufRead,
) -> io::Result<T> {
    let mut line = String::new();
    // A remote process is not trusted to allocate arbitrary amounts of RAM
    // with a single malformed record (or an accidental login banner).
    let length = input.take(MAX_LINE).read_line(&mut line)?;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "remote helper closed the connection without a complete scan",
        ));
    }
    if !line.ends_with('\n') {
        let reason = if length as u64 == MAX_LINE {
            "oversized remote record"
        } else {
            "truncated remote record"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
    }
    serde_json::from_str(&line).map_err(json_error)
}

/// The helper has exactly one operation: scan. It never removes files,
/// installs software, invokes sudo, or executes a command from the client.
pub fn serve(input: &mut impl BufRead, out: &mut impl Write) -> io::Result<()> {
    let (request, _) = read_request(input)?;
    serve_request(request, out)
}

/// Read one bounded request, including the opt-in connection lifetime.
pub fn read_request(input: &mut impl BufRead) -> io::Result<(Request, bool)> {
    let session: SessionRequest = receive(input)?;
    Ok((session.request, session.watch_disconnect))
}

/// Scan a decoded request. The standalone helper supervises its lifetime.
pub fn serve_request(request: Request, out: &mut impl Write) -> io::Result<()> {
    let home = std::env::home_dir();
    let root = request
        .root
        .or_else(|| home.clone())
        .ok_or_else(|| io::Error::other("no remote home directory"))?;
    let root = if request.disk {
        volume_root_for(&root).unwrap_or_else(|| PathBuf::from("/"))
    } else {
        root
    }
    .canonicalize()?;
    if !root.is_dir() {
        return Err(io::Error::other("scan root is not a directory"));
    }
    send(
        out,
        &Header {
            version: VERSION,
            disk_root: volume_root_for(&root),
            space: space_info(&root).ok(),
            root: root.clone(),
            home,
            platform: std::env::consts::OS.into(),
            identity: crate::identity::HostIdentity::current(),
        },
    )?;
    out.flush()?;
    #[cfg(unix)]
    crate::remote_walk::stream(&root, &request.options, out)?;
    #[cfg(not(unix))]
    write_node(out, &scan(&root, request.options)?)?;
    // An explicit terminator distinguishes a complete scan from a severed SSH
    // connection after any otherwise valid prefix of the postorder stream.
    send(out, &"done")?;
    out.flush()
}

#[cfg(not(unix))]
fn write_node(out: &mut impl Write, node: &Node) -> io::Result<()> {
    for child in &node.children {
        write_node(out, child)?;
    }
    let kind = match node.kind {
        NodeKind::Directory => 0,
        NodeKind::File => 1,
        NodeKind::Symlink => 2,
        NodeKind::Other => 3,
    };
    send(
        out,
        &Record(
            if node.name.contains('/') {
                "root".into()
            } else {
                node.name.to_string()
            },
            kind,
            node.own_bytes(),
            node.own_files(),
            node.modified,
            node.read_error,
            node.children.len(),
        ),
    )
}

pub fn read_snapshot(input: &mut impl BufRead) -> io::Result<Snapshot> {
    let header: Header = receive(input)?;
    if header.version != VERSION || !header.root.is_absolute() {
        return Err(io::Error::other("incompatible remote helper protocol"));
    }
    let mut stack = Vec::<Node>::new();
    loop {
        let value: serde_json::Value = receive(input)?;
        if value == "done" {
            break;
        }
        let Record(name, kind, bytes, files, modified, read_error, count) =
            serde_json::from_value(value).map_err(json_error)?;
        // Names must remain single components when joined to marked paths.
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains(['/', '\0'])
            || (cfg!(windows) && name.contains(['\\', ':']))
        {
            return Err(io::Error::other(format!(
                "remote name cannot be represented safely: {name:?}"
            )));
        }
        if count > stack.len() {
            return Err(io::Error::other(format!(
                "incomplete remote directory {name:?}: \
                 expected {count} children, received {}",
                stack.len(),
            )));
        }
        let kind = match kind {
            0 => NodeKind::Directory,
            1 => NodeKind::File,
            2 => NodeKind::Symlink,
            3 => NodeKind::Other,
            _ => return Err(io::Error::other("invalid remote node kind")),
        };
        if !kind.is_dir() && count != 0 {
            return Err(io::Error::other("remote leaf has children"));
        }
        let children = stack.split_off(stack.len() - count);
        let mut node = Node::entry(name, kind, bytes);
        node.files = files;
        node.modified = modified;
        node.read_error = read_error;
        node.children = children;
        stack.push(node);
    }
    if stack.len() != 1 {
        return Err(io::Error::other("incomplete remote tree"));
    }
    let mut tree = stack.pop().expect("one root checked above");
    aggregate(&mut tree, crate::tree::Metric::Bytes);
    crate::classify::classify(&mut tree);
    Ok(Snapshot { header, tree })
}

pub fn validate_host(host: &str) -> io::Result<()> {
    if host.is_empty()
        || host.starts_with('-')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._-:[]".contains(c))
    {
        return Err(io::Error::other("invalid SSH destination"));
    }
    Ok(())
}

fn read_diagnostics(mut input: impl io::Read) -> String {
    let mut tail = Vec::new();
    let mut chunk = [0_u8; 4096];
    while let Ok(length) = input.read(&mut chunk) {
        if length == 0 {
            break;
        }
        tail.extend_from_slice(&chunk[..length]);
        if tail.len() > MAX_DIAGNOSTICS {
            tail.drain(..tail.len() - MAX_DIAGNOSTICS);
        }
    }
    // Diagnostics are remote-controlled too; keep text, not terminal escapes.
    String::from_utf8_lossy(&tail)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect::<String>()
        .trim()
        .to_owned()
}

fn ssh_error(host: &str, details: &str, fallback: &io::Error) -> io::Error {
    let reason = if details.is_empty() {
        fallback.to_string()
    } else {
        details.to_owned()
    };
    let hint = if reason.contains("Permission denied")
        || reason.contains("Authentication failed")
    {
        format!(
            "Run ssh {host} in a terminal to verify your credentials. \
             When starting disktree from a terminal, SSH can ask for a \
             password there; GUI launches need an agent or SSH askpass."
        )
    } else if reason.contains("Host key verification failed") {
        format!("Run ssh {host} in a terminal and verify its host key first.")
    } else if reason.contains("not installed") || reason.contains("not found") {
        format!(
            "Install disktree-scan ON {host}, not on this computer. \
             Run make install-scan from the checkout on the server."
        )
    } else {
        "Check the server's SSH connection and disktree-scan installation."
            .into()
    };
    io::Error::other(format!("SSH {host}: {reason}\n\n{hint}"))
}

/// Cancelling a rescan or closing a window kills SSH and closes the pipe.
///
/// The helper monitors stdin for EOF even before it has a tree to write;
/// keep the request pipe open until the entire snapshot has arrived.
#[derive(Debug)]
pub struct RemoteScan {
    child: Arc<Mutex<Child>>,
    result: mpsc::Receiver<io::Result<Snapshot>>,
}

impl RemoteScan {
    pub fn spawn(host: &str, request: &Request) -> io::Result<Self> {
        validate_host(host)?;
        let archive = crate::payload::Archive::current()?;
        let remote = if archive.is_some() {
            crate::deployment::COMMAND
        } else {
            REMOTE_COMMAND
        };
        let mut command = Command::new("ssh");
        command.args([
            "-T",
            "-C",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
            "--",
            host,
            remote,
        ]);
        Self::spawn_with_archive(command, host, request, archive)
    }

    #[cfg(test)]
    fn spawn_command(
        command: Command,
        host: &str,
        request: &Request,
    ) -> io::Result<Self> {
        Self::spawn_with_archive(command, host, request, None)
    }

    fn spawn_with_archive(
        mut command: Command,
        host: &str,
        request: &Request,
        archive: Option<crate::payload::Archive>,
    ) -> io::Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().expect("piped stderr");
        // Drain concurrently: a noisy login script must not fill SSH's stderr
        // pipe and deadlock a scan. Retain only a bounded tail for the window.
        let diagnostics = std::thread::spawn(move || read_diagnostics(stderr));
        let mut stdin = child.stdin.take().expect("piped stdin");
        let request = request.clone();
        let stdout = child.stdout.take().expect("piped stdout");
        let child = Arc::new(Mutex::new(child));
        let worker = child.clone();
        let metric = request.options.metric;
        let host = host.to_owned();
        let (tx, result) = mpsc::channel();
        std::thread::spawn(move || {
            let mut input = BufReader::new(stdout);
            let snapshot = (|| {
                if let Some(archive) = archive {
                    crate::deployment::deploy(
                        &archive, &mut input, &mut stdin,
                    )?;
                }
                send(
                    &mut stdin,
                    &SessionRequest {
                        request,
                        watch_disconnect: true,
                    },
                )?;
                read_snapshot(&mut input)
            })()
            .map(|mut snapshot| {
                if metric != crate::tree::Metric::Bytes {
                    aggregate(&mut snapshot.tree, metric);
                }
                snapshot
            });
            drop(stdin);
            let mut process = worker.lock().expect("SSH process lock");
            if snapshot.is_err() {
                let _ = process.kill();
            }
            let status = process.wait();
            drop(process);
            let details = diagnostics.join().unwrap_or_default();
            let outcome = match (snapshot, status) {
                (Ok(snapshot), Ok(status)) if status.success() => Ok(snapshot),
                (Err(error), _) | (_, Err(error)) => {
                    Err(ssh_error(&host, &details, &error))
                }
                (_, Ok(status)) => Err(ssh_error(
                    &host,
                    &details,
                    &io::Error::other(format!("SSH exited with {status}")),
                )),
            };
            let _ = tx.send(outcome);
        });
        Ok(Self { child, result })
    }

    pub fn poll(&self) -> Option<io::Result<Snapshot>> {
        self.result.try_recv().ok()
    }
}

impl Drop for RemoteScan {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            root: None,
            disk: false,
            options: ScanOptions::default(),
        }
    }

    fn wait(scan: &RemoteScan) -> io::Result<Snapshot> {
        wait_for(scan, std::time::Duration::from_secs(10))
    }

    fn wait_for(
        scan: &RemoteScan,
        timeout: std::time::Duration,
    ) -> io::Result<Snapshot> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(result) = scan.poll() {
                return result;
            }
            assert!(std::time::Instant::now() < deadline, "SSH scan hung");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    fn failing_process(script: &str) -> io::Error {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        let handle =
            RemoteScan::spawn_command(command, "dev", &request()).unwrap();
        wait(&handle).unwrap_err()
    }

    #[cfg(unix)]
    #[test]
    fn ssh_authentication_diagnostics_reach_the_caller() {
        let error = failing_process(
            "read -r request; echo 'Permission denied (publickey,password).' \
             >&2; exit 255",
        )
        .to_string();
        assert!(error.contains("Permission denied"), "{error}");
        assert!(error.contains("verify your credentials"), "{error}");
        assert!(!error.contains("truncated"), "{error}");
        assert!(!error.contains("Install disktree-scan"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn missing_helper_diagnostics_name_the_server() {
        let error = failing_process(
            "read -r request; echo 'disktree-scan: command not found' \
             >&2; exit 127",
        )
        .to_string();
        assert!(error.contains("command not found"), "{error}");
        assert!(error.contains("ON dev, not on this computer"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn banner_and_truncated_output_are_reported_without_a_hang() {
        for output in ["hello", "hello\\n"] {
            let error =
                failing_process(&format!("read -r request; printf '{output}'"))
                    .to_string();
            assert!(error.contains("SSH dev:"), "{error}");
        }
    }

    #[test]
    fn diagnostics_are_bounded_and_controls_are_stripped() {
        let mut data = vec![b'x'; MAX_DIAGNOSTICS * 4];
        data.extend_from_slice(b"\x1b[31mPermission denied\r\n");
        let text = read_diagnostics(data.as_slice());
        assert!(text.len() <= MAX_DIAGNOSTICS);
        assert!(text.ends_with("Permission denied"));
        assert!(!text.contains(['\x1b', '\r']));
    }

    // Uses an explicitly supplied config, never the user's default SSH host.
    #[cfg(unix)]
    #[test]
    #[ignore = "requires DISKTREE_TEST_SSH_CONFIG with isolated sshd"]
    fn real_ssh_transport_returns_a_snapshot() {
        let config = std::env::var("DISKTREE_TEST_SSH_CONFIG").unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep"), b"hello").unwrap();
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let helper = std::env::var("DISKTREE_TEST_HELPER").unwrap();
        std::os::unix::fs::symlink(helper, bin.join("disktree-scan")).unwrap();
        // Force the documented ~/.local/bin fallback, not the ambient PATH.
        let remote = format!(
            "HOME={} PATH=/nonexistent; export HOME PATH;\n{REMOTE_COMMAND}",
            crate::export::shell_quote(home.path().to_str().unwrap()),
        );
        let mut command = Command::new("ssh");
        command.args(["-F", &config, "-T", "-C", "fixture", &remote]);
        let request = Request {
            root: Some(dir.path().into()),
            options: ScanOptions {
                apparent_size: true,
                ..ScanOptions::default()
            },
            ..request()
        };
        let handle =
            RemoteScan::spawn_command(command, "fixture", &request).unwrap();
        let snapshot = wait(&handle).unwrap();
        assert_eq!(snapshot.tree.bytes, 5);
        assert_eq!(snapshot.tree.files, 1);
        assert_eq!(std::fs::read(dir.path().join("keep")).unwrap(), b"hello");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires DISKTREE_TEST_SSH_CONFIG with isolated sshd"]
    fn real_ssh_transport_reports_auth_and_install_errors() {
        let config = std::env::var("DISKTREE_TEST_SSH_CONFIG").unwrap();
        let mut denied = Command::new("ssh");
        denied.args([
            "-F",
            &config,
            "-T",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PreferredAuthentications=none",
            "fixture",
            REMOTE_COMMAND,
        ]);
        let scan =
            RemoteScan::spawn_command(denied, "fixture", &request()).unwrap();
        let error = wait(&scan).unwrap_err().to_string();
        assert!(error.contains("Permission denied"), "{error}");

        let home = tempfile::tempdir().unwrap();
        let remote = format!(
            "HOME={} PATH=/nonexistent; export HOME PATH;\n{REMOTE_COMMAND}",
            crate::export::shell_quote(home.path().to_str().unwrap()),
        );
        let mut missing = Command::new("ssh");
        missing.args(["-F", &config, "-T", "fixture", &remote]);
        let scan =
            RemoteScan::spawn_command(missing, "fixture", &request()).unwrap();
        let error = wait(&scan).unwrap_err().to_string();
        assert!(error.contains("not installed on this server"), "{error}");
        assert!(error.contains("ON fixture"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires isolated sshd and DISKTREE_TEST_ARCHIVE"]
    fn real_ssh_transport_bootstraps_and_checks_cached_payloads() {
        let config = std::env::var("DISKTREE_TEST_SSH_CONFIG").unwrap();
        let archive = crate::payload::Archive::open(
            PathBuf::from(std::env::var("DISKTREE_TEST_ARCHIVE").unwrap())
                .as_path(),
        )
        .unwrap()
        .unwrap();
        let home = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(data.path().join("keep"), b"hello").unwrap();
        let cache = home.path().join("cache");
        let remote = format!(
            "HOME={} XDG_CACHE_HOME={}; export HOME XDG_CACHE_HOME;\n{}",
            crate::export::shell_quote(home.path().to_str().unwrap()),
            crate::export::shell_quote(cache.to_str().unwrap()),
            crate::deployment::COMMAND,
        );
        let arch = std::env::consts::ARCH;
        let (entry, bytes) = archive.load(arch).unwrap();
        let cached = cache
            .join("disktree/ssh")
            .join(&entry.sha256)
            .join("disktree-scan");
        let request = Request {
            root: Some(data.path().into()),
            options: ScanOptions {
                apparent_size: true,
                ..ScanOptions::default()
            },
            ..request()
        };
        for attempt in 0..3 {
            let mut command = Command::new("ssh");
            command.args(["-F", &config, "-T", "fixture", &remote]);
            let handle = RemoteScan::spawn_with_archive(
                command,
                "fixture",
                &request,
                Some(archive.clone()),
            )
            .unwrap();
            let snapshot = wait(&handle).unwrap();
            assert_eq!(snapshot.tree.bytes, 5);
            assert!(snapshot.header.identity.is_some());
            assert_eq!(std::fs::read(&cached).unwrap(), bytes);
            if attempt == 1 {
                // A damaged cache must be repaired, never executed.
                let damaged = cached.with_extension("damaged");
                std::fs::write(&damaged, b"broken").unwrap();
                std::fs::rename(damaged, &cached).unwrap();
            }
        }
        assert!(!home.path().join(".local/bin/disktree-scan").exists());
    }

    /// Explicit opt-in only: never contact a real machine in the test gate.
    #[test]
    #[ignore = "requires DISKTREE_TEST_SSH_HOST and DISKTREE_TEST_SSH_ROOT"]
    fn live_ssh_scan_uses_the_production_transport() {
        let host = std::env::var("DISKTREE_TEST_SSH_HOST").unwrap();
        let root = std::env::var("DISKTREE_TEST_SSH_ROOT").unwrap();
        let scan = RemoteScan::spawn(
            &host,
            &Request {
                root: Some(PathBuf::from(&root)),
                ..request()
            },
        )
        .unwrap();
        let snapshot =
            wait_for(&scan, std::time::Duration::from_mins(3)).unwrap();
        assert!(snapshot.tree.is_dir());
        assert!(snapshot.header.root.is_absolute());
        println!(
            "SSH {}: {} — {} bytes, {} files, {} directories; space: {:?}",
            host,
            snapshot.header.root.display(),
            snapshot.tree.bytes,
            snapshot.tree.files,
            snapshot.tree.dirs,
            snapshot.header.space,
        );
    }

    #[test]
    fn rejects_ssh_options_and_shell_syntax() {
        for host in ["-oProxyCommand=oops", "dev; touch x", "dev\nother", ""] {
            assert!(validate_host(host).is_err());
        }
        for host in ["dev", "user@dev", "[::1]"] {
            assert!(validate_host(host).is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_backslashes_in_names_roundtrip_without_becoming_separators() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(r"back\slash"), b"x").unwrap();
        let request = Request {
            root: Some(dir.path().into()),
            disk: false,
            options: ScanOptions {
                apparent_size: true,
                ..ScanOptions::default()
            },
        };
        let mut input = Vec::new();
        send(&mut input, &request).unwrap();
        let mut data = Vec::new();
        serve(&mut input.as_slice(), &mut data).unwrap();
        let snapshot = read_snapshot(&mut data.as_slice()).unwrap();
        assert_eq!(snapshot.tree.bytes, 1);
        assert!(snapshot.tree.child_named(r"back\slash").is_some());
    }

    #[test]
    fn protocol_roundtrip_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a ' file"), b"hello").unwrap();
        std::fs::create_dir(dir.path().join("empty")).unwrap();
        let request = Request {
            root: Some(dir.path().into()),
            disk: false,
            options: ScanOptions {
                apparent_size: true,
                ..ScanOptions::default()
            },
        };
        let mut data = Vec::new();
        let mut input = Vec::new();
        send(&mut input, &request).unwrap();
        serve(&mut input.as_slice(), &mut data).unwrap();
        let snapshot = read_snapshot(&mut data.as_slice()).unwrap();
        assert_eq!(snapshot.tree.bytes, 5);
        assert_eq!(snapshot.tree.files, 1);
        assert!(snapshot.tree.child_named("empty").unwrap().is_dir());
        data.truncate(data.len() - 7);
        assert!(read_snapshot(&mut data.as_slice()).is_err());
        assert!(dir.path().join("a ' file").exists());
    }
}
