//! Bounded-memory SSH traversal. No Node, arena, child vector or sort:
//! the receiver owns the tree; the helper retains only its open ancestors.
use std::fs::{self, ReadDir};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::remote::{Record, send};
use crate::scan::{ScanOptions, measure, modified_seconds};

// Only unresolved multiply linked files need a file-identity table.
const MAX_PENDING_LINKS: usize = 65_536;

struct Frame {
    entries: Option<ReadDir>,
    record: Record,
}

impl Frame {
    fn open(path: &Path, name: String) -> Self {
        let entries = fs::read_dir(path);
        let failed = entries.is_err();
        Self {
            entries: entries.ok(),
            record: Record(name, 0, 0, 0, 0, failed, 0),
        }
    }
}

pub fn stream(
    root: &Path,
    options: &ScanOptions,
    out: &mut impl Write,
    live_progress: bool,
) -> io::Result<()> {
    if options.follow_links || !options.one_filesystem {
        return Err(io::Error::other(
            "Remote streaming scans never follow symlinks or cross mounts;              select that mount as a separate scan root.",
        ));
    }
    // Require a table, not just st_dev: a bind mount can have the same dev.
    let boundaries =
        crate::space::mount_boundaries_for(root).ok_or_else(|| {
            io::Error::other("cannot read remote mount boundaries")
        })?;
    let mut excluded: FxHashSet<PathBuf> = boundaries.into_iter().collect();
    excluded.extend(crate::space::never_scanned(root, root));
    stream_with_boundaries(root, options, &excluded, out, live_progress)
}

fn stream_with_boundaries(
    root: &Path,
    options: &ScanOptions,
    excluded: &FxHashSet<PathBuf>,
    out: &mut impl Write,
    live_progress: bool,
) -> io::Result<()> {
    let device = fs::metadata(root)?.dev();
    let mut frames = vec![Frame::open(root, "root".into())];
    // Ordinary single-link files need no identity storage. Forget a shared
    // inode once all its names were met, and bound unmatched identities.
    let mut links = FxHashMap::<(u64, u64), u64>::default();
    let mut directory = root.to_path_buf();
    let mut heartbeat = None::<std::time::Instant>;
    while let Some(frame) = frames.last_mut() {
        if live_progress
            && heartbeat.is_none_or(|last| {
                last.elapsed() >= crate::remote_progress::INTERVAL
            })
        {
            send(out, &serde_json::json!({"directory": directory}))?;
            // Flush on a timer even when few tree records fill the buffer.
            out.flush()?;
            heartbeat = Some(std::time::Instant::now());
        }
        let entry = match frame.entries.as_mut().and_then(Iterator::next) {
            None => {
                let frame = frames.pop().expect("frame checked above");
                send(out, &frame.record)?;
                directory.pop();
                continue;
            }
            Some(Err(_)) => {
                frame.record.5 = true;
                continue;
            }
            Some(Ok(entry)) => entry,
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            // A replacement character must never become a deletable path.
            frame.record.5 = true;
            continue;
        };
        if !options.include_hidden && name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        // Before metadata or read_dir: do not trigger an automount.
        if excluded.contains(&path) {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            frame.record.5 = true;
            continue;
        };
        if meta.dev() != device {
            continue;
        }
        if meta.is_dir() {
            if options.max_depth.is_some_and(|limit| frames.len() > limit) {
                continue;
            }
            frames.last_mut().expect("parent exists").record.6 += 1;
            directory.clone_from(&path);
            frames.push(Frame::open(&path, name.to_owned()));
            continue;
        }
        let kind = if meta.is_file() {
            1
        } else if meta.is_symlink() {
            2
        } else {
            3
        };
        let mut bytes = if kind == 3 {
            0
        } else {
            measure(&meta, options.apparent_size)
        };
        if options.dedup_hardlinks && meta.is_file() && meta.nlink() > 1 {
            let identity = (meta.dev(), meta.ino());
            if let Some(remaining) = links.get_mut(&identity) {
                bytes = 0;
                *remaining -= 1;
                if *remaining == 0 {
                    links.remove(&identity);
                }
            } else {
                if links.len() >= MAX_PENDING_LINKS {
                    return Err(io::Error::other(format!(
                        "remote hardlink tracking limit reached at {}; scan a smaller root",
                        path.display()
                    )));
                }
                links.insert(identity, meta.nlink() - 1);
            }
        }
        send(
            out,
            &Record(
                name.to_owned(),
                kind,
                bytes,
                u64::from(meta.is_file()),
                modified_seconds(&meta),
                false,
                0,
            ),
        )?;
        frames.last_mut().expect("parent exists").record.6 += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(
        root: &Path,
        options: &ScanOptions,
        excluded: &[PathBuf],
    ) -> Vec<Record> {
        let mut bytes = Vec::new();
        stream_with_boundaries(
            root,
            options,
            &excluded.iter().cloned().collect(),
            &mut bytes,
            false,
        )
        .unwrap();
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    #[test]
    fn streaming_accounts_for_hardlinks_symlinks_and_allocated_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        fs::write(&data, b"hello").unwrap();
        fs::hard_link(&data, dir.path().join("alias")).unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/leaf"), b"leaf").unwrap();
        std::os::unix::fs::symlink("sub", dir.path().join("link")).unwrap();
        let rows = records(dir.path(), &ScanOptions::default(), &[]);
        let actual: u64 =
            rows.iter().filter(|row| row.1 != 0).map(|row| row.2).sum();
        let expected =
            crate::scan::scan(dir.path(), ScanOptions::default()).unwrap();
        assert_eq!(actual, expected.bytes);
        assert_eq!(rows.iter().map(|row| row.3).sum::<u64>(), 3);
        assert_eq!(rows.iter().filter(|row| row.0 == "leaf").count(), 1);
        assert_eq!(rows.last().unwrap().6, 4);
        assert_eq!(rows.iter().filter(|row| row.0 == "sub").count(), 1);
    }

    #[test]
    fn mounted_children_are_omitted_even_on_the_same_device() {
        let dir = tempfile::tempdir().unwrap();
        let mounted = dir.path().join("mounted");
        fs::create_dir(&mounted).unwrap();
        fs::write(mounted.join("must-not-read"), b"secret").unwrap();
        fs::write(dir.path().join("keep"), b"hello").unwrap();
        let rows = records(dir.path(), &ScanOptions::default(), &[mounted]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "keep");
        assert_eq!(rows[1].6, 1);
    }

    #[test]
    fn hidden_and_depth_filters_do_not_change_postorder_counts() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".hidden"), b"hidden").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/leaf"), b"leaf").unwrap();
        fs::write(dir.path().join("visible"), b"visible").unwrap();
        let rows = records(
            dir.path(),
            &ScanOptions {
                include_hidden: false,
                max_depth: Some(0),
                ..ScanOptions::default()
            },
            &[],
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "visible");
        assert_eq!(rows[1].6, 1);
    }

    #[test]
    fn a_deep_directory_does_not_abort_the_entire_stream() {
        let dir = tempfile::tempdir().unwrap();
        let mut path = dir.path().to_path_buf();
        for _ in 0..320 {
            path.push("d");
            fs::create_dir(&path).unwrap();
        }
        fs::write(path.join("leaf"), b"found").unwrap();
        let rows = records(dir.path(), &ScanOptions::default(), &[]);
        assert_eq!(rows.iter().filter(|row| row.1 == 0).count(), 321);
        assert!(rows.iter().any(|row| row.0 == "leaf"));
        assert!(!rows.iter().any(|row| row.5));
    }

    #[test]
    fn unsafe_traversal_options_fail_before_walking() {
        let dir = tempfile::tempdir().unwrap();
        for options in [
            ScanOptions {
                follow_links: true,
                ..ScanOptions::default()
            },
            ScanOptions {
                one_filesystem: false,
                ..ScanOptions::default()
            },
        ] {
            assert!(
                stream(dir.path(), &options, &mut Vec::new(), false).is_err()
            );
        }
    }
}
