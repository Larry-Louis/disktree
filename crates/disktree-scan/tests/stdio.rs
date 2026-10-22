//! Exercise the shipped executable, not just its protocol functions.
use std::io::{BufReader, Write as _};
use std::process::{Command, Stdio};

use disktree_core::remote::{Request, read_snapshot};
use disktree_core::scan::ScanOptions;

#[test]
fn executable_returns_a_read_only_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data");
    std::fs::write(&file, b"hello").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_disktree-scan"))
        .arg("--stdio-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let request = Request {
        root: Some(dir.path().into()),
        disk: false,
        options: ScanOptions {
            apparent_size: true,
            ..ScanOptions::default()
        },
    };
    let mut input = child.stdin.take().unwrap();
    serde_json::to_writer(&mut input, &request).unwrap();
    input.write_all(b"\n").unwrap();
    drop(input);
    let snapshot =
        read_snapshot(&mut BufReader::new(child.stdout.take().unwrap()))
            .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(snapshot.tree.bytes, 5);
    assert_eq!(snapshot.tree.files, 1);
    assert_eq!(snapshot.header.root, dir.path().canonicalize().unwrap());
    assert_eq!(std::fs::read(file).unwrap(), b"hello");
}
