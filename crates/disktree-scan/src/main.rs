//! Headless helper: no GPUI dependency and no destructive command surface.
use std::io::{self, BufWriter};

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--stdio-v1"] {
        disktree_core::remote::serve(
            &mut io::stdin().lock(),
            &mut BufWriter::new(io::stdout().lock()),
        )
    } else if args.is_empty() || args == ["--help"] || args == ["-h"] {
        println!(
            "disktree-scan — read-only SSH scan helper\n\
                  usage: disktree-scan --stdio-v1\n\
                  Used by: disktree ssh HOST [PATH]\n\
                  Reads a versioned JSON request from stdin and streams a \
                  snapshot to stdout. No deletion commands."
        );
        Ok(())
    } else {
        Err(io::Error::other("unknown option; try --help"))
    }
}
