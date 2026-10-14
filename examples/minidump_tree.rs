//! Usage: cargo run --release --example minidump_tree -- chrome.DMP [max_items]
use bxmap::minidump::Minidump;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: minidump_tree <file.dmp> [max_items]");
    let max: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20);
    let md = Minidump::open(&path)?;
    print!("{}", md.render_tree(max));
    Ok(())
}
