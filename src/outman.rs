use anyhow::Result;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn write_sock(outdir: PathBuf, fd: i32, name: &String, inside: bool, buf: &[u8]) -> Result<()> {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let name = format!("{}.{}.{}.{}", name, fd, t, inside);
    let path = outdir.join(name);
    let mut file = OpenOptions::new().write(true).create(true).open(path)?;
    file.write_all(buf)?;

    Ok(())
}
