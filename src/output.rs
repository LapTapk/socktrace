use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn safe_name(input: &str) -> String {
    const MAX_LEN: usize = 255;

    let mut out = String::with_capacity(input.len());

    for c in input.chars() {
        let safe = match c {
            '/' | '\\' => '_',
            ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        };

        out.push(safe);

        if out.len() >= MAX_LEN {
            break;
        }
    }

    if out.is_empty() { "_".to_string() } else { out }
}

pub fn write_sock(
    outdir: &PathBuf,
    fd: i32,
    name: &String,
    inside: bool,
    buf: &[u8],
) -> Result<()> {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let name = format!(
        "{}.{}.{}.{}",
        safe_name(name),
        fd,
        t,
        if inside { "in" } else { "out" }
    );
    let path = outdir.join(name);
    let path_as_str = path
        .as_os_str()
        .to_str()
        .get_or_insert("<could not decode OSString>")
        .to_owned();

    let mut file = crate::ctx!(
        OpenOptions::new().write(true).create(true).open(&path),
        "Opening {} failed",
        path_as_str
    )?;

    crate::ctx!(
        file.write_all(buf),
        "Could not write file {}, ",
        path_as_str
    )?;

    Ok(())
}
