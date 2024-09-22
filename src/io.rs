use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

use base64ct::Base64;
use base64ct::Encoding;

use crate::Comment;
use crate::COMMENT_PREFIX;

pub(crate) fn write_to_file(
    path: &Path,
    comment: Comment,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    do_write_to_file(path, comment, bytes).map_err(|e| failed_to_write(path, e))
}

fn do_write_to_file(path: &Path, comment: Comment, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(path)?;
    comment.write(&mut file)?;
    write_bytes(&mut file, bytes)?;
    Ok(())
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<(), std::io::Error> {
    writeln!(writer, "{}", Base64::encode_string(bytes))
}

pub(crate) fn read_from_file(
    path: &Path,
    name: &str,
) -> Result<(Vec<u8>, Option<String>), std::io::Error> {
    do_read_bytes(path, name).map_err(|e| failed_to_read(path, e))
}

fn do_read_bytes(path: &Path, name: &str) -> Result<(Vec<u8>, Option<String>), std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut comment: Option<String> = None;
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.starts_with(COMMENT_PREFIX) || line.is_empty() {
            comment = Some(line[COMMENT_PREFIX.len()..].into());
            continue;
        }
        let bytes = Base64::decode_vec(line)
            .map_err(|_| std::io::Error::other(format!("invalid {}", name)))?;
        return Ok((bytes, comment));
    }
    Err(std::io::Error::other(format!("{} not found", name)))
}

fn failed_to_write(path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::other(format!("failed to write `{}`: {}", path.display(), e))
}

fn failed_to_read(path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::other(format!("failed to read `{}`: {}", path.display(), e))
}
