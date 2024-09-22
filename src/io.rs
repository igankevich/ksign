use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

use base64ct::Base64;
use base64ct::Encoding;

use crate::Error;
use crate::UntrustedComment;
use crate::COMMENT_PREFIX;

/// Represents an object that can be written to file and read from file.
pub trait IO {
    /// Convert to bytes.
    fn to_bytes(&self) -> Vec<u8>;
    /// Convert from bytes with optional comment.
    fn from_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self, Error>
    where
        Self: Sized;
    /// Get human-readable file comment.
    fn get_comment(&self) -> UntrustedComment;

    /// Write byte representation to file.
    fn write_to_file(&self, path: &Path) -> Result<(), Error> {
        Ok(write_to_file(
            path,
            self.get_comment(),
            self.to_bytes().as_slice(),
        )?)
    }

    /// Read byte representation from file.
    fn read_from_file(path: &Path) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let (bytes, comment) = read_from_file(path)?;
        Self::from_bytes(&bytes, comment)
    }
}

pub(crate) fn write_to_file(
    path: &Path,
    comment: UntrustedComment,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    do_write_to_file(path, comment, bytes).map_err(|e| failed_to_write(path, e))
}

fn do_write_to_file(
    path: &Path,
    comment: UntrustedComment,
    bytes: &[u8],
) -> Result<(), std::io::Error> {
    let mut file = File::create(path)?;
    comment.write(&mut file)?;
    write_bytes(&mut file, bytes)?;
    Ok(())
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<(), std::io::Error> {
    writeln!(writer, "{}", Base64::encode_string(bytes))
}

pub(crate) fn read_from_file(path: &Path) -> Result<(Vec<u8>, Option<String>), std::io::Error> {
    do_read_bytes(path).map_err(|e| failed_to_read(path, e))
}

fn do_read_bytes(path: &Path) -> Result<(Vec<u8>, Option<String>), std::io::Error> {
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
        let bytes =
            Base64::decode_vec(line).map_err(|e| std::io::Error::other(format!("{}", e)))?;
        return Ok((bytes, comment));
    }
    Err(std::io::Error::other("base64-encoded data not found"))
}

fn failed_to_write(path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::other(format!("failed to write `{}`: {}", path.display(), e))
}

fn failed_to_read(path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::other(format!("failed to read `{}`: {}", path.display(), e))
}
