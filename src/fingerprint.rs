use std::fmt::Display;
use std::fmt::Formatter;
use std::path::Path;

use crate::read_from_file;
use crate::Error;
use crate::Fingerprint;
use crate::Checksum;
use crate::Salt;
use crate::PK_ALGO_BYTES_LEN;
use crate::SIGNATURE_BYTES_LEN;
use crate::SIGNING_KEY_BYTES_LEN;
use crate::VERIFYING_KEY_BYTES_LEN;

impl Fingerprint {
    pub fn read_from_file(path: &Path) -> Result<Fingerprint, Error> {
        let (bytes, _) = read_from_file(path, "signature/verifying key/signing key")?;
        let fingerprint_offset = match bytes.len() {
            SIGNATURE_BYTES_LEN => PK_ALGO_BYTES_LEN,
            SIGNING_KEY_BYTES_LEN => 8 + Salt::LEN + Checksum::LEN,
            VERIFYING_KEY_BYTES_LEN => PK_ALGO_BYTES_LEN,
            _ => return Err(Error::Format),
        };
        let fingerprint: Fingerprint = bytes
            .get(fingerprint_offset..(fingerprint_offset + Fingerprint::LEN))
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?;
        Ok(fingerprint)
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
