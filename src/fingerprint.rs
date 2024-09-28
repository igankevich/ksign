use std::any::TypeId;
use std::fmt::Display;
use std::fmt::Formatter;
use std::path::Path;

use crate::read_from_file;
use crate::Checksum;
use crate::Error;
use crate::Fingerprint;
use crate::Salt;
use crate::Signature;
use crate::SigningKey;
use crate::VerifyingKey;
use crate::KDF_ALGO_BYTES_LEN;
use crate::KDF_ROUNDS_BYTES_LEN;
use crate::PK_ALGO_BYTES_LEN;
use crate::SIGNATURE_BYTES_LEN;
use crate::SIGNING_KEY_BYTES_LEN;
use crate::VERIFYING_KEY_BYTES_LEN;

impl Fingerprint {
    /// Read fingerprint from the specified file assuming the contents of the file
    /// correspond to the supplied type id. Type id can be that of [Signature], [SigningKey]
    /// or [VerifyingKey].
    pub fn read_from_file<P: AsRef<Path>>(path: P, type_id: TypeId) -> Result<Fingerprint, Error> {
        let (bytes, _) = read_from_file(path.as_ref())?;
        let fingerprint_offset = match bytes.len() {
            SIGNATURE_BYTES_LEN if type_id == TypeId::of::<Signature>() => PK_ALGO_BYTES_LEN,
            SIGNING_KEY_BYTES_LEN if type_id == TypeId::of::<SigningKey>() => {
                PK_ALGO_BYTES_LEN
                    + KDF_ALGO_BYTES_LEN
                    + KDF_ROUNDS_BYTES_LEN
                    + Salt::LEN
                    + Checksum::LEN
            }
            VERIFYING_KEY_BYTES_LEN if type_id == TypeId::of::<VerifyingKey>() => PK_ALGO_BYTES_LEN,
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
