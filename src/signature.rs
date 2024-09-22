use std::path::Path;

use crate::read_from_file;
use crate::write_to_file;
use crate::Comment;
use crate::Error;
use crate::Fingerprint;
use crate::PK_ALGO;
use crate::SIGNATURE_BYTES_LEN;

pub struct Signature {
    pub(crate) signature: ed25519_dalek::Signature,
    pub(crate) fingerprint: Fingerprint,
    pub(crate) comment: Option<String>,
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNATURE_BYTES_LEN);
        bytes.extend(PK_ALGO.bytes());
        bytes.extend(self.fingerprint.0);
        bytes.extend(self.signature.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self, Error> {
        let algo = std::str::from_utf8(bytes.get(..2).ok_or(Error::Format)?)
            .map_err(|_| Error::Format)?;
        if algo != PK_ALGO {
            return Err(Error::Algorithm);
        }
        const FINGERPRINT_OFFSET: usize = 2;
        const SIGNATURE_OFFSET: usize = FINGERPRINT_OFFSET + Fingerprint::LEN;
        let fingerprint: Fingerprint = bytes
            .get(FINGERPRINT_OFFSET..SIGNATURE_OFFSET)
            .ok_or(Error::Format)?
            .try_into()?;
        let signature: ed25519_dalek::Signature = bytes
            .get(SIGNATURE_OFFSET..)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?;
        Ok(Self {
            fingerprint,
            signature,
            comment,
        })
    }

    pub fn comment(&self) -> Comment {
        match self.comment.as_ref() {
            Some(s) => Comment::String(s),
            None => Comment::Fingerprint("signed by key", self.fingerprint),
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn write_to_file(&self, path: &Path) -> Result<(), Error> {
        Ok(write_to_file(path, self.comment(), self.to_bytes().as_slice())?)
    }

    pub fn read_from_file(path: &Path) -> Result<Self, Error> {
        let (bytes, comment) = read_from_file(path, "signature")?;
        Self::from_bytes(&bytes, comment)
    }
}
