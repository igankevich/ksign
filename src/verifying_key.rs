use std::path::Path;

use ed25519_dalek::Verifier;

use crate::read_from_file;
use crate::write_to_file;
use crate::Comment;
use crate::Fingerprint;
use crate::Signature;
use crate::PK_ALGO;
use crate::VERIFYING_KEY_BYTES_LEN;
use crate::Error;

pub struct VerifyingKey {
    pub(crate) verifying_key: ed25519_dalek::VerifyingKey,
    pub(crate) fingerprint: Fingerprint,
    pub(crate) comment: Option<String>,
}

impl VerifyingKey {
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.verifying_key
            .verify(message, &signature.signature)
            .map_err(|_| Error::Verification)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(VERIFYING_KEY_BYTES_LEN);
        bytes.extend(PK_ALGO.bytes());
        bytes.extend(self.fingerprint.0);
        bytes.extend(self.verifying_key.as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self, Error> {
        let algo = std::str::from_utf8(bytes.get(..2).ok_or(Error::Format)?)
            .map_err(|_| Error::Format)?;
        if algo != PK_ALGO {
            return Err(Error::Algorithm);
        }
        const FINGERPRINT_OFFSET: usize = 2;
        const VERIFYING_KEY_OFFSET: usize = FINGERPRINT_OFFSET + Fingerprint::LEN;
        let fingerprint: Fingerprint = bytes
            .get(FINGERPRINT_OFFSET..VERIFYING_KEY_OFFSET)
            .ok_or(Error::Format)?
            .try_into()?;
        let verifying_key: ed25519_dalek::VerifyingKey = bytes
            .get(VERIFYING_KEY_OFFSET..)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?;
        Ok(Self {
            verifying_key,
            fingerprint,
            comment,
        })
    }

    pub fn comment(&self) -> Comment {
        match self.comment.as_ref() {
            Some(s) => Comment::String(s),
            None => Comment::Fingerprint("public key", self.fingerprint),
        }
    }

    pub fn write_to_file(&self, path: &Path) -> Result<(), Error> {
        Ok(write_to_file(path, self.comment(), self.to_bytes().as_slice())?)
    }

    pub fn read_from_file(path: &Path) -> Result<Self, Error> {
        let (bytes, comment) = read_from_file(path, "verifying key")?;
        Self::from_bytes(&bytes, comment)
    }
}
