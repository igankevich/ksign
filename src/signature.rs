use crate::Error;
use crate::Fingerprint;
use crate::UntrustedComment;
use crate::IO;
use crate::PK_ALGO;
use crate::SIGNATURE_BYTES_LEN;

/// Ed25519 signature.
pub struct Signature {
    pub(crate) signature: ed25519_dalek::Signature,
    pub(crate) fingerprint: Fingerprint,
    pub(crate) comment: Option<String>,
}

impl Signature {
    /// Get underlying signature.
    pub fn signature(&self) -> &ed25519_dalek::Signature {
        &self.signature
    }

    /// Get fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Get comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }
}

impl IO for Signature {
    fn get_comment(&self) -> UntrustedComment {
        match self.comment.as_ref() {
            Some(s) => UntrustedComment::String(s),
            None => UntrustedComment::Fingerprint("signed by key", self.fingerprint),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNATURE_BYTES_LEN);
        bytes.extend(PK_ALGO.bytes());
        bytes.extend(self.fingerprint.0);
        bytes.extend(self.signature.to_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self, Error> {
        let algo =
            std::str::from_utf8(bytes.get(..2).ok_or(Error::Format)?).map_err(|_| Error::Format)?;
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
}
