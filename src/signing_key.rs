use std::path::Path;

use ed25519_dalek::Signer;
use ed25519_dalek::SECRET_KEY_LENGTH;
use rand::rngs::OsRng;
use sha2::Digest;
use sha2::Sha512;

use crate::read_from_file;
use crate::write_to_file;
use crate::Checksum;
use crate::Comment;
use crate::Error;
use crate::Fingerprint;
use crate::Salt;
use crate::Signature;
use crate::VerifyingKey;
use crate::KDF_ALGO;
use crate::PK_ALGO;
use crate::SIGNING_KEY_BYTES_LEN;

pub struct SigningKey {
    pub(crate) signing_key: ed25519_dalek::SigningKey,
    pub(crate) salt: Salt,
    pub(crate) checksum: Checksum,
    pub(crate) fingerprint: Fingerprint,
    pub(crate) comment: Option<String>,
}

impl SigningKey {
    #[allow(clippy::unwrap_used)]
    pub fn generate(comment: Option<String>) -> Self {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let salt = Salt::generate();
        let fingerprint = Fingerprint::generate();
        let mut hasher = Sha512::new();
        hasher.update(signing_key.as_bytes());
        let checksum: Checksum = hasher.finalize()[..Checksum::LEN].try_into().unwrap();
        Self {
            signing_key,
            salt,
            checksum,
            fingerprint,
            comment: comment.map(|s| s.replace('\n', " ")),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.signing_key.sign(message);
        Signature {
            signature,
            fingerprint: self.fingerprint,
            comment: self.comment.clone(),
        }
    }

    pub fn to_verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            verifying_key: self.signing_key.verifying_key(),
            fingerprint: self.fingerprint,
            comment: self.comment.clone(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNING_KEY_BYTES_LEN);
        bytes.extend(PK_ALGO.bytes());
        bytes.extend(KDF_ALGO.bytes());
        bytes.extend([0, 0, 0, 0]);
        bytes.extend(self.salt.0);
        bytes.extend(self.checksum.0);
        bytes.extend(self.fingerprint.0);
        bytes.extend(self.signing_key.as_bytes());
        bytes.extend(self.signing_key.verifying_key().as_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self, Error> {
        let algo =
            std::str::from_utf8(bytes.get(..2).ok_or(Error::Format)?).map_err(|_| Error::Format)?;
        if algo != PK_ALGO {
            return Err(Error::Algorithm);
        }
        let algo = std::str::from_utf8(bytes.get(2..4).ok_or(Error::Format)?)
            .map_err(|_| Error::Format)?;
        if algo != KDF_ALGO {
            return Err(Error::Algorithm);
        }
        let kdf_rounds = u32::from_be_bytes(
            bytes
                .get(4..8)
                .ok_or(Error::Format)?
                .try_into()
                .map_err(|_| Error::Format)?,
        );
        if kdf_rounds != 0 {
            return Err(Error::Algorithm);
        }
        const SALT_OFFSET: usize = 8;
        const CHECKSUM_OFFSET: usize = SALT_OFFSET + Salt::LEN;
        const FINGERPRINT_OFFSET: usize = CHECKSUM_OFFSET + Checksum::LEN;
        const SIGNING_KEY_OFFSET: usize = FINGERPRINT_OFFSET + Fingerprint::LEN;
        const VERIFYING_KEY_OFFSET: usize = SIGNING_KEY_OFFSET + SECRET_KEY_LENGTH;
        let salt: Salt = bytes
            .get(SALT_OFFSET..CHECKSUM_OFFSET)
            .ok_or(Error::Format)?
            .try_into()?;
        let checksum: Checksum = bytes
            .get(CHECKSUM_OFFSET..FINGERPRINT_OFFSET)
            .ok_or(Error::Format)?
            .try_into()?;
        let fingerprint: Fingerprint = bytes
            .get(FINGERPRINT_OFFSET..SIGNING_KEY_OFFSET)
            .ok_or(Error::Format)?
            .try_into()?;
        let signing_key: ed25519_dalek::SigningKey = bytes
            .get(SIGNING_KEY_OFFSET..VERIFYING_KEY_OFFSET)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?;
        let verifying_key: ed25519_dalek::VerifyingKey = bytes
            .get(VERIFYING_KEY_OFFSET..)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?;
        if signing_key.verifying_key() != verifying_key {
            return Err(Error::Format);
        }
        Ok(Self {
            signing_key,
            salt,
            fingerprint,
            checksum,
            comment,
        })
    }

    pub fn comment(&self) -> Comment {
        match self.comment.as_ref() {
            Some(s) => Comment::String(s),
            None => Comment::Fingerprint("private key", self.fingerprint),
        }
    }

    pub fn write_to_file(&self, path: &Path) -> Result<(), Error> {
        Ok(write_to_file(
            path,
            self.comment(),
            self.to_bytes().as_slice(),
        )?)
    }

    pub fn read_from_file(path: &Path) -> Result<Self, Error> {
        let (bytes, comment) = read_from_file(path, "signing key")?;
        Self::from_bytes(&bytes, comment)
    }
}
