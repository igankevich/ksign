use ed25519_dalek::PUBLIC_KEY_LENGTH;
use ed25519_dalek::SECRET_KEY_LENGTH;
use ed25519_dalek::SIGNATURE_LENGTH;

use crate::Checksum;
use crate::Fingerprint;
use crate::Salt;

pub(crate) const PK_ALGO_BYTES_LEN: usize = 2;
pub(crate) const SIGNING_KEY_BYTES_LEN: usize = PK_ALGO_BYTES_LEN
    + KDF_ALGO_BYTES_LEN
    + KDF_ROUNDS_BYTES_LEN
    + Salt::LEN
    + Checksum::LEN
    + Fingerprint::LEN
    + SECRET_KEY_LENGTH
    + PUBLIC_KEY_LENGTH;
pub(crate) const VERIFYING_KEY_BYTES_LEN: usize =
    PK_ALGO_BYTES_LEN + Fingerprint::LEN + PUBLIC_KEY_LENGTH;
pub(crate) const SIGNATURE_BYTES_LEN: usize =
    PK_ALGO_BYTES_LEN + Fingerprint::LEN + SIGNATURE_LENGTH;
pub(crate) const KDF_ALGO_BYTES_LEN: usize = 2;
pub(crate) const KDF_ROUNDS_BYTES_LEN: usize = 4;

pub(crate) const PK_ALGO: &str = "Ed";
pub(crate) const KDF_ALGO: &str = "BK";
pub(crate) const COMMENT_PREFIX: &str = "untrusted comment:";
