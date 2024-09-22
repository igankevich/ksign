use crate::Error;

macro_rules! struct_bytes {
    ($type:ident, $len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, PartialEq, Hash)]
        pub struct $type(pub [u8; $len]);

        impl $type {
            /// Length in bytes.
            pub const LEN: usize = $len;
        }

        impl TryFrom<&[u8]> for $type {
            type Error = Error;
            fn try_from(other: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(other.try_into().map_err(|_| Error::Format)?))
            }
        }
    };
}

macro_rules! struct_bytes_generate {
    ($type:ident, $len:expr) => {
        impl $type {
            /// Generate from random bytes.
            pub fn generate() -> Self {
                use rand::rngs::OsRng;
                use rand::RngCore;
                let mut data: [u8; $len] = Default::default();
                OsRng.fill_bytes(&mut data[..]);
                Self(data)
            }
        }
    };
}

struct_bytes!(
    Fingerprint,
    8,
    "Fingerprint generated along with the signing key."
);
struct_bytes_generate!(Fingerprint, 8);

struct_bytes!(Salt, 16, "Salt generated along with the signing key.");
struct_bytes_generate!(Salt, 16);

struct_bytes!(Checksum, 8, "Checksum of the signing key.");
