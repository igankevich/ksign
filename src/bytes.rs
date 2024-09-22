use crate::Error;

macro_rules! struct_bytes {
    ($type:ident, $len:expr) => {
        #[derive(Clone, Copy, Eq, PartialEq, Hash)]
        pub struct $type(pub [u8; $len]);

        impl $type {
            pub const LEN: usize = $len;

            pub fn generate() -> Self {
                use rand::rngs::OsRng;
                use rand::RngCore;
                let mut data: [u8; $len] = Default::default();
                OsRng.fill_bytes(&mut data[..]);
                Self(data)
            }
        }

        impl TryFrom<&[u8]> for $type {
            type Error = LengthError;
            fn try_from(other: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(other.try_into().map_err(|_| LengthError)?))
            }
        }
    };
}

struct_bytes!(Fingerprint, 8);
struct_bytes!(Salt, 16);
struct_bytes!(Checksum, 8);

#[derive(Debug)]
pub struct LengthError;

impl From<LengthError> for Error {
    fn from(_: LengthError) -> Self {
        Error::Format
    }
}
