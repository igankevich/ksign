use std::ffi::OsStr;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use base64ct::Base64;
use base64ct::Encoding;
use clap::Parser;
use clap::Subcommand;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use ed25519_dalek::SIGNATURE_LENGTH;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Digest;
use sha2::Sha512;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate {
        verifying_key_file: PathBuf,
        signing_key_file: PathBuf,
    },
    Sign {
        message_file: PathBuf,
        signing_key_file: PathBuf,
    },
    Verify {
        message_file: PathBuf,
        verifying_key_file: PathBuf,
    },
    Fingerprint {
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    match do_main() {
        Ok(ret) => ret,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn do_main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args = Args::parse();
    match args.command {
        Command::Generate {
            verifying_key_file,
            signing_key_file,
        } => {
            let signing_key = SigningKey::generate();
            let verifying_key = signing_key.to_verifying_key();
            signing_key.write_to_file(signing_key_file.as_path())?;
            verifying_key.write_to_file(verifying_key_file.as_path())?;
        }
        Command::Sign {
            message_file,
            signing_key_file,
        } => {
            let message = std::fs::read(message_file.as_path())
                .map_err(|e| failed_to_read(message_file.as_path(), e))?;
            let signing_key = SigningKey::read_from_file(signing_key_file.as_path())?;
            let signature = signing_key.sign(&message);
            let signature_file = to_signature_file(message_file.as_path());
            signature.write_to_file(signature_file.as_path())?;
        }
        Command::Verify {
            message_file,
            verifying_key_file,
        } => {
            let message = std::fs::read(message_file.as_path())
                .map_err(|e| failed_to_read(message_file.as_path(), e))?;
            let signature_file = to_signature_file(message_file.as_path());
            let signature = Signature::read_from_file(signature_file.as_path())?;
            let verifying_key = VerifyingKey::read_from_file(verifying_key_file.as_path())?;
            verifying_key.verify(&message, &signature)?;
        }
        Command::Fingerprint { file } => {
            let bytes = read_bytes(file.as_path(), "signature/verifying key/signing key")?;
            let fingerprint_offset = match bytes.len() {
                SIGNATURE_BYTES_LEN => PK_ALGO_BYTES_LEN,
                SIGNING_KEY_BYTES_LEN => 8 + Salt::LEN + Checksum::LEN,
                VERIFYING_KEY_BYTES_LEN => PK_ALGO_BYTES_LEN,
                _ => return Err("invalid length".into()),
            };
            let fingerprint: Fingerprint = bytes
                .get(fingerprint_offset..(fingerprint_offset + Fingerprint::LEN))
                .ok_or_else(|| "invalid length")?
                .try_into()
                .map_err(|_| "invalid length")?;
            println!("{}", hex::encode(fingerprint.as_bytes()));
        }
    }
    Ok(ExitCode::SUCCESS)
}

type Fingerprint = Bytes<8>;
type Salt = Bytes<16>;
type Checksum = Bytes<8>;

struct SigningKey {
    signing_key: ed25519_dalek::SigningKey,
    salt: Salt,
    checksum: Checksum,
    fingerprint: Fingerprint,
}

impl SigningKey {
    fn generate() -> Self {
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
        }
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.signing_key.sign(message);
        Signature {
            signature,
            fingerprint: self.fingerprint,
        }
    }

    fn to_verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            verifying_key: self.signing_key.verifying_key(),
            fingerprint: self.fingerprint,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNING_KEY_BYTES_LEN);
        bytes.extend(PK_ALGO.bytes());
        bytes.extend(KDF_ALGO.bytes());
        bytes.extend([0, 0, 0, 0]);
        bytes.extend(self.salt.as_bytes());
        bytes.extend(self.checksum.as_bytes());
        bytes.extend(self.fingerprint.as_bytes());
        bytes.extend(self.signing_key.as_bytes());
        bytes.extend(self.signing_key.verifying_key().as_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let algo = std::str::from_utf8(bytes.get(..2).ok_or_else(invalid_key)?)
            .map_err(|_| invalid_key())?;
        if algo != PK_ALGO {
            return Err(unsupported_format());
        }
        let algo = std::str::from_utf8(bytes.get(2..4).ok_or_else(invalid_key)?)
            .map_err(|_| invalid_key())?;
        if algo != KDF_ALGO {
            return Err(unsupported_format());
        }
        let kdf_rounds = u32::from_be_bytes(
            bytes
                .get(4..8)
                .ok_or_else(invalid_key)?
                .try_into()
                .map_err(|_| invalid_key())?,
        );
        if kdf_rounds != 0 {
            return Err(unsupported_format());
        }
        const SALT_OFFSET: usize = 8;
        const CHECKSUM_OFFSET: usize = SALT_OFFSET + Salt::LEN;
        const FINGERPRINT_OFFSET: usize = CHECKSUM_OFFSET + Checksum::LEN;
        const SIGNING_KEY_OFFSET: usize = FINGERPRINT_OFFSET + Fingerprint::LEN;
        const VERIFYING_KEY_OFFSET: usize = SIGNING_KEY_OFFSET + SIGNING_KEY_LEN;
        let salt: Salt = bytes
            .get(SALT_OFFSET..CHECKSUM_OFFSET)
            .ok_or_else(invalid_key)?
            .try_into()?;
        let checksum: Checksum = bytes
            .get(CHECKSUM_OFFSET..FINGERPRINT_OFFSET)
            .ok_or_else(invalid_key)?
            .try_into()?;
        let fingerprint: Fingerprint = bytes
            .get(FINGERPRINT_OFFSET..SIGNING_KEY_OFFSET)
            .ok_or_else(invalid_key)?
            .try_into()?;
        let signing_key: ed25519_dalek::SigningKey = bytes
            .get(SIGNING_KEY_OFFSET..VERIFYING_KEY_OFFSET)
            .ok_or_else(invalid_key)?
            .try_into()
            .map_err(|_| invalid_key())?;
        let verifying_key: ed25519_dalek::VerifyingKey = bytes
            .get(VERIFYING_KEY_OFFSET..)
            .ok_or_else(invalid_key)?
            .try_into()
            .map_err(|_| invalid_key())?;
        if signing_key.verifying_key() != verifying_key {
            return Err(invalid_key());
        }
        Ok(Self {
            signing_key,
            salt,
            fingerprint,
            checksum,
        })
    }

    fn write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        self.do_write_to_file(path)
            .map_err(|e| failed_to_write(path, e))
    }

    fn do_write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut file = File::create(path)?;
        write_comment(&mut file, "private key", self.fingerprint)?;
        write_bytes(&mut file, self.to_bytes().as_slice())?;
        Ok(())
    }

    fn read_from_file(path: &Path) -> Result<Self, std::io::Error> {
        Self::from_bytes(&read_bytes(path, "signing key")?)
    }
}

struct VerifyingKey {
    verifying_key: ed25519_dalek::VerifyingKey,
    fingerprint: Fingerprint,
}

impl VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), std::io::Error> {
        self.verifying_key
            .verify(message, &signature.signature)
            .map_err(|_| std::io::Error::other("verification error"))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(VERIFYING_KEY_BYTES_LEN);
        bytes.extend(PK_ALGO.bytes());
        bytes.extend(self.fingerprint.as_bytes());
        bytes.extend(self.verifying_key.as_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let algo = std::str::from_utf8(bytes.get(..2).ok_or_else(invalid_key)?)
            .map_err(|_| invalid_key())?;
        if algo != PK_ALGO {
            return Err(unsupported_format());
        }
        const FINGERPRINT_OFFSET: usize = 2;
        const VERIFYING_KEY_OFFSET: usize = FINGERPRINT_OFFSET + Fingerprint::LEN;
        let fingerprint: Fingerprint = bytes
            .get(FINGERPRINT_OFFSET..VERIFYING_KEY_OFFSET)
            .ok_or_else(invalid_key)?
            .try_into()?;
        let verifying_key: ed25519_dalek::VerifyingKey = bytes
            .get(VERIFYING_KEY_OFFSET..)
            .ok_or_else(invalid_key)?
            .try_into()
            .map_err(|_| invalid_key())?;
        Ok(Self {
            verifying_key,
            fingerprint,
        })
    }

    fn write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        self.do_write_to_file(path)
            .map_err(|e| failed_to_write(path, e))
    }

    fn do_write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut file = File::create(path)?;
        write_comment(&mut file, "public key", self.fingerprint)?;
        write_bytes(&mut file, self.to_bytes().as_slice())?;
        Ok(())
    }

    fn read_from_file(path: &Path) -> Result<Self, std::io::Error> {
        Self::from_bytes(&read_bytes(path, "verifying key")?)
    }
}

struct Signature {
    signature: ed25519_dalek::Signature,
    fingerprint: Fingerprint,
}

impl Signature {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNATURE_BYTES_LEN);
        bytes.extend(PK_ALGO.bytes());
        bytes.extend(self.fingerprint.as_bytes());
        bytes.extend(self.signature.to_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let algo = std::str::from_utf8(bytes.get(..2).ok_or_else(invalid_signature)?)
            .map_err(|_| invalid_signature())?;
        if algo != PK_ALGO {
            return Err(unsupported_format());
        }
        const FINGERPRINT_OFFSET: usize = 2;
        const SIGNATURE_OFFSET: usize = FINGERPRINT_OFFSET + Fingerprint::LEN;
        let fingerprint: Fingerprint = bytes
            .get(FINGERPRINT_OFFSET..SIGNATURE_OFFSET)
            .ok_or_else(invalid_signature)?
            .try_into()?;
        let signature: ed25519_dalek::Signature = bytes
            .get(SIGNATURE_OFFSET..)
            .ok_or_else(invalid_signature)?
            .try_into()
            .map_err(|_| invalid_signature())?;
        Ok(Self {
            fingerprint,
            signature,
        })
    }

    fn write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        self.do_write_to_file(path)
            .map_err(|e| failed_to_write(path, e))
    }

    fn do_write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut file = File::create(path)?;
        write_comment(&mut file, "signed by key", self.fingerprint)?;
        write_bytes(&mut file, self.to_bytes().as_slice())?;
        Ok(())
    }

    fn read_from_file(path: &Path) -> Result<Self, std::io::Error> {
        Self::from_bytes(&read_bytes(path, "signature")?)
    }
}

#[derive(Clone, Copy)]
struct Bytes<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Bytes<N> {
    const LEN: usize = N;

    fn new() -> Self {
        Self { data: [0_u8; N] }
    }

    fn generate() -> Self {
        let mut tmp = Self::new();
        OsRng.fill_bytes(&mut tmp.data[..]);
        tmp
    }

    fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }
}

impl<const N: usize> TryFrom<&[u8]> for Bytes<N> {
    type Error = std::io::Error;

    fn try_from(other: &[u8]) -> Result<Self, Self::Error> {
        let mut data = [0_u8; N];
        data.copy_from_slice(other.get(..N).ok_or_else(|| invalid_key())?);
        Ok(Self { data })
    }
}

fn write_comment(
    writer: &mut impl Write,
    comment: &str,
    fingerprint: Fingerprint,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "{} {} {}",
        COMMENT_PREFIX,
        comment,
        hex::encode(fingerprint.as_bytes())
    )
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<(), std::io::Error> {
    writeln!(writer, "{}", Base64::encode_string(bytes))
}

fn read_bytes(path: &Path, name: &str) -> Result<Vec<u8>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.starts_with(COMMENT_PREFIX) || line.is_empty() {
            continue;
        }
        return Base64::decode_vec(line)
            .map_err(|_| std::io::Error::other(format!("invalid {}", name)));
    }
    Err(std::io::Error::other(format!("{} not found", name)))
}

fn to_signature_file(message_file: &Path) -> PathBuf {
    let signature_file_name = match message_file.file_name() {
        Some(file_name) => {
            let mut tmp = file_name.to_os_string();
            tmp.push(".sig");
            tmp
        }
        None => OsStr::new("sig").to_os_string(),
    };
    let signature_file = {
        let mut tmp = message_file.to_path_buf();
        tmp.set_file_name(signature_file_name);
        tmp
    };
    signature_file
}

const COMMENT_PREFIX: &str = "untrusted comment:";
const PK_ALGO: &str = "Ed";
const KDF_ALGO: &str = "BK";
const SIGNING_KEY_LEN: usize = 32;

const PK_ALGO_BYTES_LEN: usize = 2;
const SIGNING_KEY_BYTES_LEN: usize = 104;
const VERIFYING_KEY_BYTES_LEN: usize = 42;
const SIGNATURE_BYTES_LEN: usize = PK_ALGO_BYTES_LEN + Fingerprint::LEN + SIGNATURE_LENGTH;

fn failed_to_write(path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::other(format!("failed to write `{}`: {}", path.display(), e))
}

fn failed_to_read(path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::other(format!("failed to read `{}`: {}", path.display(), e))
}

fn invalid_key() -> std::io::Error {
    std::io::Error::other("invalid key")
}

fn invalid_signature() -> std::io::Error {
    std::io::Error::other("invalid signature")
}

fn unsupported_format() -> std::io::Error {
    std::io::Error::other("unsupported key format")
}
