use std::ffi::OsStr;
use std::fmt::Display;
use std::fmt::Formatter;
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
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use ed25519_dalek::SIGNATURE_LENGTH;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Digest;
use sha2::Sha512;

#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Verify signed file.
    #[arg(short = 'V', action)]
    verify: bool,
    /// Sign speificed file.
    #[arg(short = 'S', action)]
    sign: bool,
    /// Print key fingerprint for public key, secret key or signature.
    #[arg(short = 'F', action)]
    fingerprint: bool,
    /// Generate a new key pair.
    #[arg(short = 'G', action)]
    generate: bool,
    /// The comment to include in the file.
    #[arg(short = 'c')]
    comment: Option<String>,
    /// Message file.
    #[arg(short = 'm', value_name = "FILE")]
    message_file: Option<PathBuf>,
    /// Public key file.
    #[arg(short = 'p', value_name = "FILE")]
    public_key_file: Option<PathBuf>,
    /// Public key directory.
    #[arg(short = 'P', value_name = "DIRECTORY")]
    public_key_directory: Option<PathBuf>,
    /// Do not print signature verification status to stdout.
    #[arg(short = 'q', action)]
    quiet: bool,
    /// Secret key file.
    #[arg(short = 's', value_name = "FILE")]
    secret_key_file: Option<PathBuf>,
    /// Signature file.
    #[arg(short = 'x', value_name = "FILE")]
    signature_file: Option<PathBuf>,
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
    let num_commands = [args.verify, args.sign, args.fingerprint, args.generate]
        .into_iter()
        .filter(|x| *x)
        .count();
    if num_commands > 1 {
        return Err("multiple commands specified".into());
    }
    if args.generate {
        let signing_key_file = args
            .secret_key_file
            .ok_or_else(|| "no secret key file specified")?;
        let verifying_key_file = args
            .public_key_file
            .ok_or_else(|| "no verifying key file specified")?;
        let signing_key = SigningKey::generate(args.comment);
        let verifying_key = signing_key.to_verifying_key();
        signing_key.write_to_file(signing_key_file.as_path())?;
        verifying_key.write_to_file(verifying_key_file.as_path())?;
        Ok(ExitCode::SUCCESS)
    } else if args.sign {
        let message_file = args
            .message_file
            .ok_or_else(|| "no message file specified")?;
        let signing_key_file = args
            .secret_key_file
            .ok_or_else(|| "no secret key file specified")?;
        let signature_file = args
            .signature_file
            .unwrap_or_else(|| to_signature_file(message_file.as_path()));
        let message = std::fs::read(message_file.as_path())
            .map_err(|e| failed_to_read(message_file.as_path(), e))?;
        let signing_key = SigningKey::read_from_file(signing_key_file.as_path())?;
        let signature = signing_key.sign(&message);
        signature.write_to_file(signature_file.as_path())?;
        Ok(ExitCode::SUCCESS)
    } else if args.verify {
        let message_file = args
            .message_file
            .ok_or_else(|| "no message file specified")?;
        let signature_file = args
            .signature_file
            .unwrap_or_else(|| to_signature_file(message_file.as_path()));
        let message = std::fs::read(message_file.as_path())
            .map_err(|e| failed_to_read(message_file.as_path(), e))?;
        let signature = Signature::read_from_file(signature_file.as_path())?;
        let verifying_key_file = match (args.public_key_file, args.public_key_directory) {
            (Some(_), Some(_)) => {
                return Err("both public key file and public key directory specified".into())
            }
            (Some(file), None) => file,
            (None, Some(dir)) => dir.join(hex::encode(signature.fingerprint.data)),
            (None, None) => {
                return Err("neither public key file nor public key directory specified".into())
            }
        };
        let verifying_key = VerifyingKey::read_from_file(verifying_key_file.as_path())?;
        verifying_key.verify(&message, &signature)?;
        if !args.quiet {
            println!("OK");
        }
        Ok(ExitCode::SUCCESS)
    } else if args.fingerprint {
        let files: Vec<_> = [
            args.signature_file,
            args.secret_key_file,
            args.public_key_file,
        ]
        .into_iter()
        .flatten()
        .collect();
        if files.len() == 0 {
            return Err("no file specified".into());
        }
        if files.len() > 1 {
            return Err("multiple files specified".into());
        }
        let (bytes, _) = read_bytes(files[0].as_path(), "signature/verifying key/signing key")?;
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
        Ok(ExitCode::SUCCESS)
    } else {
        Err("no command specified".into())
    }
}

type Fingerprint = Bytes<8>;
type Salt = Bytes<16>;
type Checksum = Bytes<8>;

struct SigningKey {
    signing_key: ed25519_dalek::SigningKey,
    salt: Salt,
    checksum: Checksum,
    fingerprint: Fingerprint,
    comment: Option<String>,
}

impl SigningKey {
    fn generate(comment: Option<String>) -> Self {
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
            comment: comment.map(|s| s.replace("\n", " ")),
        }
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.signing_key.sign(message);
        Signature {
            signature,
            fingerprint: self.fingerprint,
            comment: self.comment.clone(),
        }
    }

    fn to_verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            verifying_key: self.signing_key.verifying_key(),
            fingerprint: self.fingerprint,
            comment: self.comment.clone(),
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

    fn from_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self, std::io::Error> {
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
            comment,
        })
    }

    fn get_comment(&self) -> Comment {
        match self.comment.as_ref() {
            Some(s) => Comment::String(s),
            None => Comment::Fingerprint("private key", self.fingerprint),
        }
    }

    fn write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        self.do_write_to_file(path)
            .map_err(|e| failed_to_write(path, e))
    }

    fn do_write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut file = File::create(path)?;
        write_comment(&mut file, self.get_comment())?;
        write_bytes(&mut file, self.to_bytes().as_slice())?;
        Ok(())
    }

    fn read_from_file(path: &Path) -> Result<Self, std::io::Error> {
        let (bytes, comment) = read_bytes(path, "signing key")?;
        Self::from_bytes(&bytes, comment)
    }
}

struct VerifyingKey {
    verifying_key: ed25519_dalek::VerifyingKey,
    fingerprint: Fingerprint,
    comment: Option<String>,
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

    fn from_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self, std::io::Error> {
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
            comment,
        })
    }

    fn get_comment(&self) -> Comment {
        match self.comment.as_ref() {
            Some(s) => Comment::String(s),
            None => Comment::Fingerprint("public key", self.fingerprint),
        }
    }

    fn write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        self.do_write_to_file(path)
            .map_err(|e| failed_to_write(path, e))
    }

    fn do_write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut file = File::create(path)?;
        write_comment(&mut file, self.get_comment())?;
        write_bytes(&mut file, self.to_bytes().as_slice())?;
        Ok(())
    }

    fn read_from_file(path: &Path) -> Result<Self, std::io::Error> {
        let (bytes, comment) = read_bytes(path, "verifying key")?;
        Self::from_bytes(&bytes, comment)
    }
}

struct Signature {
    signature: ed25519_dalek::Signature,
    fingerprint: Fingerprint,
    comment: Option<String>,
}

impl Signature {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNATURE_BYTES_LEN);
        bytes.extend(PK_ALGO.bytes());
        bytes.extend(self.fingerprint.as_bytes());
        bytes.extend(self.signature.to_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8], comment: Option<String>) -> Result<Self, std::io::Error> {
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
            comment,
        })
    }

    fn get_comment(&self) -> Comment {
        match self.comment.as_ref() {
            Some(s) => Comment::String(s),
            None => Comment::Fingerprint("signed by key", self.fingerprint),
        }
    }

    fn write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        self.do_write_to_file(path)
            .map_err(|e| failed_to_write(path, e))
    }

    fn do_write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut file = File::create(path)?;
        write_comment(&mut file, self.get_comment())?;
        write_bytes(&mut file, self.to_bytes().as_slice())?;
        Ok(())
    }

    fn read_from_file(path: &Path) -> Result<Self, std::io::Error> {
        let (bytes, comment) = read_bytes(path, "signature")?;
        Self::from_bytes(&bytes, comment)
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

enum Comment<'a> {
    String(&'a str),
    Fingerprint(&'a str, Fingerprint),
}

impl<'a> Display for Comment<'a> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::String(s) => f.write_str(s),
            Self::Fingerprint(s, fp) => write!(f, "{} {}", s, hex::encode(fp.as_bytes())),
        }
    }
}

fn write_comment(writer: &mut impl Write, comment: Comment<'_>) -> Result<(), std::io::Error> {
    writeln!(writer, "{} {}", COMMENT_PREFIX, comment)
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<(), std::io::Error> {
    writeln!(writer, "{}", Base64::encode_string(bytes))
}

fn read_bytes(path: &Path, name: &str) -> Result<(Vec<u8>, Option<String>), std::io::Error> {
    do_read_bytes(path, name).map_err(|e| failed_to_read(path, e))
}

fn do_read_bytes(path: &Path, name: &str) -> Result<(Vec<u8>, Option<String>), std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut comment: Option<String> = None;
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.starts_with(COMMENT_PREFIX) || line.is_empty() {
            comment = Some(line[COMMENT_PREFIX.len()..].into());
            continue;
        }
        let bytes = Base64::decode_vec(line)
            .map_err(|_| std::io::Error::other(format!("invalid {}", name)))?;
        return Ok((bytes, comment));
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
