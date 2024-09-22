#![doc = include_str!("../README.md")]

use std::any::TypeId;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::CommandFactory;
use clap::Parser;
use ksign::Fingerprint;
use ksign::Signature;
use ksign::SigningKey;
use ksign::VerifyingKey;
use ksign::IO;

#[derive(Parser)]
#[command(long_about = None, about = "OpenWRT's `usign` utility rewritten in Rust.", disable_help_flag = true)]
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
    /// Print help.
    #[arg(short = 'h', action)]
    help: bool,
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
    if args.help {
        Args::command().print_help()?;
        return Ok(ExitCode::SUCCESS);
    }
    let num_commands = [args.verify, args.sign, args.fingerprint, args.generate]
        .into_iter()
        .filter(|x| *x)
        .count();
    if num_commands > 1 {
        return Err("multiple commands specified".into());
    }
    if args.generate {
        let signing_key_file = args.secret_key_file.ok_or("no secret key file specified")?;
        let verifying_key_file = args
            .public_key_file
            .ok_or("no verifying key file specified")?;
        let signing_key = SigningKey::generate(args.comment);
        let verifying_key = signing_key.to_verifying_key();
        signing_key.write_to_file(signing_key_file.as_path())?;
        verifying_key.write_to_file(verifying_key_file.as_path())?;
        Ok(ExitCode::SUCCESS)
    } else if args.sign {
        let message_file = args.message_file.ok_or("no message file specified")?;
        let signing_key_file = args.secret_key_file.ok_or("no secret key file specified")?;
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
        let message_file = args.message_file.ok_or("no message file specified")?;
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
            (None, Some(dir)) => dir.join(signature.fingerprint().to_string()),
            (None, None) => {
                return Err("neither public key file nor public key directory specified".into())
            }
        };
        let verifying_key = VerifyingKey::read_from_file(verifying_key_file.as_path())?;
        verifying_key.verify(&message, &signature)?;
        if !args.quiet {
            eprintln!("OK");
        }
        Ok(ExitCode::SUCCESS)
    } else if args.fingerprint {
        let num_files = [
            args.signature_file.is_some(),
            args.secret_key_file.is_some(),
            args.public_key_file.is_some(),
        ]
        .into_iter()
        .filter(|x| *x)
        .count();
        if num_files > 1 {
            return Err("multiple files specified".into());
        }
        let (file, type_id) = if let Some(file) = args.signature_file {
            (file, TypeId::of::<Signature>())
        } else if let Some(file) = args.secret_key_file {
            (file, TypeId::of::<SigningKey>())
        } else if let Some(file) = args.public_key_file {
            (file, TypeId::of::<VerifyingKey>())
        } else {
            return Err("no file specified".into());
        };
        let fingerprint = Fingerprint::read_from_file(file.as_path(), type_id)?;
        println!("{}", fingerprint);
        Ok(ExitCode::SUCCESS)
    } else {
        Err("no command specified".into())
    }
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
    let mut tmp = message_file.to_path_buf();
    tmp.set_file_name(signature_file_name);
    tmp
}

fn failed_to_read(path: &Path, e: std::io::Error) -> std::io::Error {
    std::io::Error::other(format!("failed to read `{}`: {}", path.display(), e))
}
