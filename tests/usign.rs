use std::path::Path;
use std::process::Command;

use tempfile::TempDir;
use test_bin::get_test_bin;

#[test]
fn test_usign() {
    let workdir = TempDir::new().unwrap();
    let public_key = workdir.path().join("public-key");
    let secret_key = workdir.path().join("secret-key");
    let signature = workdir.path().join("signature");
    Command::new("usign")
        .args([
            "-G",
            "-p",
            public_key.display().to_string().as_str(),
            "-s",
            secret_key.display().to_string().as_str(),
        ])
        .status()
        .unwrap();
    Command::new("usign")
        .args([
            "-S",
            "-m",
            public_key.display().to_string().as_str(),
            "-s",
            secret_key.display().to_string().as_str(),
            "-x",
            signature.display().to_string().as_str(),
        ])
        .status()
        .unwrap();
    compares_usign_and_ksign(
        public_key.as_path(),
        secret_key.as_path(),
        signature.as_path(),
    );
}

#[test]
fn test_ksign() {
    let workdir = TempDir::new().unwrap();
    let public_key = workdir.path().join("public-key");
    let secret_key = workdir.path().join("secret-key");
    let signature = workdir.path().join("signature");
    get_test_bin("ksign")
        .args([
            "-G",
            "-p",
            public_key.display().to_string().as_str(),
            "-s",
            secret_key.display().to_string().as_str(),
        ])
        .status()
        .unwrap();
    get_test_bin("ksign")
        .args([
            "-S",
            "-m",
            public_key.display().to_string().as_str(),
            "-s",
            secret_key.display().to_string().as_str(),
            "-x",
            signature.display().to_string().as_str(),
        ])
        .status()
        .unwrap();
    compares_usign_and_ksign(
        public_key.as_path(),
        secret_key.as_path(),
        signature.as_path(),
    );
}

fn compares_usign_and_ksign(public_key: &Path, secret_key: &Path, signature: &Path) {
    let args = ["-F", "-p", public_key.display().to_string().as_str()].map(|x| x.to_owned());
    assert_eq!(
        Command::new("usign").args(&args).output().unwrap(),
        get_test_bin("ksign").args(args).output().unwrap(),
        "public key fingerprint mismatch"
    );
    let args = ["-F", "-s", secret_key.display().to_string().as_str()].map(|x| x.to_owned());
    assert_eq!(
        Command::new("usign").args(&args).output().unwrap(),
        get_test_bin("ksign").args(args).output().unwrap(),
        "secret key fingerprint mismatch"
    );
    let args = ["-F", "-x", signature.display().to_string().as_str()].map(|x| x.to_owned());
    assert_eq!(
        Command::new("usign").args(&args).output().unwrap(),
        get_test_bin("ksign").args(args).output().unwrap(),
        "signature fingerprint mismatch"
    );
    let args = [
        "-V",
        "-m",
        public_key.display().to_string().as_str(),
        "-x",
        signature.display().to_string().as_str(),
        "-p",
        public_key.display().to_string().as_str(),
    ]
    .map(|x| x.to_owned());
    let expected = Command::new("usign").args(&args).output().unwrap();
    let actual = get_test_bin("ksign").args(args).output().unwrap();
    assert_eq!(expected, actual, "signature verification mismatch");
}
