# ksign

[![Crates.io Version](https://img.shields.io/crates/v/ksign)](https://crates.io/crates/ksign)
[![Docs](https://docs.rs/ksign/badge.svg)](https://docs.rs/ksign)
[![dependency status](https://deps.rs/repo/github/igankevich/ksign/status.svg)](https://deps.rs/repo/github/igankevich/ksign)

OpenWRT's [usign](https://git.openwrt.org/project/usign.git) utility rewritten in Rust. The crate provides both the executable and the library.
Use it to sign files using Ed25519 keys.

    Usage: ksign [OPTIONS]
    
    Options:
      -V                  Verify signed file
      -S                  Sign speificed file
      -F                  Print key fingerprint for public key, secret key or signature
      -G                  Generate a new key pair
      -c <COMMENT>        The comment to include in the file
      -m <FILE>           Message file
      -p <FILE>           Public key file
      -P <DIRECTORY>      Public key directory
      -q                  Do not print signature verification status to stdout
      -s <FILE>           Secret key file
      -x <FILE>           Signature file
      -h                  Print help
