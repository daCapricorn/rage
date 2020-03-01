# Changelog
All notable changes to the age-core crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 1.0.0 are beta releases.

## [Unreleased]
### Added
- `age_core::primitives::{aead_decrypt, aead_encrypt, hkdf}`, to enable these
  common primitives to be reused in plugins.

## [0.3.1] - 2020-02-11
### Fixed
- Bumped dependencies to `cookie-factory ^0.3.1` to fix nightly builds.

## [0.3.0] - 2020-02-09
(relative to `age 0.2.0`)

### Fixed
- Base64 padding is now correctly rejected by the age stanza parser.
