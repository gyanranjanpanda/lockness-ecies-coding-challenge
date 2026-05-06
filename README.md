# Lockness ECIES Implementation

This repository contains a Rust implementation of the elliptic-curve encryption scheme for the Lockness Mentorship Coding Challenge.

## Features

- Fully compliant with the provided cryptographic specifications.
- Agnostic to the underlying elliptic curve (supports secp256k1, secp384r1, ed25519, etc. via `generic-ec`).
- Uses `sha2` (SHA-256) for KDF (Key Derivation Function).
- Safe error handling (no panics) using the `thiserror` crate.

## Setup and Usage

### Prerequisites

You need to have Rust installed on your system. If you do not have it, you can install it using rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Running Tests

To verify the implementation and run the test suite, simply use:

```bash
cargo test
```

This will run all unit tests, verifying the correctness of encryption/decryption on different curves and ensuring proper error handling.

## Structure

- `src/lib.rs`: Contains the core implementation of the `encrypt` and `decrypt` functions, custom error types, and the test suite.
- `Cargo.toml`: Defines the project dependencies.
