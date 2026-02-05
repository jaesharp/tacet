//! Cryptographic library timing tests
//!
//! Tests real-world cryptographic implementations for timing side channels.
//! Organized by crate/ecosystem:
//! - `rustcrypto`: RustCrypto ecosystem (aes, sha3, blake2, rsa, chacha20poly1305)
//! - `ring`: ring crate (AES-GCM, ChaCha20-Poly1305)
//! - `dalek`: dalek ecosystem (x25519-dalek)
//! - `pqcrypto`: Post-quantum crypto (Kyber, Dilithium, Falcon, SPHINCS+)
//! - `c_libraries`: C/C++ libraries via FFI (LibreSSL, Libsodium)
//! - `rust_libraries`: Pure Rust libraries (orion)

#[path = "crypto/c_libraries.rs"]
mod c_libraries;
#[path = "crypto/dalek.rs"]
mod dalek;
#[path = "crypto/pqcrypto.rs"]
mod pqcrypto;
#[path = "crypto/ring.rs"]
mod ring;
#[path = "crypto/rust_libraries.rs"]
mod rust_libraries;
#[path = "crypto/rustcrypto.rs"]
mod rustcrypto;
