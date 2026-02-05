//! C/C++ cryptographic library timing tests
//!
//! Tests implementations from C/C++ libraries via Rust FFI bindings:
//! - openssl: LibreSSL/OpenSSL (RSA, ECDSA, AES-GCM) — always available (uses openssl crate)
//! - sodiumoxide: Libsodium (Ed25519, X25519, crypto_box/secretbox) — always available (uses sodiumoxide crate)
//! - wolfssl: wolfSSL (RSA, ECDSA, AES-GCM) — requires `test-wolfssl` feature + system library
//! - mbedtls: mbedTLS/ARM Mbed TLS (RSA, AES-GCM) — requires `test-mbedtls` feature + system library
//! - botan: Botan 3 (RSA, ECDSA, AES-GCM) — requires `test-botan` feature + system library

#[path = "c_libraries/libressl.rs"]
mod libressl;
#[path = "c_libraries/libsodium.rs"]
mod libsodium;

#[cfg(feature = "test-wolfssl")]
#[path = "c_libraries/wolfssl.rs"]
mod wolfssl;

#[cfg(feature = "test-mbedtls")]
#[path = "c_libraries/mbedtls.rs"]
mod mbedtls;

#[cfg(feature = "test-botan")]
#[path = "c_libraries/botan.rs"]
mod botan;
