//! C/C++ cryptographic library timing tests
//!
//! Tests implementations from C/C++ libraries via Rust FFI bindings:
//! - openssl: LibreSSL/OpenSSL (RSA, ECDSA, AES-GCM)
//! - sodiumoxide: Libsodium (Ed25519, X25519, crypto_box/secretbox)
//! - wolfssl: wolfSSL (RSA, ECDSA, AES-GCM)
//! - mbedtls: mbedTLS/ARM Mbed TLS (RSA, ECDSA, AES-GCM)
//! - botan: Botan (modern C++11/14 crypto library with constant-time focus)
//!
//! NOTE: BoringSSL tests are implemented but not integrated due to `openssl` ↔ `boring`
//! crate conflicts. See BORINGSSL_INVESTIGATION_REPORT.md for details.

#[path = "c_libraries/libressl.rs"]
mod libressl;
#[path = "c_libraries/libsodium.rs"]
mod libsodium;
#[path = "c_libraries/mbedtls.rs"]
mod mbedtls;
#[path = "c_libraries/wolfssl.rs"]
mod wolfssl;
#[path = "c_libraries/botan.rs"]
mod botan;
