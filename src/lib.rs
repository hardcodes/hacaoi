// #![cfg_attr(not(test), no_std)]
// #![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
// TODO: change URL, when the project has been uploaded!
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/hardcodes/hacaoi/6126a1fcbb6293cf0c83f8c4bf5dfacff9f658a1/resources/gfx/logo_small.png"
)]
#![warn(missing_docs)]
//!# Examples
//!
//! ## PKCS#1 v1.5 encryption - OpenSSL
//!
//! Note: features `openssl` and `b64` must be enabled.
//!
#![cfg_attr(all(feature = "openssl", feature = "b64"), doc = "```")]
#![cfg_attr(not(any(feature = "openssl", feature = "b64")), doc = "```ignore")]
//! use hacaoi::rsa::{RsaKeysFunctions, KeySize};
//!
//! fn main() {
//!     let rsa = hacaoi::openssl::rsa::RsaKeys::random(KeySize::Bit2048).unwrap();
//!     let encrypted_b64 = rsa.encrypt_str_pkcs1v15_padding_to_b64("plaintext").unwrap();
//!     let decrypted = rsa.decrypt_b64_pkcs1v15_padding_to_string(&encrypted_b64).unwrap();
//!     assert_eq!("plaintext", &decrypted);
//! }
//! ```
//!
//! ## PKCS#1 v1.5 encryption - RustCrypto
//!
//! Note: features `rust-crypto` and `b64` must be enabled.
//!
#![cfg_attr(all(feature = "rust-crypto", feature = "b64"), doc = "```")]
#![cfg_attr(not(any(feature = "rust-crypto", feature = "b64")), doc = "```ignore")]
//! use hacaoi::rsa::{RsaKeysFunctions, KeySize};
//!
//! fn main() {
//!     let rsa = hacaoi::openssl::rsa::RsaKeys::random(KeySize::Bit2048).unwrap();
//!     let encrypted_b64 = rsa.encrypt_str_pkcs1v15_padding_to_b64("plaintext").unwrap();
//!     let decrypted = rsa.decrypt_b64_pkcs1v15_padding_to_string(&encrypted_b64).unwrap();
//!     assert_eq!("plaintext", &decrypted);
//! }
//! ```
//!
//! ## PKCS#1 v1.5 sha512 signatures - RustCrypto
//!
//! Note: features `rust-crypto` and `b64` must be enabled.
//!
#![cfg_attr(all(feature = "rust-crypto", feature = "b64"), doc = "```")]
#![cfg_attr(not(any(feature = "rust-crypto", feature = "b64")), doc = "```ignore")]
//! use hacaoi::rsa::{RsaKeysFunctions, KeySize};
//!
//! fn main() {
//!     let rsa = hacaoi::openssl::rsa::RsaKeys::random(KeySize::Bit2048).unwrap();
//!     let signature_b64 = rsa.sign_str_sha512_b64("plaintext").unwrap();
//!     let validation_result = rsa.validate_sha512_b64_signature("plaintext", &signature_b64);
//! assert!(validation_result.is_ok());
//! }
//! ```
//!
//! ## AES 256 CBC - RustCrypto
//!
//! Note: features `rust-crypto` and `b64` must be enabled.
//!
#![cfg_attr(all(feature = "rust-crypto", feature = "b64"), doc = "```")]
#![cfg_attr(not(any(feature = "rust-crypto", feature = "b64")), doc = "```ignore")]
//! use hacaoi::aes::{Aes256CbcFunctions, AesRustCryptoScope};
//!
//! fn main() {
//!     const AES_KEY: [u8; 32] = [42; 32];
//!     const AES_IV: [u8; 16] = [84; 16];
//!     const PLAINTEXT: &str = "Lorem ipsum dolor sit amet";
//!     let aes = hacaoi::aes::Aes256Cbc::<AesRustCryptoScope>::from_key_iv(AES_KEY, AES_IV);
//!     let enrypted = aes.encrypt_str_to_vec(PLAINTEXT).unwrap();
//!     let decrypted = aes.decrypt_bytes_to_string(enrypted).unwrap();
//!     assert_eq!(decrypted, PLAINTEXT)
//! }
//! ```
//!
//! ## Hybrid encryption - OpenSSL
//!
//! Note: features `openssl` and `b64` must be enabled.
//!
#![cfg_attr(all(feature = "openssl", feature = "b64"), doc = "```")]
#![cfg_attr(not(any(feature = "openssl", feature = "b64")), doc = "```ignore")]
//! use hacaoi::hybrid_crypto::HybridCryptoFunctions;
//! use std::path::Path;
//!
//! fn main() {
//!     const RSA_PASSPHRASE: &str = "12345678901234";
//!     let openssl_hybrid_crypto = hacaoi::openssl::hybrid_crypto::HybridCrypto::from_file(
//!         Path::new("resources/tests/rsa/rsa_private.pkcs1.key"),
//!         RSA_PASSPHRASE,
//!     )
//!     .unwrap();
//!     const PLAINTEXT: &str = "Lorem ipsum dolor sit amet";
//!     let encrypted = openssl_hybrid_crypto.hybrid_encrypt_str(PLAINTEXT).unwrap();
//!     let decrypted = openssl_hybrid_crypto
//!         .hybrid_decrypt_str(&encrypted)
//!         .unwrap();
//!     assert_eq!(decrypted, PLAINTEXT)
//! }
//! ```

/// Encryption and decryption with AES 256 in CBC mode.
pub mod aes;
/// Feature *b64* enables the base64_trait, which enables base64
/// conversions for the [openssl] and [rust_crypto] modules.
#[cfg(feature = "b64")]
pub mod base64_trait;
/// Trait for hybrid encryption/decryption using AES and RSA functions.
#[cfg(any(feature = "openssl", feature = "rust-crypto"))]
pub mod hybrid_crypto;
/// Feature *openssl* enables all cryptographic functions which
/// depend on the Rust openssl crate, which in turn depends on
/// an installed openssl library.
#[cfg(feature = "openssl")]
pub mod openssl;
/// Encryption/decryption and signature creation/validation with
/// RSA public and private keys.
pub mod rsa;
/// Feature *rust-crypto* enables all cryptographic functions which
/// depend on the RustCrypto crates but won't need any external
/// libraries.
#[cfg(feature = "rust-crypto")]
pub mod rust_crypto;
/// Only include for testing
#[cfg(test)]
pub mod tests;
