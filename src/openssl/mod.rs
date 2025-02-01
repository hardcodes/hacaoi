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
//! ## AES 256 CBC - RustCrypto
//!
//! Note: features `openssl` and `b64` must be enabled.
//!
#![cfg_attr(all(feature = "openssl", feature = "b64"), doc = "```")]
#![cfg_attr(not(any(feature = "openssl", feature = "b64")), doc = "```ignore")]
//! use hacaoi::aes::{Aes256CbcFunctions, AesOpenSslScope};
//!
//! fn main() {
//!     const AES_KEY: [u8; 32] = [42; 32];
//!     const AES_IV: [u8; 16] = [84; 16];
//!     const PLAINTEXT: &str = "Lorem ipsum dolor sit amet";
//!     let aes = hacaoi::aes::Aes256Cbc::<AesOpenSslScope>::from_key_iv(AES_KEY, AES_IV);
//!     let enrypted = aes.encrypt_str_to_vec(PLAINTEXT).unwrap();
//!     let decrypted = aes.decrypt_bytes_to_string(&enrypted).unwrap();
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

/// Use this for symmetric encryption and decryption with AES 256 in CBC mode implemented with help of the Rust OpenSSL crate.
pub mod aes;
/// Use this to encrypt and decrypt data in hybrid mode (combination of the modules [`aes`] and [`rsa`]), implemented with help of the Rust OpenSSL crate..
pub mod hybrid_crypto;
/// Use this for for asymmetric encryption and decryption with RSA keys implemented with help of the Rust OpenSSL crate..
pub mod rsa;
