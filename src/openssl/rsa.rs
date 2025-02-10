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
//!     const PLAINTEXT: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
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
//!     const PLAINTEXT: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
//!     let encrypted = openssl_hybrid_crypto.hybrid_encrypt_str(PLAINTEXT).unwrap();
//!     let decrypted = openssl_hybrid_crypto
//!         .hybrid_decrypt_str(&encrypted)
//!         .unwrap();
//!     assert_eq!(decrypted, PLAINTEXT)
//! }
//! ```

use crate::error::HacaoiError;
use crate::rsa::{KeySize, RsaKeysFunctions};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};
use std::path::Path;

// min bit size of the modulus (modulus * 8 = rsa key bits)
const MIN_RSA_MODULUS_SIZE: u32 = 256;

/// Holds the RSA private and public key for
/// encryption and decryption
pub struct RsaKeys {
    private_key: Rsa<openssl::pkey::Private>,
    public_key: Rsa<openssl::pkey::Public>,
}

impl RsaKeysFunctions for RsaKeys {
    /// Build a new random RSA key pair.
    #[inline(always)]
    fn random(key_size: KeySize) -> Result<Self, HacaoiError> {
        let rsa = Rsa::generate(key_size as u32)?;
        let rsa_public_key = Rsa::public_key_from_pem(&rsa.public_key_to_pem()?)?;
        let rsa_private_key = Rsa::private_key_from_pem(&rsa.private_key_to_pem()?)?;
        Ok(RsaKeys {
            private_key: rsa_private_key,
            public_key: rsa_public_key,
        })
    }

    /// Loads an encryped RSA private key file from
    /// the given path, hence the passphrase is needed.
    /// The RSA public key is derived from the RSA private key.
    #[inline(always)]
    fn from_file<P: AsRef<Path>>(
        rsa_private_key_path: P,
        rsa_private_key_password: &str,
    ) -> Result<Self, HacaoiError> {
        let rsa_private_key_file = std::fs::read_to_string(rsa_private_key_path)?;
        let rsa_private_key = match Rsa::private_key_from_pem_passphrase(
            rsa_private_key_file.as_bytes(),
            rsa_private_key_password.as_bytes(),
        ) {
            Ok(p) => p,
            Err(e) => {
                return Err(format!("cannot load rsa private key: {}", e).into());
            }
        };
        let rsa_public_key_pem = rsa_private_key.public_key_to_pem()?;
        let rsa_public_key = Rsa::public_key_from_pem(&rsa_public_key_pem)?;
        if rsa_public_key.size() < MIN_RSA_MODULUS_SIZE {
            return Err(format!("modulus is < {} bytes", MIN_RSA_MODULUS_SIZE).into());
        }
        Ok(RsaKeys {
            private_key: rsa_private_key,
            public_key: rsa_public_key,
        })
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Encrypt a String slice with stored RSA public key
    /// using PKCS#1 v1.5 padding and return it as `Vec<u8>`.
    #[inline(always)]
    fn encrypt_bytes_pkcs1v15_padding_to_vec(
        &self,
        unencrypted_bytes: &[u8],
    ) -> Result<Vec<u8>, HacaoiError> {
        let public_key = self.public_key.as_ref();
        let mut buf: Vec<u8> = vec![0; public_key.size() as usize];
        match public_key.public_encrypt(unencrypted_bytes, &mut buf, Padding::PKCS1) {
            Err(e) => Err(format!("Could not rsa encrypt given value: {}", &e).into()),
            Ok(_) => Ok(buf),
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Decryption
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Decrypt `&[u8]` with RSA encrypted data and
    /// PKCS#1 v1.5 padding using the stored RSA private key
    /// and return it as plaintext String.
    #[inline(always)]
    fn decrypt_bytes_pkcs1v15_padding_to_vec(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<Vec<u8>, HacaoiError> {
        let private_key = self.private_key.as_ref();
        let mut buf: Vec<u8> = vec![0; private_key.size() as usize];
        match private_key.private_decrypt(encrypted_bytes, &mut buf, Padding::PKCS1) {
            Err(e) => Err(format!("Could not rsa decrypt given value: {}", &e).into()),
            Ok(_) => Ok(buf),
        }
    }

    /// Decrypt `&[u8]` with RSA encrypted data and
    /// PKCS#1 v1.5 padding using the stored RSA private key
    /// and return it as plaintext String.
    #[inline(always)]
    fn decrypt_bytes_pkcs1v15_padding_to_string(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<String, HacaoiError> {
        let decrypted_bytes = self.decrypt_bytes_pkcs1v15_padding_to_vec(encrypted_bytes)?;
        let decrypted_data = match String::from_utf8(decrypted_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(HacaoiError::FromUtf8Error(e));
            }
        };
        Ok(decrypted_data.trim_matches(char::from(0)).to_string())
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Signature
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Create a sha512 signature for the given
    /// string slice using the rsa private key.
    #[inline(always)]
    fn sign_str_sha512(&self, data_to_sign: &str) -> Result<Vec<u8>, HacaoiError> {
        let pkey = match PKey::from_rsa(self.private_key.clone()) {
            Ok(pkey) => pkey,
            Err(e) => {
                return Err(format!("Could not build pkey: {}", &e).into());
            }
        };
        let mut signer = match Signer::new(MessageDigest::sha512(), &pkey) {
            Ok(signer) => signer,
            Err(e) => {
                return Err(format!("Could not build signer: {}", &e).into());
            }
        };
        let update_result = signer.update(data_to_sign.as_bytes());
        if update_result.is_err() {
            return Err(format!(
                "Could not add data to signer: {}",
                &update_result.unwrap_err()
            )
            .into());
        }
        match signer.sign_to_vec() {
            Err(e) => Err(format!("Could not sign data: {}", &e).into()),
            Ok(s) => Ok(s),
        }
    }

    /// Validate a `&[u8]` signature that was created using
    /// the corresponding rsa private key.
    #[inline(always)]
    fn validate_sha512_bytes_signature(
        &self,
        signed_data: &str,
        signature_bytes: &[u8],
    ) -> Result<(), HacaoiError> {
        let pkey = match PKey::from_rsa(self.public_key.clone()) {
            Ok(pkey) => pkey,
            Err(e) => {
                return Err(format!("Could not build pkey: {}", &e).into());
            }
        };
        let mut verifier = match Verifier::new(MessageDigest::sha512(), &pkey) {
            Ok(verifier) => verifier,
            Err(e) => {
                return Err(format!("Could not build verifier: {}", &e).into());
            }
        };
        let update_result = verifier.update(signed_data.as_bytes());
        if update_result.is_err() {
            return Err(format!(
                "Could not add signed data to verifier: {}",
                &update_result.unwrap_err()
            )
            .into());
        }
        let validation_result = match verifier.verify(signature_bytes) {
            Ok(validation_result) => validation_result,
            Err(e) => {
                return Err(format!("Could not verify signature: {}", &e).into());
            }
        };
        if validation_result {
            return Ok(());
        }
        Err(HacaoiError::StringError("invalid signature".into()))
    }
}
