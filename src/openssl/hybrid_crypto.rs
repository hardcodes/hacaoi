//! # Examples
//!
//! ## Hybrid encryption - OpenSSL
//!
//! Note: features `openssl` and `b64` must be enabled.
//!
#![cfg_attr(all(feature = "openssl", feature = "b64"), doc = "```")]
#![cfg_attr(not(any(feature = "openssl", feature = "b64")), doc = "```ignore")]
//! use hacaoi::hybrid_crypto::HybridCryptoFunctions;
//! use std::env;
//! use std::path::Path;
//!
//! fn main() {
//!     const RSA_PASSPHRASE: &str = "12345678901234";
//!     let openssl_hybrid_crypto = hacaoi::openssl::hybrid_crypto::HybridCrypto::from_file(
//!         Path::new(
//!             &env::current_dir()
//!                 .unwrap()
//!                 .join("resources/tests/rsa/rsa_private.pkcs1.key"),
//!         ),
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

use crate::base64_trait::{Base64StringConversions, Base64VecU8Conversions};

use crate::aes::{Aes256Cbc, Aes256CbcFunctions, AesOpenSslScope};
use crate::hybrid_crypto::HybridCryptoFunctions;
use crate::openssl::rsa::RsaKeys;
use crate::rsa::RsaKeysFunctions;
use std::error::Error;
use std::path::Path;

/// The [`HybridCrypto`] struct is used to encrypt and
/// decrypt data in hybrid mode. Meaning, the plaintext
/// is encrypted with AES 256 in CBC mode with a random
/// key/IV and encoded as base64. The random key/IV are
/// then itself enrypted using the stored RSA public key
/// and also encoded with base64.
/// Finally both results are concatenated as a String:
///
/// `<version>.<encrypted key and IV>.<encrypted payload>`.
///
/// For now only version `v1` exists.
///
/// Decryption takes such a concatenated string and then
/// computes those steps backwards.
///
/// This is mainly for convenience and a higher abstraction
/// at application level.
pub struct HybridCrypto {
    rsa_keys: RsaKeys,
}

impl HybridCryptoFunctions for HybridCrypto {
    /// Build [`HybridCrypto`] by loading an encryped RSA
    /// private key file from the given path, hence the
    /// passphrase is needed. The RSA public key is derived
    /// from the RSA private key.
    #[inline(always)]
    fn from_file<P: AsRef<Path>>(
        rsa_private_key_path: P,
        rsa_private_key_password: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let rsa_keys = RsaKeys::from_file(rsa_private_key_path, rsa_private_key_password)?;
        Ok(HybridCrypto { rsa_keys })
    }

    /// Build **HybridCrypto** with a random
    /// RSA private key. The public key is
    /// derived from the private key.
    /// This may be useful for application runtime
    /// data encryption/decryption.
    fn random(key_size: crate::rsa::KeySize) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let rsa_keys = RsaKeys::random(key_size)?;
        Ok(HybridCrypto { rsa_keys })
    }

    /// Encrypt a string slice in a hybrid mode:
    ///
    /// 1. A random AES 256 key and IV are created.
    /// 2. The string slice is encrypted with AES256 in CBC mode.
    ///    and encoded with base64.
    /// 3. The key and IV are enrypted with the stored RSA public
    ///    and the result is also encoded with base64.
    /// 4. Finally both results are concatenated as a String:
    ///
    ///    `<version>.<encrypted ky and IV>.<encrypted payload>`.
    ///
    ///    For now only version `v1` exists.
    #[inline(always)]
    fn hybrid_encrypt_str(&self, plaintext_data: &str) -> Result<String, Box<dyn Error>> {
        // AES Keys to encrypt the payload - the keysize of 256bit can be
        // encrypted using a 2048 RSA key. A smaller key size makes no sense and
        // this will result in a panic. Albeit it should not happen, since the
        // crate only loads keysizes of 2048 bits and above.
        let aes = Aes256Cbc::<AesOpenSslScope>::random();
        let base64_encrypted_key_iv = self
            .rsa_keys
            .encrypt_bytes_pkcs1v15_padding_to_b64(&aes.key_iv_as_vec())?;
        let payload = aes.encrypt_str_to_vec(plaintext_data)?.to_base64_encoded();
        Ok(format_args!("v1.{base64_encrypted_key_iv}.{payload}").to_string())
    }

    /// Decrypt a hybrid encrypted and base64 encoded string slice.
    ///
    /// 1. Split string slice in `<version>`, `<encrypted key and IV>` and `<encrypted payload>`
    ///
    ///    `<version>.<encrypted key and IV>.<encrypted payload>`.
    ///
    ///    For now only version `v1` exists.
    /// 2. Decrypt the AES 256 key and IV
    /// 3. Use AES 256 key and IV to decrypt the AES 256 CBC encrypted payload
    /// 4. return plaintext String
    #[inline(always)]
    fn hybrid_decrypt_str(&self, hybrid_encrypted_data: &str) -> Result<String, Box<dyn Error>> {
        let elements: Vec<&str> = hybrid_encrypted_data.split('.').collect();

        if elements.len() != 3 {
            return Err(format!("Expected {} parts, but found  {}", 3, elements.len()).into());
        }
        // we can access the elements since we checked the length first.
        let encryption_scheme = elements.first().unwrap();
        if "v1" != *encryption_scheme {
            return Err(format!("Unsupported encryption scheme: {}", encryption_scheme).into());
        }

        let encrypted_key_iv = Vec::from_base64_encoded(elements.get(1).unwrap())?;
        let encrypted_payload = Vec::from_base64_encoded(elements.get(2).unwrap())?;

        let aes_key_iv: Vec<u8> = self
            .rsa_keys
            .decrypt_bytes_pkcs1v15_padding_to_vec(&encrypted_key_iv)?;
        if aes_key_iv.len() < 48 {
            return Err("Key and IV too short".into());
        }
        let aes = Aes256Cbc::<AesOpenSslScope>::from_vec(&aes_key_iv[0..48])?;

        aes.decrypt_bytes_to_string(encrypted_payload)
    }

    /// Convenience function that decrypts a base64
    /// encoded String slice either with the stored
    /// RSA private key or decrypts the stored AES
    /// key and IV to decrypt the rest of the string.
    ///
    /// # Arguments
    ///
    /// - `encrypted_data`: a String slice with data to decrypt
    #[inline(always)]
    fn decrypt_str(&self, encrypted_data: &str) -> Result<String, Box<dyn Error>> {
        if encrypted_data.find('.').is_none() {
            self.rsa_keys
                .decrypt_b64_pkcs1v15_padding_to_string(encrypted_data)
        } else {
            self.hybrid_decrypt_str(encrypted_data)
        }
    }
}
