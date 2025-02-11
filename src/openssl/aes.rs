//!# Examples
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

use crate::aes::{Aes256Cbc, Aes256CbcFunctions, AesOpenSslScope};
use crate::error::HacaoiError;
use openssl::symm::{decrypt, encrypt, Cipher};

impl Aes256CbcFunctions<AesOpenSslScope> for Aes256Cbc<AesOpenSslScope> {
    /// Encrypt the given plaintext using Aes 256 CBC
    /// with PKCS#5 padding  and return the result as
    /// `Vec<u8>`.
    #[inline(always)]
    fn encrypt_str_to_vec(&self, plaintext: &str) -> Result<Vec<u8>, HacaoiError> {
        let cipher = Cipher::aes_256_cbc();
        let ciphertext = encrypt(cipher, &self.key(), Some(&self.iv()), plaintext.as_bytes())?;
        Ok(ciphertext)
    }

    /// Decrypt the data inside a `Vec<u8>` and return the
    /// plaintext as `String`.
    #[inline(always)]
    fn decrypt_bytes_to_string(&self, encrypted_bytes: &[u8]) -> Result<String, HacaoiError> {
        let cipher = Cipher::aes_256_cbc();
        let decrypted_payload = decrypt(cipher, &self.key(), Some(&self.iv()), encrypted_bytes)?;
        return Ok(String::from_utf8(decrypted_payload)?
            .trim_matches(char::from(0))
            .to_string());
    }
}
