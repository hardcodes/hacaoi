//!# Examples
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
//!     let decrypted = aes.decrypt_bytes_to_string(&enrypted).unwrap();
//!     assert_eq!(decrypted, PLAINTEXT)
//! }
//! ```

use crate::aes::{Aes256Cbc, Aes256CbcFunctions, AesRustCryptoScope};
use crate::error::HacaoiError;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256Enc>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256Dec>;

impl Aes256CbcFunctions<AesRustCryptoScope> for Aes256Cbc<AesRustCryptoScope> {
    /// Encrypt the given plaintext using Aes 256 CBC
    /// with PKCS#7 padding  and return the result as
    /// `Vec<u8>`.
    ///
    /// PKCS#5 padding is identical to PKCS#7 padding,
    /// except that it has only been defined for block
    /// ciphers that use a 64-bit (8-byte) block size.
    /// Taken from wikipedia, see
    /// <https://en.wikipedia.org/wiki/Padding_(cryptography)>
    #[inline(always)]
    fn encrypt_str_to_vec(&self, plaintext: &str) -> Result<Vec<u8>, HacaoiError> {
        let plaintext_len = plaintext.len();
        // message block length = 128 bits = 16 bytes
        let padding_len = 16 - plaintext_len % 16;
        // the buffer size must guarantee to hold the message plus
        // padding bytes (total must be a multiple of 16 bytes)
        let mut buf: Vec<u8> = vec![0; plaintext_len + padding_len];
        buf[0..plaintext_len].copy_from_slice(plaintext.as_bytes());
        let aes256_encryptor = Aes256CbcEnc::new(&self.key().into(), &self.iv().into());
        let ciphertext = match aes256_encryptor.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
        {
            Err(e) => {
                return Err(format!("{}", &e).into());
            }
            Ok(cipher) => cipher,
        };
        Ok(ciphertext.to_vec())
    }

    /// Decrypt the data inside a `Vec<u8>` and return the
    /// plaintext as `String`.
    #[inline(always)]
    fn decrypt_bytes_to_string(&self, encrypted_bytes: &[u8]) -> Result<String, HacaoiError> {
        let aes256_decryptor = Aes256CbcDec::new(&self.key().into(), &self.iv().into());
        let mut encrypted_bytes_vec = encrypted_bytes.to_vec();
        let decrypted_payload =
            match aes256_decryptor.decrypt_padded_mut::<Pkcs7>(encrypted_bytes_vec.as_mut()) {
                Err(e) => {
                    return Err(format!("{}", &e).into());
                }
                Ok(plaintext) => plaintext,
            };
        return Ok(std::str::from_utf8(decrypted_payload)?
            .trim_matches(char::from(0))
            .to_string());
    }
}
