#[cfg(feature = "b64")]
use crate::base64_trait::Base64StringConversions;
#[cfg(feature = "b64")]
use crate::base64_trait::Base64VecU8Conversions;
use crate::error::HacaoiError;
use rand::RngCore;
use std::marker::PhantomData;
use zeroize::Zeroize;

/// Scope marker for [Aes256Cbc] struct and [Aes256CbcFunctions] trait to provide AES functions using the Rust OpenSSL crate
pub struct AesOpenSslScope;
/// Scope marker for [Aes256Cbc] struct and [Aes256CbcFunctions] trait to provide AES functions using the RustCrypto crate
pub struct AesRustCryptoScope;

/// Encryption and Decryption functions that are
/// implemented by the scope markers [AesOpenSslScope]
/// and [AesRustCryptoScope] for the [Aes256Cbc] struct.
/// Scopes prevent too much code repetition in this case.
pub trait Aes256CbcFunctions<Scope> {
    /// Encrypt the given plaintext using Aes 256 CBC
    /// with PKCS#5 padding  and return the result as
    /// `Vec<u8>`.
    fn encrypt_str_to_vec(&self, plaintext: &str) -> Result<Vec<u8>, HacaoiError>;
    /// Decrypt the data inside a `Vec<u8>` and return the
    /// plaintext as [`String`].
    fn decrypt_bytes_to_string(&self, encrypted_bytes: &[u8]) -> Result<String, HacaoiError>;
    /// Encrypt the given plaintext using Aes 256 CBC
    /// with PKCS#5 padding  and return the result as
    /// url safe base64 encoded [`String`].
    #[cfg(feature = "b64")]
    #[inline(always)]
    fn encrypt_str_to_b64(&self, plaintext: &str) -> Result<String, HacaoiError> {
        let encrypted_vec = self.encrypt_str_to_vec(plaintext)?;
        Ok(encrypted_vec.to_base64_urlsafe_encoded())
    }
    /// Decrypt the url safe base64 encoded data and return the
    /// plaintext as [`String`].
    #[cfg(feature = "b64")]
    #[inline(always)]
    fn decrypt_b64_to_string(&self, encrypted_b64: &str) -> Result<String, HacaoiError> {
        let encrypted_bytes =
            Vec::from_base64_urlsafe_encoded(encrypted_b64.trim_matches(char::from(0)))?;
        self.decrypt_bytes_to_string(&encrypted_bytes)
    }
}

/// Used to encrypt or decrypt data using AES 256 in CBC mode.
pub struct Aes256Cbc<Scope> {
    aes_key: [u8; 32],
    aes_iv: [u8; 16],
    scope: PhantomData<Scope>,
}

impl<T> Drop for Aes256Cbc<T> {
    fn drop(&mut self) {
        self.aes_key.zeroize();
        self.aes_iv.zeroize();
    }
}

impl<Scope> Aes256Cbc<Scope> {
    /// Create a new random key and IV and return
    /// them as [`Aes256Cbc`] struct.
    #[inline(always)]
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut aes_key = [0; 32];
        let mut aes_iv = [0; 16];
        rng.fill_bytes(&mut aes_key);
        rng.fill_bytes(&mut aes_iv);
        Aes256Cbc {
            aes_key,
            aes_iv,
            scope: PhantomData,
        }
    }

    /// Create key and IV from a `Vec<u8>` that contains the
    /// concatenated key and IV values and return the result
    /// as `Aes256Cbc` struct.
    #[inline(always)]
    pub fn from_vec<T>(aes_key_iv: T) -> Result<Self, HacaoiError>
    where
        T: Into<Vec<u8>>,
    {
        let mut aes_key_iv_vec_u8: Vec<u8> = aes_key_iv.into();
        if 48 != aes_key_iv_vec_u8.len() {
            return Err(HacaoiError::StringError(
                "wrong length of Vec<u8> containing aes key and IV".into(),
            ));
        }
        let mut aes_key: [u8; 32] = [0; 32];
        let mut aes_iv = [0; 16];
        aes_key.copy_from_slice(&aes_key_iv_vec_u8.as_slice()[0..32]);
        aes_iv.copy_from_slice(&aes_key_iv_vec_u8.as_slice()[32..48]);
        aes_key_iv_vec_u8.zeroize();
        Ok(Aes256Cbc {
            aes_key,
            aes_iv,
            scope: PhantomData,
        })
    }

    /// Build [`Aes256Cbc`] struct from the given key and IV.
    #[inline(always)]
    pub fn from_key_iv(aes_key: [u8; 32], aes_iv: [u8; 16]) -> Self {
        Aes256Cbc {
            aes_key,
            aes_iv,
            scope: PhantomData,
        }
    }

    /// Get the key
    #[inline(always)]
    pub fn key(&self) -> [u8; 32] {
        self.aes_key
    }

    /// Get the IV
    #[inline(always)]
    pub fn iv(&self) -> [u8; 16] {
        self.aes_iv
    }

    /// Get key and IV as concatenated `Vec<u8>`
    #[inline(always)]
    pub fn key_iv_as_vec(&self) -> Vec<u8> {
        let mut aes_key_iv: Vec<u8> = Vec::new();
        aes_key_iv.extend_from_slice(&self.aes_key);
        aes_key_iv.extend_from_slice(&self.aes_iv);
        aes_key_iv
    }
}
