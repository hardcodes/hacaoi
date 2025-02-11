#[cfg(feature = "b64")]
use crate::base64_trait::{Base64StringConversions, Base64VecU8Conversions};
use crate::error::HacaoiError;
use std::path::Path;

/// Valid key size in bits used for random rsa private key creation.
/// 
/// ⚠️ **Security Warning**: A key size smaller than 2048 bits is insecure
/// as of the year 2025. Even 2048 is questionable. Use 4096 if possible.
pub enum KeySize {
    /// Key size of 1024 bits (⚠️ **Security Warning**: use only if you know what you are doing!)
    Bit1024 = 1024,
    /// Key size of 2048 bits
    Bit2048 = 2048,
    /// Key size of 3072 bits
    Bit3072 = 3072,
    /// Key size of 4096 bits
    Bit4096 = 4096,
}

/// Encryption and Decryption functions that are
/// implemented by the OpenSSL and RustCrypto RSA
/// variants.
pub trait RsaKeysFunctions {
    /// Build a new random RSA key pair.
    fn random(key_size: KeySize) -> Result<Self, HacaoiError>
    where
        Self: Sized;
    /// Loads an encryped RSA private key file from
    /// the given path, hence the passphrase is needed.
    /// The RSA public key is derived from the RSA private key.
    fn from_file<P: AsRef<Path>>(
        rsa_private_key_path: P,
        rsa_private_key_password: &str,
    ) -> Result<Self, HacaoiError>
    where
        Self: Sized;

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Encrypt a String slice with stored RSA public key
    /// using PKCS#1 v1.5 padding and return it as `Vec<u8>`.
    fn encrypt_str_pkcs1v15_padding_to_vec(&self, plaintext: &str) -> Result<Vec<u8>, HacaoiError>
    where
        Self: Sized,
    {
        self.encrypt_bytes_pkcs1v15_padding_to_vec(plaintext.as_bytes())
    }
    /// Encrypt a String slice with stored RSA public key
    /// using PKCS#1 v1.5 padding and return it as `Vec<u8>`.
    fn encrypt_bytes_pkcs1v15_padding_to_vec(
        &self,
        unencrypted_bytes: &[u8],
    ) -> Result<Vec<u8>, HacaoiError>
    where
        Self: Sized;
    /// Encrypt `&[u8]` slice with stored RSA public key
    /// using PKCS#1 v1.5 padding and and return it as base64
    /// encoded String.
    #[cfg(feature = "b64")]
    fn encrypt_bytes_pkcs1v15_padding_to_b64(
        &self,
        unencrypted_bytes: &[u8],
    ) -> Result<String, HacaoiError>
    where
        Self: Sized,
    {
        let buf: Vec<u8> = self.encrypt_bytes_pkcs1v15_padding_to_vec(unencrypted_bytes)?;
        Ok(buf.to_base64_encoded())
    }

    /// Encrypt a String slice with stored RSA public key
    /// using PKCS#1 v1.5 padding and return it as base64
    /// encoded String.
    #[cfg(feature = "b64")]
    fn encrypt_str_pkcs1v15_padding_to_b64(&self, plaintext: &str) -> Result<String, HacaoiError>
    where
        Self: Sized,
    {
        let buf: Vec<u8> = self.encrypt_str_pkcs1v15_padding_to_vec(plaintext)?;
        Ok(buf.to_base64_encoded())
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Decryption
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Decrypt `&[u8]` with RSA encrypted data and
    /// PKCS#1 v1.5 padding using the stored RSA private key
    /// and return it as plaintext String.
    fn decrypt_bytes_pkcs1v15_padding_to_vec(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<Vec<u8>, HacaoiError>
    where
        Self: Sized;

    /// Decrypt `&[u8]` with RSA encrypted data and
    /// PKCS#1 v1.5 padding using the stored RSA private key
    /// and return it as plaintext String.
    fn decrypt_bytes_pkcs1v15_padding_to_string(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<String, HacaoiError>
    where
        Self: Sized;

    /// Decrypt a base64 encoded String slice with
    /// RSA encrypted data and PKCS#1 v1.5 padding
    /// using the stored RSA private key and return
    /// it as `Vec<u8>`.
    #[cfg(feature = "b64")]
    fn decrypt_b64_pkcs1v15_padding_to_vec(
        &self,
        encrypted_b64_data: &str,
    ) -> Result<Vec<u8>, HacaoiError>
    where
        Self: Sized,
    {
        let raw_encrypted_data = match Vec::from_base64_encoded(encrypted_b64_data) {
            Ok(b) => b,
            Err(e) => {
                return Err(HacaoiError::Base64DecodeError(e));
            }
        };
        self.decrypt_bytes_pkcs1v15_padding_to_vec(&raw_encrypted_data)
    }

    /// Decrypt a base64 encoded String slice with
    /// RSA encrypted data and PKCS#1 v1.5 padding
    /// using the stored RSA private key and return
    /// it as plaintext String.
    #[cfg(feature = "b64")]
    fn decrypt_b64_pkcs1v15_padding_to_string(
        &self,
        encrypted_b64_data: &str,
    ) -> Result<String, HacaoiError>
    where
        Self: Sized,
    {
        let raw_encrypted_data = match Vec::from_base64_encoded(encrypted_b64_data) {
            Ok(b) => b,
            Err(e) => {
                return Err(format!("Could not base64 decode value: {}", &e).into());
            }
        };
        self.decrypt_bytes_pkcs1v15_padding_to_string(&raw_encrypted_data)
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Signature
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Create a sha512 signature for the given
    /// string slice using the rsa private key.
    fn sign_str_sha512(&self, data_to_sign: &str) -> Result<Vec<u8>, HacaoiError>
    where
        Self: Sized;

    /// Create a sha512 signature for the given
    /// string slice using the rsa private key
    /// and encode it to base64.
    #[cfg(feature = "b64")]
    fn sign_str_sha512_b64(&self, data_to_sign: &str) -> Result<String, HacaoiError>
    where
        Self: Sized,
    {
        let signature = self.sign_str_sha512(data_to_sign)?;
        Ok(signature.to_base64_encoded())
    }

    /// Validate a `&[u8]` signature that was created using
    /// the corresponding rsa private key.
    fn validate_sha512_bytes_signature(
        &self,
        signed_data: &str,
        signature_bytes: &[u8],
    ) -> Result<(), HacaoiError>
    where
        Self: Sized;

    /// Validate a base64 encoded signature that was created
    /// using the corresponding rsa private key.
    #[cfg(feature = "b64")]
    fn validate_sha512_b64_signature(
        &self,
        signed_data: &str,
        signature_b64: &str,
    ) -> Result<(), HacaoiError>
    where
        Self: Sized,
    {
        let signature_bytes = match Vec::from_base64_encoded(signature_b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(format!("Could not base64 decode signature: {}", &e).into());
            }
        };
        self.validate_sha512_bytes_signature(signed_data, &signature_bytes)
    }
}
