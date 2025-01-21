use std::error::Error;
use std::path::Path;

/// This trait defines the functions that are implemented by the
/// OpenSSL and RustCrypto variants.
pub trait HybridCryptoFunctions {
    /// Build **HybridCrypto** by loading an encrypted RSA
    /// private key file from the given path, hence the
    /// passphrase is needed. The RSA public key is derived
    /// from the RSA private key.
    fn from_file<P: AsRef<Path>>(
        rsa_private_key_path: P,
        rsa_private_key_password: &str,
    ) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;

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
    fn hybrid_encrypt_str(&self, plaintext_data: &str) -> Result<String, Box<dyn Error>>
    where
        Self: Sized;

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
    fn hybrid_decrypt_str(&self, hybrid_encrypted_data: &str) -> Result<String, Box<dyn Error>>
    where
        Self: Sized;

    /// Convenience function that decrypts a base64
    /// encoded String slice either with the stored
    /// RSA private key or decrypts the stored AES
    /// key and IV to decrypt the rest of the string.
    ///
    /// # Arguments
    ///
    /// - `encrypted_data`: a String slice with data to decrypt
    fn decrypt_str(&self, encrypted_data: &str) -> Result<String, Box<dyn Error>>
    where
        Self: Sized;
}
