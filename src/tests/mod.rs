// Reference the modules for testing. This way we make
// sure the tests itself can reference non public modules.

/// Test AES functions
pub mod test_aes;
/// Test bas64 conversions
pub mod test_base64_trait;
/// Test the hybrd crypto functions
pub mod test_hybrid_crypto;
/// Test the RSA functions
pub mod test_rsa;
/// Test zeroize
pub mod zeroize;
