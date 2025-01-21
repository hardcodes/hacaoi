# HaCaOI

**Ha**des **Ca**p **O**f **I**nvisibilty - a Rust libary for encryption and decryption.

Well, encrypted data is not invisble but the plaintext is, you get the drift.

This Rust library is a facade for
- AES 256 encryption/decryption in CBC mode,
- RSA encryption/decryption
- Hybrid encryption/decryption using AES and RSA,

implemented with help the Rust OpenSSL crate and with the RustCrypto crates, mainly for use at [lmtyas](https://github.com/hardcodes/lmtyas) and other non-public projects.


## About

The reason for this project was the personal desire of yours truly to replace the [openssl](https://github.com/sfackler/rust-openssl) crate used by [lmtyas](https://github.com/hardcodes/lmtyas) with functions of one or multiple of the [rust crypto](https://github.com/rustcrypto) crates.
There were no hard feelings for or against openssl per se, only the wish to get rid of an external non-rust dependency.

It turned out not to be as easy as expected, since the documentation of the RustCrypto crates is quite minimal to say the least. They also use different naming conventions for the same things as in openssl. While formally correct they often raise the question if it really **is** the same or **does** the same. The RustCrypto crates use many traits to do the same thing for many ciphers and algorithms and this is good, since they had the chance to build their stuff from scratch. You will be rewarded once you get the knack of the RustCrypto way of thinking. The challenge is to get there in the first place. There are some gaps to fill for people coming from the openssl world to be able to transfer the concepts.

Going from openssl command line tools to use the openssl library via rust openssl crate bindungs was easy. Going from rust openssl crate to RustCrypto was hard. At least for yours truly and his small dumb brain.


------

# License

The code is dual licensed under the [MIT License](./LICENSE-MIT) **or** the [APACHE 2.0 License](http://www.apache.org/licenses/LICENSE-2.0), which ever suits you better.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
