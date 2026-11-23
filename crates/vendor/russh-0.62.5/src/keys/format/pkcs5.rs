// Modified by the Broil project from russh 0.62.5; see LICENSE.txt and docs/provenance/russh-0.62.5.md for provenance.
use aes::*;
use ssh_key::PrivateKey;
use zeroize::Zeroizing;

use super::Encryption;
use crate::keys::Error;

/// Decode a secret key in the PKCS#5 format, possibly deciphering it
/// using the supplied password.
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&str>,
    enc: Encryption,
) -> Result<PrivateKey, Error> {
    use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};

    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut c = md5::Context::new();
                c.consume(pass.as_bytes());
                c.consume(&iv[..8]);
                let md5 = c.finalize();

                #[allow(clippy::unwrap_used)] // AES parameters are static
                let c = cbc::Decryptor::<Aes128>::new_from_slices(&md5.0, &iv[..]).unwrap();
                let mut dec = Zeroizing::new(secret.to_vec());
                let plaintext_len = c.decrypt_padded::<Pkcs7>(&mut dec)?.len();
                dec.truncate(plaintext_len);
                dec
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        // TODO: presumably pkcs5 could contain non-RSA keys?
        #[cfg(feature = "rsa")]
        {
            super::decode_rsa_pkcs1_der(&sec).map(Into::into)
        }
        #[cfg(not(feature = "rsa"))]
        {
            drop(sec);
            Err(Error::UnsupportedKeyType {
                key_type_string: "RSA".to_string(),
                key_type_raw: vec![],
            })
        }
    } else {
        Err(Error::KeyIsEncrypted)
    }
}
