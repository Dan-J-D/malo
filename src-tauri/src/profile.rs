//! Connection profiles: a file the user keeps wherever they like (like a KeePassXC database),
//! encrypted with a password of its own. It holds which server to connect to, the certificate
//! pinned for it, the username and, if the user wants, the Malo password. The app itself only
//! remembers the paths of recently used profile files, never a server.
//!
//! File: JSON `{ format, kdf: { m_kib, t, p }, salt, data }` (hex), `data` is
//! `nonce(12) | AES-256-GCM(payload)`. The format, KDF settings and salt are authenticated as AAD,
//! so weakening the KDF in the file makes it fail to open instead of cracking faster.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const FORMAT: &str = "malo-profile-v1";
/// File name extension, without the dot.
pub const EXTENSION: &str = "malo";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

/// What new profiles are sealed with: m=128 MiB, t=3 (about a second on a laptop).
const DEFAULT_KDF: Kdf = Kdf {
    m_kib: 128 * 1024,
    t: 3,
    p: 1,
};
/// A crafted file mustn't make the app spend gigabytes of memory or minutes of CPU.
const MAX_KDF: Kdf = Kdf {
    m_kib: 1024 * 1024,
    t: 10,
    p: 4,
};

fn kdf() -> Kdf {
    // Debug builds only: the end-to-end tests unlock profiles many times.
    if cfg!(debug_assertions) && std::env::var("MALO_INSECURE_FAST_KDF").as_deref() == Ok("1") {
        Kdf {
            m_kib: 8 * 1024,
            t: 1,
            p: 1,
        }
    } else {
        DEFAULT_KDF
    }
}

#[derive(Serialize, Deserialize)]
struct File {
    format: String,
    kdf: Kdf,
    salt: String,
    data: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Server {
    /// The server bundled with the app, on this computer.
    Local,
    /// `fingerprint` is the pinned certificate (or authority); none for a publicly trusted one.
    Remote {
        url: String,
        fingerprint: Option<String>,
    },
}

/// The decrypted contents of a profile.
#[derive(Serialize, Deserialize, Clone)]
pub struct Data {
    pub server: Server,
    pub username: Option<String>,
    /// The Malo password, only when the user chose to keep it here.
    pub password: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Data")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "…"))
            .finish()
    }
}

/// The key of an open profile, kept so changes (a new pin, another username) can be saved
/// without asking for its password again. Forgotten when the profile is closed.
pub struct Sealer {
    kdf: Kdf,
    salt: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong password, or the profile file was damaged")]
    WrongPassword,
    #[error("not a Malo profile file")]
    NotAProfile,
    #[error("this profile was made by a newer version of Malo")]
    Unsupported,
    #[error("{0}")]
    Other(String),
}

fn derive(password: &str, salt: &[u8; 16], kdf: Kdf) -> Result<Zeroizing<[u8; 32]>, Error> {
    use unicode_normalization::UnicodeNormalization;
    // NFC: the same password typed as composed or decomposed characters gives the same key.
    let password: Zeroizing<String> = Zeroizing::new(password.nfc().collect());
    let params =
        Params::new(kdf.m_kib, kdf.t, kdf.p, Some(32)).map_err(|e| Error::Other(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| Error::Other(e.to_string()))?;
    Ok(key)
}

fn aad(kdf: Kdf, salt: &[u8; 16]) -> Vec<u8> {
    let mut a = FORMAT.as_bytes().to_vec();
    for n in [kdf.m_kib, kdf.t, kdf.p] {
        a.extend_from_slice(&n.to_be_bytes());
    }
    a.extend_from_slice(salt);
    a
}

impl Sealer {
    /// A new key for `password` with a fresh salt. Slow: call from a blocking thread.
    pub fn new(password: &str) -> Result<Sealer, Error> {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let kdf = kdf();
        Ok(Sealer {
            kdf,
            salt,
            key: derive(password, &salt, kdf)?,
        })
    }

    pub fn seal(&self, data: &Data) -> Result<Vec<u8>, Error> {
        let plain =
            Zeroizing::new(serde_json::to_vec(data).map_err(|e| Error::Other(e.to_string()))?);
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = Aes256Gcm::new_from_slice(self.key.as_ref())
            .expect("32-byte key")
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad(self.kdf, &self.salt),
                },
            )
            .map_err(|_| Error::Other("encryption failed".into()))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ct);
        let file = File {
            format: FORMAT.into(),
            kdf: self.kdf,
            salt: hex::encode(self.salt),
            data: hex::encode(blob),
        };
        serde_json::to_vec_pretty(&file).map_err(|e| Error::Other(e.to_string()))
    }
}

/// Opens a profile file's bytes. Slow: call from a blocking thread.
pub fn open(bytes: &[u8], password: &str) -> Result<(Data, Sealer), Error> {
    let file: File = serde_json::from_slice(bytes).map_err(|_| Error::NotAProfile)?;
    if !file.format.starts_with("malo-profile-") {
        return Err(Error::NotAProfile);
    }
    if file.format != FORMAT {
        return Err(Error::Unsupported);
    }
    let k = file.kdf;
    if k.m_kib > MAX_KDF.m_kib || k.t > MAX_KDF.t || k.p > MAX_KDF.p || k.t < 1 || k.p < 1 {
        return Err(Error::Other(
            "the profile's key derivation settings are out of range".into(),
        ));
    }
    let salt: [u8; 16] = hex::decode(&file.salt)
        .ok()
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::NotAProfile)?;
    let blob = hex::decode(&file.data).map_err(|_| Error::NotAProfile)?;
    if blob.len() < 12 + 16 {
        return Err(Error::NotAProfile);
    }
    let key = derive(password, &salt, k)?;
    let plain = Zeroizing::new(
        Aes256Gcm::new_from_slice(key.as_ref())
            .expect("32-byte key")
            .decrypt(
                Nonce::from_slice(&blob[..12]),
                Payload {
                    msg: &blob[12..],
                    aad: &aad(k, &salt),
                },
            )
            .map_err(|_| Error::WrongPassword)?,
    );
    let data: Data = serde_json::from_slice(&plain).map_err(|_| Error::NotAProfile)?;
    Ok((data, Sealer { kdf: k, salt, key }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Data {
        Data {
            server: Server::Remote {
                url: "https://backup.lan:8443".into(),
                fingerprint: Some("AB:CD".into()),
            },
            username: Some("alice".into()),
            password: Some(Zeroizing::new("hunter2hunter2".into())),
        }
    }

    #[test]
    fn round_trip_and_wrong_password() {
        std::env::set_var("MALO_INSECURE_FAST_KDF", "1");
        let s = Sealer::new("profile pw").unwrap();
        let bytes = s.seal(&sample()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("alice") && !text.contains("backup.lan") && !text.contains("hunter2")
        );
        let (d, s2) = open(&bytes, "profile pw").unwrap();
        assert_eq!(d.server, sample().server);
        assert_eq!(
            d.password.as_deref().map(|p| p.as_str()),
            Some("hunter2hunter2")
        );
        // Saving again with the kept key opens with the same password.
        let again = s2.seal(&d).unwrap();
        assert!(open(&again, "profile pw").is_ok());
        assert!(matches!(open(&bytes, "wrong"), Err(Error::WrongPassword)));
        // Composed and decomposed "é" are the same password.
        let s = Sealer::new("caf\u{e9}").unwrap();
        assert!(open(&s.seal(&sample()).unwrap(), "cafe\u{301}").is_ok());
    }

    #[test]
    fn tampered_settings_and_junk_are_refused() {
        std::env::set_var("MALO_INSECURE_FAST_KDF", "1");
        let s = Sealer::new("pw").unwrap();
        let mut file: serde_json::Value =
            serde_json::from_slice(&s.seal(&sample()).unwrap()).unwrap();
        file["kdf"]["m_kib"] = 4096.into();
        let weakened = serde_json::to_vec(&file).unwrap();
        assert!(matches!(open(&weakened, "pw"), Err(Error::WrongPassword)));
        file["kdf"]["m_kib"] = (64 * 1024 * 1024).into();
        assert!(matches!(
            open(&serde_json::to_vec(&file).unwrap(), "pw"),
            Err(Error::Other(_))
        ));
        assert!(matches!(open(b"{}", "pw"), Err(Error::NotAProfile)));
        assert!(matches!(open(b"not json", "pw"), Err(Error::NotAProfile)));
        file["format"] = "malo-profile-v9".into();
        assert!(matches!(
            open(&serde_json::to_vec(&file).unwrap(), "pw"),
            Err(Error::Unsupported)
        ));
    }
}
