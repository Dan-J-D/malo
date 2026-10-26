//! Key hierarchy and encryption primitives.
//!
//! ```text
//! password ─Argon2id(salt)─► KEK ─AES-256-GCM wrap─► MDK (vault.bin)
//! MDK ─HKDF─► config key · sqlcipher key · spool key
//! archive key (random, inside the encrypted config) ─HKDF per object─► segmented AES-256-GCM
//! ```

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub type Key = Zeroizing<[u8; 32]>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("wrong password or corrupted vault")]
    WrongPassword,
    #[error("decryption failed: data was modified or the key is wrong")]
    Integrity,
    #[error("truncated ciphertext")]
    Truncated,
    #[error("unsupported format: {0}")]
    Format(String),
    #[error("key derivation failed: {0}")]
    Kdf(String),
}

pub fn random_key() -> Key {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(k.as_mut());
    k
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// HKDF-SHA256 expand of `ikm` with a context label.
pub fn derive(ikm: &[u8], salt: Option<&[u8]>, info: &str) -> Key {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), out.as_mut())
        .expect("32 bytes is a valid HKDF length");
    out
}

pub fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Check value of an archive key, kept in the recovery kit: a mistyped or damaged kit is refused
/// instead of creating a user who can read nothing. Reveals nothing usable about the key.
pub fn kit_check(archive_key: &Key) -> String {
    let k = derive(archive_key.as_ref(), None, "malo/v1/kit-check");
    hmac_hex(k.as_ref(), b"malo recovery kit")[..16].to_string()
}

// ───────────────────────────── vault ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Production parameters: m=256 MiB, t=3, p=1.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 256 * 1024,
        t: 3,
        p: 1,
    };
    /// Cheap parameters for tests.
    pub const TEST: KdfParams = KdfParams {
        m_kib: 8 * 1024,
        t: 1,
        p: 1,
    };

    /// Honours `MALO_INSECURE_FAST_KDF=1` (tests only).
    pub fn from_env() -> KdfParams {
        if std::env::var("MALO_INSECURE_FAST_KDF").as_deref() == Ok("1") {
            KdfParams::TEST
        } else {
            KdfParams::DEFAULT
        }
    }
}

const VAULT_MAGIC: &[u8; 8] = b"MALOVLT1";
const VAULT_HEADER_LEN: usize = 8 + 1 + 12 + 16;
const VAULT_LEN: usize = VAULT_HEADER_LEN + 12 + 32 + 16;

/// The wrapped master data key of one user (contents of `vault.bin`).
///
/// Layout: `magic(8) | version(1) | m_kib(4) | t(4) | p(4) | salt(16) | nonce(12) | ct(32+16)`.
/// The header (magic … salt) and the user id are authenticated as AAD.
#[derive(Clone, PartialEq, Eq)]
pub struct Vault {
    pub params: KdfParams,
    pub salt: [u8; 16],
    nonce: [u8; 12],
    wrapped: Vec<u8>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

/// Passwords are NFC-normalized first: the same password typed as composed or decomposed
/// characters (it differs between operating systems and input methods) derives the same key.
fn kek(password: &str, salt: &[u8; 16], params: KdfParams) -> Result<Key, CryptoError> {
    use unicode_normalization::UnicodeNormalization;
    let password: Zeroizing<String> = Zeroizing::new(password.nfc().collect());
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

impl Vault {
    fn header(&self) -> [u8; VAULT_HEADER_LEN] {
        let mut h = [0u8; VAULT_HEADER_LEN];
        h[..8].copy_from_slice(VAULT_MAGIC);
        h[8] = 1;
        h[9..13].copy_from_slice(&self.params.m_kib.to_be_bytes());
        h[13..17].copy_from_slice(&self.params.t.to_be_bytes());
        h[17..21].copy_from_slice(&self.params.p.to_be_bytes());
        h[21..37].copy_from_slice(&self.salt);
        h
    }

    fn aad(&self, user_id: &str) -> Vec<u8> {
        let mut aad = self.header().to_vec();
        aad.extend_from_slice(user_id.as_bytes());
        aad
    }

    /// Wraps `mdk` under a key derived from `password` with a fresh salt.
    pub fn seal(
        user_id: &str,
        password: &str,
        mdk: &Key,
        params: KdfParams,
    ) -> Result<Vault, CryptoError> {
        let mut v = Vault {
            params,
            salt: random_bytes(),
            nonce: random_bytes(),
            wrapped: vec![],
        };
        let kek = kek(password, &v.salt, params)?;
        let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).expect("32-byte key");
        v.wrapped = cipher
            .encrypt(
                Nonce::from_slice(&v.nonce),
                Payload {
                    msg: mdk.as_ref(),
                    aad: &v.aad(user_id),
                },
            )
            .map_err(|_| CryptoError::Integrity)?;
        Ok(v)
    }

    /// Unwraps the MDK. A tag failure means a wrong password (or tampering).
    pub fn open(&self, user_id: &str, password: &str) -> Result<Key, CryptoError> {
        let kek = kek(password, &self.salt, self.params)?;
        let cipher = Aes256Gcm::new_from_slice(kek.as_ref()).expect("32-byte key");
        let mut pt = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.wrapped,
                    aad: &self.aad(user_id),
                },
            )
            .map_err(|_| CryptoError::WrongPassword)?;
        if pt.len() != 32 {
            pt.zeroize();
            return Err(CryptoError::Format("bad key length".into()));
        }
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&pt);
        pt.zeroize();
        Ok(k)
    }

    /// Re-wraps the same MDK under a new password (and optionally new Argon2 parameters).
    pub fn rewrap(
        &self,
        user_id: &str,
        old: &str,
        new: &str,
        params: KdfParams,
    ) -> Result<Vault, CryptoError> {
        let mdk = self.open(user_id, old)?;
        Vault::seal(user_id, new, &mdk, params)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header().to_vec();
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Vault, CryptoError> {
        if b.len() != VAULT_LEN || &b[..8] != VAULT_MAGIC {
            return Err(CryptoError::Format("not a malo vault".into()));
        }
        if b[8] != 1 {
            return Err(CryptoError::Format(format!("vault version {}", b[8])));
        }
        let u32_at = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
        let params = KdfParams {
            m_kib: u32_at(9),
            t: u32_at(13),
            p: u32_at(17),
        };
        if !params.within(MAX_VAULT_KDF) {
            return Err(CryptoError::Format(
                "vault key derivation settings out of range".into(),
            ));
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[21..37]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&b[37..49]);
        Ok(Vault {
            params,
            salt,
            nonce,
            wrapped: b[49..].to_vec(),
        })
    }
}

/// Keys derived from the MDK for one user.
pub struct UserKeys {
    pub config: Key,
    pub sqlcipher: Key,
    pub spool: Key,
}

impl UserKeys {
    pub fn derive(mdk: &Key) -> UserKeys {
        UserKeys {
            config: derive(mdk.as_ref(), None, "malo/v1/config"),
            sqlcipher: derive(mdk.as_ref(), None, "malo/v1/sqlcipher"),
            spool: derive(mdk.as_ref(), None, "malo/v1/spool"),
        }
    }
}

// ───────────────────────────── passphrase-sealed files ─────────────────────────────

/// Upper bounds for KDF parameters read from an uploaded file (a recovery kit): what Malo seals
/// with itself, so a crafted file costs no more than a real one.
pub const MAX_FILE_KDF: KdfParams = KdfParams::DEFAULT;

/// Upper bounds for the vault's KDF parameters. The vault is the server's own file, but a damaged
/// or planted one still mustn't make it spend gigabytes of memory or minutes of CPU.
pub const MAX_VAULT_KDF: KdfParams = KdfParams {
    m_kib: 1024 * 1024,
    t: 10,
    p: 4,
};

impl KdfParams {
    /// Within `max`, and usable (t and p of at least 1).
    pub fn within(&self, max: KdfParams) -> bool {
        self.m_kib <= max.m_kib && self.t <= max.t && self.p <= max.p && self.t >= 1 && self.p >= 1
    }
}

/// Seals `plaintext` under a passphrase (Argon2id, then AES-256-GCM). Returns the salt and the
/// sealed bytes. Call from a blocking thread.
pub fn seal_with_passphrase(
    passphrase: &str,
    aad: &[u8],
    plaintext: &[u8],
    params: KdfParams,
) -> Result<([u8; 16], Vec<u8>), CryptoError> {
    let salt: [u8; 16] = random_bytes();
    let key = kek(passphrase, &salt, params)?;
    Ok((salt, seal_blob(&key, aad, plaintext)))
}

/// Opens what [`seal_with_passphrase`] sealed. A wrong passphrase is an integrity error.
pub fn open_with_passphrase(
    passphrase: &str,
    aad: &[u8],
    salt: &[u8; 16],
    params: KdfParams,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if !params.within(MAX_FILE_KDF) {
        return Err(CryptoError::Format(
            "key derivation settings out of range".into(),
        ));
    }
    let key = kek(passphrase, salt, params)?;
    open_blob(&key, aad, sealed)
}

// ───────────────────────────── small blobs ─────────────────────────────

/// AES-256-GCM: `nonce(12) | ct+tag`.
pub fn seal_blob(key: &Key, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; 12] = random_bytes();
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encrypt");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    out
}

pub fn open_blob(key: &Key, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < 12 + 16 {
        return Err(CryptoError::Truncated);
    }
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    cipher
        .decrypt(
            Nonce::from_slice(&blob[..12]),
            Payload {
                msg: &blob[12..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Integrity)
}

// ───────────────────────────── segmented stream ─────────────────────────────

/// Segment size of the streaming format (plaintext bytes per segment).
pub const SEGMENT: usize = 64 * 1024;
const STREAM_MAGIC: &[u8; 8] = b"MALOENC1";
/// `magic(8) | version(1) | segment(4) | salt(32) | nonce prefix(7)`
pub const STREAM_HEADER_LEN: usize = 8 + 1 + 4 + 32 + 7;
const TAG: usize = 16;

/// Ciphertext size for a plaintext of `len` bytes.
pub fn encrypted_len(len: u64) -> u64 {
    let seg = SEGMENT as u64;
    let segments = if len == 0 { 1 } else { len.div_ceil(seg) };
    STREAM_HEADER_LEN as u64 + len + segments * TAG as u64
}

fn segment_nonce(prefix: &[u8; 7], counter: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    n
}

fn object_cipher(archive_key: &Key, salt: &[u8]) -> Aes256Gcm {
    let k = derive(archive_key.as_ref(), Some(salt), "malo/v1/object");
    Aes256Gcm::new_from_slice(k.as_ref()).expect("32-byte key")
}

/// Encrypts a whole object with the STREAM construction (per-object HKDF key, 64 KiB segments,
/// counter + last-segment flag in the nonce, header as AAD). Truncation and reordering are detected.
pub fn encrypt_object(archive_key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let salt: [u8; 32] = random_bytes();
    let prefix: [u8; 7] = random_bytes();
    let mut header = Vec::with_capacity(STREAM_HEADER_LEN);
    header.extend_from_slice(STREAM_MAGIC);
    header.push(1);
    header.extend_from_slice(&(SEGMENT as u32).to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&prefix);
    let cipher = object_cipher(archive_key, &salt);
    let mut out = Vec::with_capacity(encrypted_len(plaintext.len() as u64) as usize);
    out.extend_from_slice(&header);
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[][..]]
    } else {
        plaintext.chunks(SEGMENT).collect()
    };
    let n = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        let nonce = segment_nonce(&prefix, i as u32, i + 1 == n);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: chunk,
                    aad: &header,
                },
            )
            .expect("encrypt");
        out.extend_from_slice(&ct);
    }
    out
}

/// Incremental decryptor: feed ciphertext in arbitrary chunks, get plaintext back.
pub struct StreamDecryptor {
    archive_key: Key,
    header: Vec<u8>,
    cipher: Option<Aes256Gcm>,
    prefix: [u8; 7],
    buf: Vec<u8>,
    counter: u32,
    finished: bool,
}

impl StreamDecryptor {
    pub fn new(archive_key: &Key) -> Self {
        StreamDecryptor {
            archive_key: archive_key.clone(),
            header: Vec::new(),
            cipher: None,
            prefix: [0; 7],
            buf: Vec::new(),
            counter: 0,
            finished: false,
        }
    }

    fn init(&mut self) -> Result<(), CryptoError> {
        let h = &self.buf[..STREAM_HEADER_LEN];
        if &h[..8] != STREAM_MAGIC {
            return Err(CryptoError::Format("not a malo encrypted object".into()));
        }
        if h[8] != 1 {
            return Err(CryptoError::Format(format!("object version {}", h[8])));
        }
        if u32::from_be_bytes(h[9..13].try_into().unwrap()) as usize != SEGMENT {
            return Err(CryptoError::Format("unsupported segment size".into()));
        }
        self.cipher = Some(object_cipher(&self.archive_key, &h[13..45]));
        self.prefix.copy_from_slice(&h[45..52]);
        self.header = h.to_vec();
        self.buf.drain(..STREAM_HEADER_LEN);
        Ok(())
    }

    fn open_segment(&mut self, len: usize, last: bool) -> Result<Vec<u8>, CryptoError> {
        let nonce = segment_nonce(&self.prefix, self.counter, last);
        let seg: Vec<u8> = self.buf.drain(..len).collect();
        let pt = self
            .cipher
            .as_ref()
            .unwrap()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &seg,
                    aad: &self.header,
                },
            )
            .map_err(|_| CryptoError::Integrity)?;
        self.counter = self.counter.checked_add(1).ok_or(CryptoError::Integrity)?;
        Ok(pt)
    }

    /// Feeds ciphertext. Full non-final segments are decrypted as soon as more data follows them.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.finished {
            return Err(CryptoError::Integrity);
        }
        self.buf.extend_from_slice(data);
        if self.cipher.is_none() {
            if self.buf.len() < STREAM_HEADER_LEN {
                return Ok(vec![]);
            }
            self.init()?;
        }
        let mut out = Vec::new();
        // Keep at least one byte beyond a full segment so we know it isn't the final one.
        while self.buf.len() > SEGMENT + TAG {
            out.extend(self.open_segment(SEGMENT + TAG, false)?);
        }
        Ok(out)
    }

    /// Decrypts the final segment. Fails if the stream was truncated.
    pub fn finish(mut self) -> Result<Vec<u8>, CryptoError> {
        if self.cipher.is_none() || self.buf.len() < TAG || self.buf.len() > SEGMENT + TAG {
            return Err(CryptoError::Truncated);
        }
        let len = self.buf.len();
        let pt = self.open_segment(len, true)?;
        self.finished = true;
        Ok(pt)
    }
}

pub fn decrypt_object(archive_key: &Key, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut d = StreamDecryptor::new(archive_key);
    let mut out = d.update(ciphertext)?;
    out.extend(d.finish()?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_round_trip_and_wrong_password() {
        let mdk = random_key();
        let v = Vault::seal("u1", "correct horse", &mdk, KdfParams::TEST).unwrap();
        let parsed = Vault::from_bytes(&v.to_bytes()).unwrap();
        assert_eq!(*parsed.open("u1", "correct horse").unwrap(), *mdk);
        assert!(matches!(
            parsed.open("u1", "wrong"),
            Err(CryptoError::WrongPassword)
        ));
        // Bound to the user id.
        assert!(parsed.open("u2", "correct horse").is_err());
    }

    #[test]
    fn unicode_passwords_are_normalized() {
        let mdk = random_key();
        let composed = "p\u{e4}ssw\u{f6}rd \u{1F510}"; // ä ö as single code points
        let decomposed = "pa\u{308}sswo\u{308}rd \u{1F510}"; // a + combining diaeresis
        let v = Vault::seal("u1", composed, &mdk, KdfParams::TEST).unwrap();
        assert_eq!(*v.open("u1", decomposed).unwrap(), *mdk);
        // Invisible characters are still part of the password.
        assert!(v.open("u1", &format!("{composed}\u{200B}")).is_err());
    }

    #[test]
    fn vault_header_tamper_rejected() {
        let mdk = random_key();
        let v = Vault::seal("u1", "pw", &mdk, KdfParams::TEST).unwrap();
        let mut b = v.to_bytes();
        b[30] ^= 1; // salt byte
        assert!(Vault::from_bytes(&b).unwrap().open("u1", "pw").is_err());
        let mut b = v.to_bytes();
        // Bump t: header is AAD, so even if the KDF ran with other params the tag fails.
        b[16] ^= 2;
        assert!(Vault::from_bytes(&b).unwrap().open("u1", "pw").is_err());
        let mut b = v.to_bytes();
        let last = b.len() - 1;
        b[last] ^= 1;
        assert!(Vault::from_bytes(&b).unwrap().open("u1", "pw").is_err());
    }

    #[test]
    fn password_change_keeps_mdk() {
        let mdk = random_key();
        let v = Vault::seal("u1", "old", &mdk, KdfParams::TEST).unwrap();
        let config_ct = seal_blob(&UserKeys::derive(&mdk).config, b"cfg", b"{\"accounts\":[]}");
        let v2 = v.rewrap("u1", "old", "new", KdfParams::TEST).unwrap();
        assert_ne!(v.to_bytes(), v2.to_bytes());
        assert!(v2.open("u1", "old").is_err());
        let mdk2 = v2.open("u1", "new").unwrap();
        assert_eq!(*mdk2, *mdk);
        // Config ciphertext untouched and still decryptable.
        let pt = open_blob(&UserKeys::derive(&mdk2).config, b"cfg", &config_ct).unwrap();
        assert_eq!(&pt[..], b"{\"accounts\":[]}");
        assert!(v.rewrap("u1", "nope", "x", KdfParams::TEST).is_err());
    }

    #[test]
    fn passphrase_sealing() {
        let (salt, sealed) =
            seal_with_passphrase("correct horse", b"aad", b"secret", KdfParams::TEST).unwrap();
        let open =
            open_with_passphrase("correct horse", b"aad", &salt, KdfParams::TEST, &sealed).unwrap();
        assert_eq!(open.as_slice(), b"secret");
        assert!(
            open_with_passphrase("wrong horse", b"aad", &salt, KdfParams::TEST, &sealed).is_err()
        );
        assert!(
            open_with_passphrase("correct horse", b"other", &salt, KdfParams::TEST, &sealed)
                .is_err()
        );
        let huge = KdfParams {
            m_kib: 64 * 1024 * 1024,
            ..KdfParams::TEST
        };
        assert!(matches!(
            open_with_passphrase("correct horse", b"aad", &salt, huge, &sealed),
            Err(CryptoError::Format(_))
        ));
        // A file can't ask for more than Malo itself seals with.
        for over in [
            KdfParams {
                m_kib: KdfParams::DEFAULT.m_kib + 1,
                ..KdfParams::DEFAULT
            },
            KdfParams {
                t: KdfParams::DEFAULT.t + 1,
                ..KdfParams::DEFAULT
            },
            KdfParams {
                p: KdfParams::DEFAULT.p + 1,
                ..KdfParams::DEFAULT
            },
            KdfParams {
                t: 0,
                ..KdfParams::TEST
            },
        ] {
            assert!(matches!(
                open_with_passphrase("correct horse", b"aad", &salt, over, &sealed),
                Err(CryptoError::Format(_))
            ));
        }
    }

    #[test]
    fn vault_kdf_bounded() {
        let v = Vault::seal("u1", "pw", &random_key(), KdfParams::TEST).unwrap();
        let mut b = v.to_bytes();
        b[9..13].copy_from_slice(&(64 * 1024 * 1024u32).to_be_bytes());
        assert!(matches!(Vault::from_bytes(&b), Err(CryptoError::Format(_))));
        let mut b = v.to_bytes();
        b[17..21].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(Vault::from_bytes(&b), Err(CryptoError::Format(_))));
    }

    #[test]
    fn blob_aad_bound() {
        let k = random_key();
        let ct = seal_blob(&k, b"a", b"hello");
        assert!(open_blob(&k, b"b", &ct).is_err());
        assert_eq!(&open_blob(&k, b"a", &ct).unwrap()[..], b"hello");
    }

    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn stream_round_trip_sizes() {
        let k = random_key();
        for n in [
            0,
            1,
            SEGMENT - 1,
            SEGMENT,
            SEGMENT + 1,
            3 * SEGMENT,
            3 * SEGMENT + 17,
        ] {
            let pt = sample(n);
            let ct = encrypt_object(&k, &pt);
            assert_eq!(ct.len() as u64, encrypted_len(n as u64), "len {n}");
            assert_eq!(decrypt_object(&k, &ct).unwrap(), pt, "size {n}");
            // Incremental feeding in odd chunk sizes.
            let mut d = StreamDecryptor::new(&k);
            let mut out = Vec::new();
            for c in ct.chunks(7919) {
                out.extend(d.update(c).unwrap());
            }
            out.extend(d.finish().unwrap());
            assert_eq!(out, pt);
        }
    }

    #[test]
    fn stream_truncation_detected() {
        let k = random_key();
        let pt = sample(3 * SEGMENT + 5);
        let ct = encrypt_object(&k, &pt);
        // Drop the final segment exactly at a segment boundary.
        let cut = STREAM_HEADER_LEN + 3 * (SEGMENT + TAG);
        assert!(decrypt_object(&k, &ct[..cut]).is_err());
        assert!(decrypt_object(&k, &ct[..ct.len() - 1]).is_err());
        assert!(decrypt_object(&k, &ct[..10]).is_err());
        // Appending garbage fails too.
        let mut longer = ct.clone();
        longer.extend_from_slice(&[0u8; 40]);
        assert!(decrypt_object(&k, &longer).is_err());
    }

    #[test]
    fn stream_reorder_and_tamper_detected() {
        let k = random_key();
        let pt = sample(3 * SEGMENT + 5);
        let ct = encrypt_object(&k, &pt);
        let s = SEGMENT + TAG;
        let h = STREAM_HEADER_LEN;
        let mut swapped = ct[..h].to_vec();
        swapped.extend_from_slice(&ct[h + s..h + 2 * s]);
        swapped.extend_from_slice(&ct[h..h + s]);
        swapped.extend_from_slice(&ct[h + 2 * s..]);
        assert!(decrypt_object(&k, &swapped).is_err());
        let mut flipped = ct.clone();
        flipped[h + 5] ^= 0x80;
        assert!(decrypt_object(&k, &flipped).is_err());
        let mut hdr = ct.clone();
        hdr[20] ^= 1; // salt → different key
        assert!(decrypt_object(&k, &hdr).is_err());
        assert!(decrypt_object(&random_key(), &ct).is_err());
    }
}
