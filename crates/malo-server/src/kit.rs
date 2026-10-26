//! Recovery kit files. The kit holds the archive key; the file is sealed with a passphrase the
//! user picks when saving it (not the account password: the kit is for when that's forgotten).

use base64::Engine;
use chrono::Utc;
use malo_api::{KitKdf, RecoveryKit, RecoveryKitFile, SealedRecoveryKit, SEALED_KIT_FORMAT};
use malo_core::crypto::{self, KdfParams, Key};
use zeroize::Zeroizing;

use crate::error::{ApiErr, ApiResult};

const PLAIN_FORMAT: &str = "malo-recovery-kit-v1";
const AAD: &[u8] = b"malo/v1/recovery-kit";
pub const MIN_PASSPHRASE: usize = 12;

pub fn check_passphrase(passphrase: &str) -> ApiResult<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Err(ApiErr::bad_request(format!(
            "the kit passphrase must have at least {MIN_PASSPHRASE} characters"
        )));
    }
    Ok(())
}

/// Builds the kit of a user and seals it with `passphrase` (Argon2id; call from a blocking thread).
pub fn seal(
    user_id: &str,
    username: &str,
    archive_key: &Key,
    passphrase: &str,
) -> anyhow::Result<SealedRecoveryKit> {
    let kit = RecoveryKit {
        format: PLAIN_FORMAT.into(),
        user_id: user_id.into(),
        username: username.into(),
        created_at: Utc::now(),
        archive_key: hex::encode(archive_key.as_ref()),
        check: Some(crypto::kit_check(archive_key)),
    };
    let json = Zeroizing::new(serde_json::to_vec(&kit)?);
    let params = KdfParams::from_env();
    let (salt, sealed) = crypto::seal_with_passphrase(passphrase, AAD, &json, params)?;
    Ok(SealedRecoveryKit {
        format: SEALED_KIT_FORMAT.into(),
        kdf: KitKdf {
            algorithm: "argon2id".into(),
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
        },
        salt: hex::encode(salt),
        data: base64::engine::general_purpose::STANDARD.encode(sealed),
    })
}

/// The archive key in a kit file, checked against the kit's check value. A sealed kit needs its
/// passphrase (Argon2id; call from a blocking thread). Errors are user-facing.
pub fn open(file: &RecoveryKitFile, passphrase: Option<&str>) -> ApiResult<Key> {
    let bad = || ApiErr::bad_request("this isn't a valid Malo recovery kit");
    let kit: RecoveryKit = match file {
        RecoveryKitFile::Plain(k) => {
            if k.format != PLAIN_FORMAT {
                return Err(bad());
            }
            k.clone()
        }
        RecoveryKitFile::Sealed(s) => {
            if s.format != SEALED_KIT_FORMAT || s.kdf.algorithm != "argon2id" {
                return Err(bad());
            }
            let passphrase = passphrase
                .filter(|p| !p.is_empty())
                .ok_or_else(|| ApiErr::bad_request("enter the passphrase of the recovery kit"))?;
            let salt: [u8; 16] = hex::decode(&s.salt)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(bad)?;
            let sealed = base64::engine::general_purpose::STANDARD
                .decode(&s.data)
                .map_err(|_| bad())?;
            let params = KdfParams {
                m_kib: s.kdf.m_kib,
                t: s.kdf.t,
                p: s.kdf.p,
            };
            let json = crypto::open_with_passphrase(passphrase, AAD, &salt, params, &sealed)
                .map_err(|e| match e {
                    crypto::CryptoError::Integrity => {
                        ApiErr::unauthorized("the kit passphrase is wrong")
                    }
                    _ => bad(),
                })?;
            serde_json::from_slice(&json).map_err(|_| bad())?
        }
    };
    let bytes = Zeroizing::new(hex::decode(kit.archive_key.trim()).map_err(|_| bad())?);
    let mut key = Zeroizing::new([0u8; 32]);
    if bytes.len() != 32 {
        return Err(bad());
    }
    key.copy_from_slice(&bytes);
    if kit
        .check
        .as_deref()
        .is_some_and(|c| c != crypto::kit_check(&key))
    {
        return Err(ApiErr::bad_request(
            "the recovery kit is damaged (its check value doesn't match)",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_kit_round_trip() {
        std::env::set_var("MALO_INSECURE_FAST_KDF", "1");
        let key = crypto::random_key();
        let sealed = seal("u1", "dan", &key, "long passphrase").unwrap();
        // The file shows nothing but the format and KDF settings.
        let text = serde_json::to_string(&sealed).unwrap();
        assert!(!text.contains("dan") && !text.contains(&hex::encode(key.as_ref())));
        let file = RecoveryKitFile::Sealed(sealed);
        assert_eq!(
            open(&file, Some("long passphrase")).unwrap().as_ref(),
            key.as_ref()
        );
        assert!(open(&file, Some("wrong passphrase")).is_err());
        assert!(open(&file, None).is_err());
    }

    #[test]
    fn plain_kits_are_checked() {
        let key = crypto::random_key();
        let mut kit = RecoveryKit {
            format: PLAIN_FORMAT.into(),
            user_id: "u1".into(),
            username: "dan".into(),
            created_at: Utc::now(),
            archive_key: hex::encode(key.as_ref()),
            check: None,
        };
        // Kits from older versions have no check value and still open.
        assert!(open(&RecoveryKitFile::Plain(kit.clone()), None).is_ok());
        kit.check = Some(crypto::kit_check(&key));
        assert!(open(&RecoveryKitFile::Plain(kit.clone()), None).is_ok());
        kit.archive_key.replace_range(
            0..2,
            if kit.archive_key.starts_with("00") {
                "11"
            } else {
                "00"
            },
        );
        assert!(
            open(&RecoveryKitFile::Plain(kit), None).is_err(),
            "a mistyped key is refused"
        );
    }
}
