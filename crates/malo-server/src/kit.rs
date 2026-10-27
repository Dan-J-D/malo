//! Recovery kit files. The kit holds the archive key; the file is sealed with a passphrase the
//! user picks when saving it (not the account password: the kit is for when that's forgotten).

use base64::Engine;
use chrono::Utc;
use malo_api::{KitKdf, RecoveryKit, RecoveryKitFile, SealedRecoveryKit, SEALED_KIT_FORMAT};
use malo_core::config::Destination;
use malo_core::crypto::{self, KdfParams, Key};
use zeroize::Zeroizing;

use crate::error::{ApiErr, ApiResult};

const PLAIN_FORMAT: &str = "malo-recovery-kit-v1";
const AAD: &[u8] = b"malo/v1/recovery-kit";
pub const MIN_PASSPHRASE: usize = 12;
/// More destinations than anyone sets up: a kit with more is not one Malo wrote.
const MAX_DESTINATIONS: usize = 64;

pub fn check_passphrase(passphrase: &str) -> ApiResult<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Err(ApiErr::bad_request(format!(
            "the kit passphrase must have at least {MIN_PASSPHRASE} characters"
        )));
    }
    Ok(())
}

/// Builds the kit of a user and seals it with `passphrase` (Argon2id; call from a blocking thread).
/// The destinations go in as [`Destination::for_recovery`] has them: credentials only for those
/// the user chose, the others come back asking for theirs.
pub fn seal(
    user_id: &str,
    username: &str,
    archive_key: &Key,
    destinations: &[Destination],
    passphrase: &str,
) -> anyhow::Result<SealedRecoveryKit> {
    let kit = RecoveryKit {
        format: PLAIN_FORMAT.into(),
        user_id: user_id.into(),
        username: username.into(),
        created_at: Utc::now(),
        archive_key: hex::encode(archive_key.as_ref()),
        check: Some(crypto::kit_check(archive_key)),
        destinations: destinations
            .iter()
            .map(|d| serde_json::to_value(d.for_recovery()))
            .collect::<Result<_, _>>()?,
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

/// What a kit file holds.
pub struct Opened {
    pub archive_key: Key,
    /// The destinations saved with the kit (none in kits from older versions). They are checked
    /// like any destination when they're used: confined `fs` roots, allowed options, private
    /// networks.
    pub destinations: Vec<Destination>,
}

/// The archive key in a kit file, checked against the kit's check value. A sealed kit needs its
/// passphrase (Argon2id; call from a blocking thread). Errors are user-facing.
pub fn open(file: &RecoveryKitFile, passphrase: Option<&str>) -> ApiResult<Opened> {
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
    if kit.destinations.len() > MAX_DESTINATIONS {
        return Err(bad());
    }
    let destinations = kit
        .destinations
        .iter()
        .map(|d| serde_json::from_value::<Destination>(d.clone()).map_err(|_| bad()))
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Opened {
        archive_key: key,
        destinations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_kit_round_trip() {
        std::env::set_var("MALO_INSECURE_FAST_KDF", "1");
        let key = crypto::random_key();
        let dest: Destination = serde_json::from_value(serde_json::json!({
            "id": "d1", "name": "nas", "scheme": "s3", "root": "/malo", "encrypt": true,
            "required_for_purge": true, "deep_check": { "mode": "full" },
            "options": { "bucket": "b", "secret_access_key": "storage-secret" },
        }))
        .unwrap();
        let mut kept = dest.clone();
        kept.recovery_secrets = true;
        let sealed = seal("u1", "dan", &key, &[dest, kept], "long passphrase").unwrap();
        // The file shows nothing but the format and KDF settings.
        let text = serde_json::to_string(&sealed).unwrap();
        assert!(!text.contains("dan") && !text.contains(&hex::encode(key.as_ref())));
        assert!(!text.contains("storage-secret") && !text.contains("nas"));
        let file = RecoveryKitFile::Sealed(sealed);
        let opened = open(&file, Some("long passphrase")).unwrap();
        assert_eq!(opened.archive_key.as_ref(), key.as_ref());
        assert_eq!(opened.destinations.len(), 2);
        // By default the kit leaves the storage secret out and says it's missing…
        assert!(!opened.destinations[0]
            .options
            .contains_key("secret_access_key"));
        assert_eq!(
            opened.destinations[0].missing_secrets,
            ["secret_access_key"]
        );
        // …unless the destination is set to keep it there.
        assert_eq!(
            opened.destinations[1].options["secret_access_key"],
            "storage-secret"
        );
        assert!(opened.destinations[1].complete());
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
            destinations: vec![],
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
