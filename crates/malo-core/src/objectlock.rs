//! Object Lock (S3) and File Lock (B2): message objects are locked against deletion and
//! overwriting for a number of days after they are written, and integrity checks extend the lock
//! of objects that are still in the backup.
//!
//! OpenDAL doesn't set retention, so these few calls are made directly: S3 with its own SigV4
//! signature, B2 through its native API. Both use the destination's own credentials only, and go
//! through [`crate::netguard`] like every other storage request.

use anyhow::{anyhow, bail, Context};
use chrono::{DateTime, SecondsFormat, Utc};
use malo_api::{LockMode, ObjectLock};
use sha2::{Digest, Sha256};

use crate::config::Destination;

/// Locks objects on one destination.
pub enum Locker {
    S3(S3Lock),
    B2(B2Lock),
}

/// The retention an object has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    pub mode: String,
    pub until: Option<DateTime<Utc>>,
}

impl Locker {
    /// The locker for a destination with Object Lock set (`None` without).
    pub fn for_destination(dest: &Destination) -> anyhow::Result<Option<Locker>> {
        let Some(lock) = dest.features.object_lock.clone() else {
            return Ok(None);
        };
        Ok(Some(match dest.scheme.to_ascii_lowercase().as_str() {
            "s3" => Locker::S3(S3Lock::new(dest, lock)?),
            "b2" => Locker::B2(B2Lock::new(dest, lock)?),
            other => bail!("Object Lock isn't available for {other} destinations"),
        }))
    }

    pub fn settings(&self) -> &ObjectLock {
        match self {
            Locker::S3(s) => &s.lock,
            Locker::B2(b) => &b.lock,
        }
    }

    /// Until when a lock set now holds.
    pub fn until_from_now(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::days(self.settings().days as i64)
    }

    /// Checks that the bucket has Object Lock (File Lock) turned on. Returns a description of
    /// its settings.
    pub async fn check_bucket(&self) -> anyhow::Result<String> {
        match self {
            Locker::S3(s) => s.check_bucket().await,
            Locker::B2(b) => b.check_bucket().await,
        }
    }

    /// Locks `path` (as Malo names it, below the operator root) until `until`. Extending a lock
    /// is always allowed; shortening one is refused by the storage.
    pub async fn lock(&self, path: &str, until: DateTime<Utc>) -> anyhow::Result<()> {
        match self {
            Locker::S3(s) => s.put_retention(path, until).await,
            Locker::B2(b) => b.update_retention(path, until).await,
        }
        .with_context(|| format!("locking {path}"))
    }

    /// The retention `path` has now.
    pub async fn retention(&self, path: &str) -> anyhow::Result<Option<Retention>> {
        match self {
            Locker::S3(s) => s.get_retention(path).await,
            Locker::B2(b) => b.get_retention(path).await,
        }
    }
}

fn option<'a>(dest: &'a Destination, keys: &[&str]) -> Option<&'a str> {
    dest.options
        .iter()
        .find(|(k, v)| keys.contains(&k.to_ascii_lowercase().as_str()) && !v.trim().is_empty())
        .map(|(_, v)| v.trim())
}

/// The object key of `path`: below the operator's `root` option, as OpenDAL places it.
fn object_key(root: Option<&str>, path: &str) -> String {
    let root = root.unwrap_or("").trim_matches('/');
    if root.is_empty() {
        path.trim_start_matches('/').to_string()
    } else {
        format!("{root}/{}", path.trim_start_matches('/'))
    }
}

fn http() -> anyhow::Result<reqwest::Client> {
    crate::netguard::http_client()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("http client")
}

/// The text of the first `<tag>…</tag>` in an XML document (S3 answers are small and flat).
fn xml_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim())
}

fn mode_name(mode: LockMode) -> &'static str {
    match mode {
        LockMode::Governance => "GOVERNANCE",
        LockMode::Compliance => "COMPLIANCE",
    }
}

// ───────────────────────────── S3 ─────────────────────────────

pub struct S3Lock {
    lock: ObjectLock,
    endpoint: url::Url,
    bucket: String,
    region: String,
    virtual_host: bool,
    root: Option<String>,
    access_key: String,
    secret_key: zeroize::Zeroizing<String>,
    session_token: Option<String>,
}

/// S3's URI encoding: everything but unreserved characters, and `/` unless it's a query value.
fn s3_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

impl S3Lock {
    fn new(dest: &Destination, lock: ObjectLock) -> anyhow::Result<S3Lock> {
        let bucket = option(
            dest,
            &["bucket", "aws_bucket", "aws_bucket_name", "bucket_name"],
        )
        .ok_or_else(|| anyhow!("Object Lock needs the bucket name"))?
        .to_string();
        let region = option(dest, &["region", "aws_region"])
            .unwrap_or("us-east-1")
            .to_string();
        let endpoint = option(
            dest,
            &[
                "endpoint",
                "aws_endpoint",
                "aws_endpoint_url",
                "endpoint_url",
            ],
        )
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://s3.{region}.amazonaws.com"));
        let endpoint = if endpoint.contains("://") {
            endpoint
        } else {
            format!("https://{endpoint}")
        };
        crate::netguard::check_url_literal("the S3 endpoint", &endpoint)?;
        let endpoint = url::Url::parse(endpoint.trim_end_matches('/'))
            .context("the S3 endpoint isn't a valid URL")?;
        let access_key = option(dest, &["access_key_id", "aws_access_key_id"])
            .ok_or_else(|| anyhow!("Object Lock needs an access key (not an anonymous bucket)"))?
            .to_string();
        let secret_key = option(dest, &["secret_access_key", "aws_secret_access_key"])
            .ok_or_else(|| anyhow!("Object Lock needs a secret access key"))?
            .to_string();
        let virtual_host = option(
            dest,
            &[
                "enable_virtual_host_style",
                "aws_virtual_hosted_style_request",
                "virtual_hosted_style_request",
            ],
        )
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        Ok(S3Lock {
            lock,
            endpoint,
            bucket,
            region,
            virtual_host,
            root: option(dest, &["root"]).map(str::to_string),
            access_key,
            secret_key: zeroize::Zeroizing::new(secret_key),
            session_token: option(
                dest,
                &["session_token", "aws_session_token", "aws_token", "token"],
            )
            .map(str::to_string),
        })
    }

    /// URL of the bucket or of an object key in it, path-style or virtual-hosted.
    fn url(&self, key: Option<&str>, query: &str) -> anyhow::Result<url::Url> {
        let mut base = self.endpoint.clone();
        let mut path = base.path().trim_end_matches('/').to_string();
        if self.virtual_host {
            let host = base
                .host_str()
                .ok_or_else(|| anyhow!("the S3 endpoint has no host"))?;
            base.set_host(Some(&format!("{}.{host}", self.bucket)))
                .context("bucket host name")?;
        } else {
            path.push('/');
            path.push_str(&s3_encode(&self.bucket, false));
        }
        if let Some(k) = key {
            path.push('/');
            path.push_str(&s3_encode(k, true));
        } else if self.virtual_host {
            path.push('/');
        }
        let url = format!(
            "{}://{}{}{}?{query}",
            base.scheme(),
            base.host_str().unwrap_or_default(),
            base.port().map(|p| format!(":{p}")).unwrap_or_default(),
            path
        );
        url::Url::parse(&url).context("S3 request URL")
    }

    /// Sends a SigV4-signed request (`query` is a single parameter without a value, e.g.
    /// `retention`).
    async fn send(
        &self,
        method: reqwest::Method,
        key: Option<&str>,
        query: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(reqwest::StatusCode, String)> {
        let url = self.url(key, query)?;
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let day = now.format("%Y%m%d").to_string();
        let payload_hash = hex::encode(Sha256::digest(&body));
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host),
            ("x-amz-content-sha256".into(), payload_hash.clone()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        if !body.is_empty() {
            use base64::Engine;
            let md5 = md5::Md5::digest(&body);
            headers.push((
                "content-md5".into(),
                base64::engine::general_purpose::STANDARD.encode(md5),
            ));
        }
        if let Some(t) = &self.session_token {
            headers.push(("x-amz-security-token".into(), t.clone()));
        }
        headers.sort();
        let signed: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        let signed = signed.join(";");
        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let canonical = format!(
            "{}\n{}\n{}=\n{canonical_headers}\n{signed}\n{payload_hash}",
            method.as_str(),
            url.path(),
            s3_encode(query, false),
        );
        let scope = format!("{day}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let k = hmac(format!("AWS4{}", &*self.secret_key).as_bytes(), &day);
        let k = hmac(&k, &self.region);
        let k = hmac(&k, "s3");
        let k = hmac(&k, "aws4_request");
        let signature = hex::encode(hmac(&k, &to_sign));
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
            self.access_key
        );
        let mut req = http()?.request(method, url).header("authorization", auth);
        for (k, v) in &headers {
            if k != "host" {
                req = req.header(k.as_str(), v.as_str());
            }
        }
        let resp = req.body(body).send().await.context("S3 request")?;
        let status = resp.status();
        // Answers are short XML documents; never read more than a little of one.
        let bytes = resp.bytes().await.unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]).into_owned();
        Ok((status, text))
    }

    fn error(status: reqwest::StatusCode, body: &str) -> anyhow::Error {
        let code = xml_value(body, "Code").unwrap_or("");
        let msg = xml_value(body, "Message").unwrap_or("");
        anyhow!("S3 answered {status}: {code} {msg}")
    }

    async fn check_bucket(&self) -> anyhow::Result<String> {
        let (status, body) = self
            .send(reqwest::Method::GET, None, "object-lock", vec![])
            .await?;
        if status == reqwest::StatusCode::NOT_FOUND
            || xml_value(&body, "Code") == Some("ObjectLockConfigurationNotFoundError")
        {
            bail!("the bucket doesn't have Object Lock turned on: create a new bucket with Object Lock enabled")
        }
        if !status.is_success() {
            return Err(Self::error(status, &body));
        }
        if xml_value(&body, "ObjectLockEnabled") != Some("Enabled") {
            bail!("the bucket doesn't have Object Lock turned on")
        }
        let default = match (
            xml_value(&body, "Mode"),
            xml_value(&body, "Days").or(xml_value(&body, "Years")),
        ) {
            (Some(m), Some(n)) => format!(
                "; bucket default: {} for {n} {}",
                m.to_lowercase(),
                if xml_value(&body, "Days").is_some() {
                    "days"
                } else {
                    "years"
                }
            ),
            _ => String::new(),
        };
        Ok(format!("Object Lock is on{default}"))
    }

    async fn put_retention(&self, path: &str, until: DateTime<Utc>) -> anyhow::Result<()> {
        let key = object_key(self.root.as_deref(), path);
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>{}</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>"#,
            mode_name(self.lock.mode),
            until.to_rfc3339_opts(SecondsFormat::Secs, true)
        );
        let (status, text) = self
            .send(
                reqwest::Method::PUT,
                Some(&key),
                "retention",
                body.into_bytes(),
            )
            .await?;
        if !status.is_success() {
            return Err(Self::error(status, &text));
        }
        Ok(())
    }

    async fn get_retention(&self, path: &str) -> anyhow::Result<Option<Retention>> {
        let key = object_key(self.root.as_deref(), path);
        let (status, text) = self
            .send(reqwest::Method::GET, Some(&key), "retention", vec![])
            .await?;
        if xml_value(&text, "Code") == Some("NoSuchObjectLockConfiguration") {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Self::error(status, &text));
        }
        Ok(xml_value(&text, "Mode").map(|m| Retention {
            mode: m.to_lowercase(),
            until: xml_value(&text, "RetainUntilDate")
                .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
                .map(|d| d.with_timezone(&Utc)),
        }))
    }
}

// ───────────────────────────── B2 ─────────────────────────────

pub struct B2Lock {
    lock: ObjectLock,
    key_id: String,
    key: zeroize::Zeroizing<String>,
    bucket: String,
    bucket_id: String,
    root: Option<String>,
    auth: tokio::sync::OnceCell<B2Auth>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct B2Auth {
    account_id: String,
    authorization_token: String,
    api_url: String,
}

impl B2Lock {
    fn new(dest: &Destination, lock: ObjectLock) -> anyhow::Result<B2Lock> {
        let get = |k: &str, what: &str| {
            option(dest, &[k])
                .map(str::to_string)
                .ok_or_else(|| anyhow!("Object Lock needs the {what}"))
        };
        Ok(B2Lock {
            lock,
            key_id: get("application_key_id", "application key ID")?,
            key: zeroize::Zeroizing::new(get("application_key", "application key")?),
            bucket: get("bucket", "bucket name")?,
            bucket_id: get("bucket_id", "bucket ID")?,
            root: option(dest, &["root"]).map(str::to_string),
            auth: Default::default(),
        })
    }

    async fn auth(&self) -> anyhow::Result<&B2Auth> {
        self.auth
            .get_or_try_init(|| async {
                let resp = http()?
                    .get("https://api.backblazeb2.com/b2api/v2/b2_authorize_account")
                    .basic_auth(&self.key_id, Some(&*self.key))
                    .send()
                    .await
                    .context("B2 sign-in")?;
                if !resp.status().is_success() {
                    bail!("B2 sign-in failed: {}", resp.status());
                }
                let auth: B2Auth = resp.json().await.context("B2 sign-in answer")?;
                crate::netguard::check_credential_url("the B2 API address", &auth.api_url)?;
                Ok(auth)
            })
            .await
    }

    async fn call(&self, op: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let auth = self.auth().await?;
        let resp = http()?
            .post(format!("{}/b2api/v2/{op}", auth.api_url))
            .header("authorization", &auth.authorization_token)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("B2 {op}"))?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            bail!(
                "B2 {op} failed ({status}): {} {}",
                v["code"].as_str().unwrap_or(""),
                v["message"].as_str().unwrap_or("")
            );
        }
        Ok(v)
    }

    async fn check_bucket(&self) -> anyhow::Result<String> {
        let auth = self.auth().await?;
        let v = self
            .call(
                "b2_list_buckets",
                serde_json::json!({"accountId": auth.account_id, "bucketId": self.bucket_id}),
            )
            .await?;
        let bucket = v["buckets"]
            .as_array()
            .and_then(|b| b.first())
            .ok_or_else(|| anyhow!("bucket {} not found", self.bucket))?;
        let cfg = &bucket["fileLockConfiguration"];
        if cfg["isClientAuthorizedToRead"] == false {
            bail!("the application key may not read the bucket's File Lock settings (it needs the readBucketRetentions capability)");
        }
        if cfg["value"]["isFileLockEnabled"] != true {
            bail!("the bucket doesn't have File Lock turned on: create a new bucket with File Lock enabled");
        }
        let d = &cfg["value"]["defaultRetention"];
        Ok(
            match (d["mode"].as_str(), d["period"]["duration"].as_u64()) {
                (Some(m), Some(n)) => format!(
                    "File Lock is on; bucket default: {m} for {n} {}",
                    d["period"]["unit"].as_str().unwrap_or("days")
                ),
                _ => "File Lock is on".into(),
            },
        )
    }

    /// Id of the newest version of a file.
    async fn file_id(&self, name: &str) -> anyhow::Result<String> {
        let v = self
            .call(
                "b2_list_file_names",
                serde_json::json!({"bucketId": self.bucket_id, "startFileName": name, "maxFileCount": 1}),
            )
            .await?;
        v["files"]
            .as_array()
            .and_then(|f| f.first())
            .filter(|f| f["fileName"] == name)
            .and_then(|f| f["fileId"].as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("{name} not found"))
    }

    async fn update_retention(&self, path: &str, until: DateTime<Utc>) -> anyhow::Result<()> {
        let name = object_key(self.root.as_deref(), path);
        let id = self.file_id(&name).await?;
        self.call(
            "b2_update_file_retention",
            serde_json::json!({
                "fileName": name,
                "fileId": id,
                "fileRetention": {
                    "mode": mode_name(self.lock.mode).to_lowercase(),
                    "retainUntilTimestamp": until.timestamp_millis(),
                },
            }),
        )
        .await?;
        Ok(())
    }

    async fn get_retention(&self, path: &str) -> anyhow::Result<Option<Retention>> {
        let name = object_key(self.root.as_deref(), path);
        let id = self.file_id(&name).await?;
        let v = self
            .call("b2_get_file_info", serde_json::json!({"fileId": id}))
            .await?;
        let r = &v["fileRetention"]["value"];
        Ok(r["mode"].as_str().map(|m| Retention {
            mode: m.to_string(),
            until: r["retainUntilTimestamp"]
                .as_i64()
                .and_then(DateTime::from_timestamp_millis),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3(opts: &[(&str, &str)]) -> S3Lock {
        let dest = Destination {
            options: opts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            scheme: "s3".into(),
            features: malo_api::DestinationFeatures {
                object_lock: Some(ObjectLock {
                    mode: LockMode::Governance,
                    days: 30,
                }),
                ..Default::default()
            },
            ..crate::store::tests::dest(true)
        };
        match Locker::for_destination(&dest).unwrap().unwrap() {
            Locker::S3(s) => s,
            _ => unreachable!(),
        }
    }

    #[test]
    fn s3_urls() {
        let base = [
            ("bucket", "b"),
            ("access_key_id", "a"),
            ("secret_access_key", "s"),
        ];
        let l = s3(&base);
        assert_eq!(
            l.url(Some("malo/x y+z.enc"), "retention").unwrap().as_str(),
            "https://s3.us-east-1.amazonaws.com/b/malo/x%20y%2Bz.enc?retention"
        );
        let mut opts = base.to_vec();
        opts.push(("endpoint", "http://127.0.0.1:9000"));
        let l = s3(&opts);
        assert_eq!(
            l.url(None, "object-lock").unwrap().as_str(),
            "http://127.0.0.1:9000/b?object-lock"
        );
        opts.push(("enable_virtual_host_style", "true"));
        opts[3] = ("endpoint", "https://s3.example.com");
        let l = s3(&opts);
        assert_eq!(
            l.url(Some("k"), "retention").unwrap().as_str(),
            "https://b.s3.example.com/k?retention"
        );
        assert_eq!(object_key(Some("/root/"), "a/b"), "root/a/b");
        assert_eq!(object_key(None, "/a/b"), "a/b");
    }

    /// The signing key derivation and signature from AWS's documentation example
    /// (GET Object, examplebucket, 20130524).
    #[test]
    fn sigv4_reference_signature() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let canonical = "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let k = hmac(format!("AWS4{secret}").as_bytes(), "20130524");
        let k = hmac(&k, "us-east-1");
        let k = hmac(&k, "s3");
        let k = hmac(&k, "aws4_request");
        assert_eq!(
            hex::encode(hmac(&k, &to_sign)),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn needs_credentials_and_supported_scheme() {
        let dest = |scheme: &str, opts: &[(&str, &str)]| Destination {
            scheme: scheme.into(),
            options: opts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            features: malo_api::DestinationFeatures {
                object_lock: Some(ObjectLock {
                    mode: LockMode::Compliance,
                    days: 1,
                }),
                ..Default::default()
            },
            ..crate::store::tests::dest(true)
        };
        assert!(Locker::for_destination(&dest(
            "s3",
            &[("bucket", "b"), ("allow_anonymous", "true")]
        ))
        .is_err());
        assert!(Locker::for_destination(&dest("gcs", &[("bucket", "b")])).is_err());
        assert!(
            Locker::for_destination(&dest(
                "b2",
                &[
                    ("bucket", "b"),
                    ("application_key_id", "i"),
                    ("application_key", "k")
                ]
            ))
            .is_err(),
            "no bucket id"
        );
        assert!(Locker::for_destination(&dest(
            "b2",
            &[
                ("bucket", "b"),
                ("bucket_id", "x"),
                ("application_key_id", "i"),
                ("application_key", "k")
            ]
        ))
        .unwrap()
        .is_some());
        assert!(Locker::for_destination(&crate::store::tests::dest(true))
            .unwrap()
            .is_none());
    }

    #[test]
    fn xml_values() {
        let x = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>3</Days></DefaultRetention></Rule></ObjectLockConfiguration>";
        assert_eq!(xml_value(x, "ObjectLockEnabled"), Some("Enabled"));
        assert_eq!(xml_value(x, "Days"), Some("3"));
        assert_eq!(xml_value(x, "Years"), None);
    }
}
