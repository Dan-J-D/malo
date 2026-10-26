//! Where the server may connect to. With the admin setting `block_private_networks`, every
//! connection to a mail server, storage endpoint or OAuth provider goes only to public addresses:
//! the addresses are checked when the name is resolved for the connection itself, so a name that
//! resolves to a public address when checked and a private one when connecting (DNS rebinding)
//! gets nowhere.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::net::TcpStream;

static BLOCK_PRIVATE: AtomicBool = AtomicBool::new(false);

/// Turns the block on or off for every connection the process makes (the server follows the
/// admin setting).
pub fn set_block_private(on: bool) {
    BLOCK_PRIVATE.store(on, Ordering::Relaxed);
}

pub fn blocking() -> bool {
    BLOCK_PRIVATE.load(Ordering::Relaxed)
}

fn private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // 0.0.0.0/8, "this network"
        || a == 0
        // 100.64.0.0/10, carrier-grade NAT
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15, benchmarking
        || (a == 198 && (18..20).contains(&b))
        // 240.0.0.0/4, reserved
        || a >= 240
}

fn private_v6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    let embedded_v4 = |hi: u16, lo: u16| Ipv4Addr::from(((hi as u32) << 16) | lo as u32);
    if let Some(v4) = v6.to_ipv4_mapped() {
        return private_v4(v4);
    }
    // NAT64 (64:ff9b::/96) reaches the IPv4 address in its last 32 bits.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return private_v4(embedded_v4(s[6], s[7]));
    }
    // 6to4 (2002::/16) reaches the IPv4 address in bits 16–47.
    if s[0] == 0x2002 {
        return private_v4(embedded_v4(s[1], s[2]));
    }
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        // IPv4-compatible ::a.b.c.d (deprecated)
        || s[..6] == [0; 6]
        // 64:ff9b:1::/48, local-use NAT64
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
        // fc00::/7, unique local
        || (s[0] & 0xfe00) == 0xfc00
        // fe80::/10, link-local
        || (s[0] & 0xffc0) == 0xfe80
        // fec0::/10, site-local (deprecated)
        || (s[0] & 0xffc0) == 0xfec0
        // 2001::/32 Teredo (an obfuscated IPv4 address) and 2001:db8::/32 documentation
        || (s[0] == 0x2001 && (s[1] == 0 || s[1] == 0xdb8))
}

/// Loopback, private, link-local, reserved and similar addresses, also inside IPv6 forms that
/// reach an IPv4 address.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => private_v4(v4),
        IpAddr::V6(v6) => private_v6(v6),
    }
}

/// The addresses of `host` the server may connect to: all of them, or with the block on only
/// public ones (an error if none is).
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    resolve_with(host, port, blocking()).await
}

/// [`resolve`] with an explicit setting.
pub async fn resolve_with(host: &str, port: u16, block: bool) -> io::Result<Vec<SocketAddr>> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if !block {
        return Ok(addrs);
    }
    let public: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| !is_private(a.ip()))
        .collect();
    match (public.is_empty(), addrs.first()) {
        (true, Some(a)) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{host} is on a private network address ({}); this server only allows public addresses",
                a.ip()
            ),
        )),
        (true, None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{host} has no addresses"),
        )),
        (false, _) => Ok(public),
    }
}

/// Connects to the first address of `host` that answers, of those [`resolve`] allows.
pub async fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in resolve(host, port).await? {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses")))
}

/// A DNS resolver for HTTP clients that applies [`resolve`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Resolver;

impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve(&host, 0).await?;
            let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

/// An HTTP client builder that resolves names through [`Resolver`] and never follows redirects
/// (a redirect could point anywhere, also at an address given as a number).
pub fn http_client() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .dns_resolver(Arc::new(Resolver))
        .redirect(reqwest::redirect::Policy::none())
}

impl reqwest013::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest013::dns::Name) -> reqwest013::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve(&host, 0).await?;
            let addrs: reqwest013::dns::Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

/// The same for storage destinations (OpenDAL's transport uses reqwest 0.13), with Malo's
/// rustls setup so it never depends on a process-wide crypto provider.
pub fn storage_http_client() -> reqwest013::ClientBuilder {
    reqwest013::Client::builder()
        .dns_resolver(Arc::new(Resolver))
        .redirect(reqwest013::redirect::Policy::none())
        .tls_backend_preconfigured(Arc::unwrap_or_clone(crate::tls::webpki_config()))
}

/// An HTTP(S) URL for credentials to be sent to: https, or http to this machine (for local test
/// servers). With the block on, addresses given as numbers must be public too, as the resolver
/// isn't asked about those.
pub fn check_credential_url(what: &str, url: &str) -> anyhow::Result<()> {
    let u = reqwest::Url::parse(url).map_err(|_| anyhow::anyhow!("{what} isn't a valid URL"))?;
    let loopback = match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => anyhow::bail!("{what} has no host"),
    };
    match u.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => anyhow::bail!("{what} must use https"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "::10.0.0.1",
            "::8.8.8.8",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "64:ff9b:1::8.8.8.8",
            "2002:a9fe:a9fe::1",
            "2002:7f00:1::",
            "2001::1",
            "2001:db8::1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700::1111",
            "100.128.0.1",
            "198.20.0.1",
            "192.0.1.1",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2001:4860::8888",
        ] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn resolving_filters_private_addresses() {
        let all = resolve_with("localhost", 993, false).await.unwrap();
        assert!(all.iter().all(|a| a.port() == 993 && a.ip().is_loopback()));
        let e = resolve_with("localhost", 993, true).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("private network"), "{e}");
        for literal in ["127.0.0.1", "[::1]", "169.254.169.254"] {
            assert!(resolve_with(literal, 80, true).await.is_err(), "{literal}");
        }
        let public = resolve_with("8.8.8.8", 53, true).await.unwrap();
        assert_eq!(public, vec!["8.8.8.8:53".parse().unwrap()]);
    }

    #[test]
    fn credential_urls() {
        for ok in [
            "https://oauth2.googleapis.com/token",
            "http://localhost:8080/default/token",
            "http://127.0.0.1/token",
            "http://[::1]:9/t",
        ] {
            assert!(check_credential_url("token URL", ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://example.com/token",
            "ftp://example.com/token",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(check_credential_url("token URL", bad).is_err(), "{bad}");
        }
    }
}
