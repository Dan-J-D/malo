//! With the admin setting `block_private_networks`, mail servers and storage endpoints must be on
//! public addresses: users can't make the server connect to (and report on) its own network.

use std::net::{IpAddr, Ipv4Addr};

use malo_core::config::{Account, Destination};

use crate::error::{ApiErr, ApiResult};
use crate::state::AppState;

fn private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        // 100.64.0.0/10, carrier-grade NAT
        || (a == 100 && (64..128).contains(&b))
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => private_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return private_v4(v4);
            }
            let s0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (s0 & 0xfe00) == 0xfc00
                || (s0 & 0xffc0) == 0xfe80
        }
    }
}

fn blocking(state: &AppState) -> bool {
    state
        .db
        .admin_settings()
        .map(|s| s.block_private_networks)
        .unwrap_or(false)
}

/// Every address `host` resolves to must be public.
async fn check_host(host: &str, port: u16) -> ApiResult<()> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ApiErr::bad_request(format!("can't resolve {host}: {e}")))?;
    for a in addrs {
        if is_private(a.ip()) {
            return Err(ApiErr::forbidden(format!(
                "{host} is on a private network address ({}); this server only allows public addresses",
                a.ip()
            )));
        }
    }
    Ok(())
}

pub async fn check_account(state: &AppState, a: &Account) -> ApiResult<()> {
    if !blocking(state) {
        return Ok(());
    }
    check_host(&a.host, a.port).await
}

/// Endpoint-like options of a destination (`endpoint`, `*_endpoint`, URLs).
pub async fn check_destination(state: &AppState, d: &Destination) -> ApiResult<()> {
    if !blocking(state) || d.scheme.eq_ignore_ascii_case("fs") {
        return Ok(());
    }
    for (k, v) in &d.options {
        let v = v.trim();
        if !k.to_ascii_lowercase().contains("endpoint") || v.is_empty() {
            continue;
        }
        let with_scheme = if v.contains("://") {
            v.to_string()
        } else {
            format!("https://{v}")
        };
        let url = url::Url::parse(&with_scheme)
            .map_err(|_| ApiErr::bad_request(format!("option '{k}' isn't a valid URL")))?;
        let host = url
            .host_str()
            .ok_or_else(|| ApiErr::bad_request(format!("option '{k}' has no host")))?;
        check_host(host, url.port_or_known_default().unwrap_or(443)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_private;

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
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "100.128.0.1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }
}
