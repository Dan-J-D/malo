# Running the server

[← Back to the README](../README.md)

```sh
docker compose up -d malo
docker compose logs malo | grep -E "setup token|certificate SHA-256"
```

On first start the server does two things:

- It creates its own **certificate authority** in `/data/tls` and logs its **SHA-256 fingerprint**. The desktop app shows this fingerprint when you first connect. Compare the two before you trust the server; the app then pins it. The authority issues the server's certificate: valid for 397 days, for the names in `MALO_TLS_HOSTNAMES`, and renewed automatically while the server runs, without changing the pin. It may only vouch for those names (name constraints), so a phone that trusts it can't be fooled about other sites. Servers that used the earlier self-signed certificate switch over on first start, and the desktop app asks once to confirm the new fingerprint.
- It logs a one-time **setup token**. Use it in the app to create the first administrator. After that, administrators invite users, or turn on self-registration.

## Configuration

The server is configured with environment variables. They can also go in a TOML file named by `MALO_CONFIG`, using the same names in lowercase without the `MALO_` prefix.

| Variable | Default | Meaning |
|---|---|---|
| `MALO_LISTEN` | `0.0.0.0:8443` | Address the server listens on |
| `MALO_DATA_DIR` | `/data` | Where `server.db`, the per-user vaults, indexes and spool, and fs destinations live |
| `MALO_TLS_CERT`, `MALO_TLS_KEY` | – | PEM files to use your own certificate instead of Malo's authority |
| `MALO_TLS_HOSTNAMES` | – | Names and addresses mail apps and browsers use for this server (e.g. `10.0.0.1,backup.lan`), comma-separated; the certificate covers them and `localhost`. A name the authority doesn't cover yet creates a new authority, to be installed again |
| `MALO_TLS=off` | on | Serve plain HTTP. Only do this behind a TLS-terminating reverse proxy |
| `MALO_MAX_AUTO_LOCK_HOURS` | `24` | Upper limit on any user's auto-lock |
| `MALO_ALLOWED_FS_MOUNTS` | – | Absolute paths, colon-separated, that `fs` destinations may use besides the user's own directory |
| `MALO_WORKERS` | `4` | Number of jobs that can run at once across all users |
| `MALO_IMAP_LISTEN` | off | Address of the IMAP service for mail apps, e.g. `0.0.0.0:1993` (implicit TLS). See [Mail apps](mail-apps.md) |
| `MALO_SMTP_LISTEN` | off | Address of the SMTP submission service for mail apps, e.g. `0.0.0.0:1465` (implicit TLS) |
| `MALO_MAIL_TRACE` | off | `1` logs every IMAP command (passwords hidden), Malo's replies and how long each took, to find where a mail app gets stuck. Commands slower than 10 s are logged anyway |
| `MALO_TRUSTED_PROXIES` | none | Addresses or CIDR ranges of your reverse proxies, comma separated (`127.0.0.1, 10.0.0.0/8`). Only requests from these take the client address (for rate limits and login backoff) from `MALO_PROXY_HEADER`; everyone else is counted by their own address, whatever headers they send |
| `MALO_PROXY_HEADER` | `x-forwarded-for` | The header your proxy sets: `x-forwarded-for` (the right-most address that isn't a trusted proxy counts) or a single-address header such as `x-real-ip` |
| `MALO_TRUST_PROXY_HEADERS` | off | Deprecated: trusts proxies on loopback and private networks. Set `MALO_TRUSTED_PROXIES` instead |

Administrators set the remaining options in the app (*Admin*): self-registration, the default and per-user account limits, the maximum auto-lock, extra `fs` mounts, and **Block private networks**. That last one refuses mail servers, storage endpoints and OAuth token URLs on loopback, private, link-local and other reserved addresses (also in their IPv6 forms such as NAT64 and 6to4). It is checked when an account or destination is saved or tested, and again on every connection, at the address actually connected to, so a name that later resolves somewhere else (DNS rebinding) gets nowhere; storage requests don't follow redirects. **It's off by default** because a LAN mail server or MinIO is a common setup: **turn it on for any server that users you don't fully trust share**, or they can make it connect to hosts on its own network, cloud metadata services included. Independently of the setting, a destination only ever uses the credentials entered for it: never the server's environment, config files or cloud identity (EC2 instance role, GCE service account, Azure managed identity), and only the options its storage service needs are accepted. The *Admin* page also lists open invites (which can be revoked) and a log of administrative actions: user changes and deletions, invites, settings, password resets with a kit, and settings restored by a rebuild.

Behind a reverse proxy with a public certificate, the app detects that the certificate is publicly trusted and doesn't pin it.

## Hardening

The server keeps unlocked keys in RAM, so it takes these steps:

- It disables core dumps (`RLIMIT_CORE=0`) and ptrace attachment (`PR_SET_DUMPABLE=0`).
- It `mlock`s its key material.
- It runs as a non-root user in a read-only, distroless container.

**Run the container without swap** (`mem_swappiness: 0` is set in the compose file). On a dedicated host, consider disabling swap or using encrypted swap. The image has a `HEALTHCHECK` (`malo-server --healthcheck`), and `/healthz` reports only how many users are sealed and how many are unlocked.
