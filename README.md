# FastShare

[![CI & Release](https://github.com/hironichu/fastshare/actions/workflows/ci-release.yml/badge.svg)](https://github.com/hironichu/fastshare/actions/workflows/ci-release.yml)
[![Release](https://img.shields.io/github/v/release/hironichu/fastshare?label=release)](https://github.com/hironichu/fastshare/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`fastshare` is a single-binary HTTP/1.1 and HTTP/2 directory server written in Rust for high-bandwidth direct file transfers over LAN or WAN.

## Architecture & Capabilities

- **Socket & Protocol Tuning**
  - Configures `4 MiB` kernel socket send buffers (`SO_SNDBUF`), disables Nagle's algorithm (`TCP_NODELAY`), and increases HTTP/2 flow-control windows (`16 MiB` connection / `4 MiB` stream).
  - Streams file payloads asynchronously in `2 MiB` chunks (configurable via `--chunk-size-kb`) with RFC 7233 `Range` (`206 Partial Content`) support for multi-connection segmented transfers.
- **On-the-Fly Directory Archiving**
  - Streams directories directly over the socket as uncompressed `.zip` (`Compression::Stored` to avoid CPU-bound deflate bottlenecks) or POSIX `.tar` archives without temporary disk staging.
- **NAT Traversal (UPnP IGD)**
  - Performs routing-aware LAN interface discovery (filtering out CGNAT/VPN/virtual interfaces) and binds SSDP discovery directly to the outbound LAN adapter, with unicast gateway fallback.
  - Automatically removes the UPnP port mapping on process exit, signal interruption, TTL expiration, or quota exhaustion.
- **Access Control & Security**
  - **Ephemeral Port Allocation**: Binds to a random unprivileged port in `10000..=60000` by default unless `--port` is specified.
  - **Token & HMAC Authentication**: Generates a 24-character capability token verified in constant time. When `--password` is set, enforces session authentication via IP-bound `HMAC-SHA256` cookies (`HttpOnly; SameSite=Strict`) and signed query tickets (`?key=`) for external CLI clients.
  - **IP / CIDR Filtering & Brute-Force Mitigation**: Supports static IPv4/IPv6 and CIDR blacklists (`--blacklist`, `--blacklist-file`), runtime TUI ban/unban controls, and automatic IP blacklisting after `--max-auth-failures` failed authentication attempts.
  - **Filesystem Containment**: Canonicalizes all resolved paths against the root directory, rejects non-normal path components, blocks dotfiles by default (`--allow-hidden` to override), and applies strict CSP, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff` headers.
- **Transfer Quotas & Session TTL**
  - Supports session expiration timers (`--ttl`), logical download limits (`--max-downloads`, deduplicating concurrent `Range` requests per `(client_ip, file)` session), and total byte transfer caps (`--max-gb`).
- **Client Integration (`aria2c` & Parallel Web Engine)**
  - Web interface includes a multi-stream `Range` downloader (`Parallel`), one-click `aria2c` integration (dispatching to local `aria2c` JSON-RPC on `:6800`/`:16800`, invoking the `fastshare://` URI handler, and copying the `aria2c` command to the clipboard), and a terminal telemetry interface (`ratatui`).

## Installation

### Prebuilt Binaries
Download the latest archive for Windows (`x86_64`), Linux (`x86_64`), or macOS (`arm64`) from [GitHub Releases](https://github.com/hironichu/fastshare/releases).

### Build from Source
```bash
git clone git@github.com:hironichu/fastshare.git
cd fastshare
cargo build --release --locked
```

## Usage

```bash
# Serve a directory on a random port with UPnP port mapping
fastshare /path/to/dir

# Require a password, expire after 30 minutes, and cap at 5 logical downloads
fastshare /path/to/dir -P "secret" --ttl 30m --max-downloads 5

# Cap total outbound transfer at 50 GiB and block specific subnets
fastshare /path/to/dir --max-gb 50 --blacklist "198.51.100.0/24,203.0.113.50"

# Bind to a specific port without UPnP (manual port forwarding)
fastshare /path/to/dir --port 28080 --no-upnp

# Register `fastshare://` URI handler on a client machine to launch aria2c from the browser
fastshare --register-protocol
```

## CLI Reference

```text
Usage: fastshare [OPTIONS] [PATH]

Arguments:
  [PATH]  Directory to serve (or a http:// / fastshare:// URI when running in client mode) [default: .]

Options:
  -d, --download <DOWNLOAD>                  Download a target URL via aria2c or the built-in multi-stream HTTP Range client
      --register-protocol                    Register `fastshare://` URI protocol handler for the current user
  -x, --connections <CONNECTIONS>            Number of parallel TCP connections when downloading in client mode [default: 16]
  -o, --output <OUTPUT>                      Output directory when downloading in client mode (defaults to ~/Downloads)
  -p, --port <PORT>                          Port to listen on (defaults to a random unprivileged port between 10000 and 60000)
  -b, --bind <BIND>                          Bind address [default: 0.0.0.0]
  -t, --token <TOKEN>                        Custom secret token in the URL (auto-generated 24-char random token if omitted)
  -P, --password <PASSWORD>                  Optional password to protect the share link
  -e, --ttl <TTL>                            Auto-expire and close the server & UPnP port after a duration (e.g. "30m", "2h", "90s") [aliases: expires]
  -m, --max-downloads <MAX_DOWNLOADS>        Maximum number of logical file/archive downloads allowed before disabling the link
      --max-gb <MAX_GB>                      Maximum total data transfer allowed in GiB (e.g. 50.0) before disabling the link
      --max-concurrent <MAX_CONCURRENT>      Maximum simultaneous active transfer connections [default: 64]
      --blacklist <BLACKLIST>                Comma-separated or repeatable list of IPs or CIDRs to blacklist
      --blacklist-file <BLACKLIST_FILE>      Path to a text file containing blacklisted IPs or CIDRs (one per line)
      --max-auth-failures <MAX_AUTH_FAILURES> Automatically blacklist any IP after this many failed token or password attempts [default: 5]
      --allow-hidden                         Allow serving hidden files / dotfiles (blocked by default for security)
      --no-upnp                              Disable automatic UPnP port forwarding
      --no-tui                               Disable interactive TUI and print logs to stdout instead
      --chunk-size-kb <CHUNK_SIZE_KB>        Read chunk size in KiB for streaming [default: 2048]
  -h, --help                                 Print help
  -V, --version                              Print version
```

## License

MIT — see [LICENSE](LICENSE).
