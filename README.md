# ⚡ FastShare 10G

[![CI & Release](https://github.com/hironichu/fastshare/actions/workflows/ci-release.yml/badge.svg)](https://github.com/hironichu/fastshare/actions/workflows/ci-release.yml)
[![Latest Release](https://img.shields.io/github/v/release/hironichu/fastshare?label=Release)](https://github.com/hironichu/fastshare/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Ultra-fast, hardened Rust HTTP/1.1 & HTTP/2 direct folder sharing server engineered to saturate **10GbE fiber connections** directly from your machine—complete with **In-Browser 16x Concurrent Downloading (`🚀 Turbo 16x`)**, automatic **UPnP IGD port mapping**, **password & capability-token security**, **download/bandwidth quotas**, **TTL auto-expiration**, and a **live Ratatui terminal dashboard**.

---

## ✨ Key Features

- **🚀 In-Browser 16x Parallel Turbo Engine (`🚀 Turbo 16x`)**:
  - Saturate 10GbE links **directly inside the web browser** without requiring external CLI downloaders.
  - Automatically stripes `8 MiB` `HTTP Range` requests across wildcard DNS shards (`s1..s4.<ip>.sslip.io`, with automatic fallback to 6x same-origin streams) to bypass the browser's 6-connection-per-host limit and open **16 concurrent TCP streams**.
  - Streams directly to disk via the native File System Access API (`showSaveFilePicker`) when available, or zero-copy `Blob` assembly, complete with a real-time in-browser **Gbps / MiB/s** HUD and 16-worker activity grid.
- **⚡ 10GbE Tuned Kernel & HTTP/2 Streaming**:
  - Uses large `2 MiB` async streaming chunks (configurable via `--chunk-size-kb`), `4 MiB` kernel TCP socket send buffers (`SO_SNDBUF`), `TCP_NODELAY`, and enlarged HTTP/2 flow-control windows (`16 MiB` connection / `4 MiB` stream).
  - Full **HTTP Range (`206 Partial Content`)** support and one-click `aria2c -x 16 -s 16` command copy for CLI power users.
- **🔒 Hardened Backend Security**:
  - **Random Unprivileged Port by Default**: Picks a cryptographically random port in `10000..=60000` on startup (or specify `-p / --port <PORT>`).
  - **24-Character Capability Token + Optional Password Protection (`-P / --password`)**:
    - Constant-time HMAC-SHA256 verification.
    - Custom dark-mode glassmorphism lock screen (`HttpOnly; SameSite=Strict` session cookie) plus signed HMAC download tickets (`?key=...`) for `aria2c`/`curl`.
  - **IP & CIDR Blacklist + Automatic Brute-Force Ban**:
    - Block specific IPs or IPv4/IPv6 CIDR subnets (`--blacklist 203.0.113.5,198.51.100.0/24` or `--blacklist-file`), ban/unban IPs live in the TUI (`[b]` / `[u]`), and automatically ban IPs after `--max-auth-failures` (default `5`) failed attempts.
  - **Path Traversal & Dotfile Containment**:
    - Canonical path containment (`std::fs::canonicalize`), dotfile/hidden-file blocking by default (`--allow-hidden` to override), and strict CSP / `X-Frame-Options: DENY` / `nosniff` security headers.
- **⏱️ Download Quotas & Auto-Expiration Timer (`--ttl`)**:
  - **Expiration Timer (`-e / --ttl 30m`)**: Automatically disables the share link, shuts down the server, and removes the UPnP port mapping from your router when the countdown ends.
  - **Download Limits (`-m / --max-downloads <N>` & `--max-gb <GiB>`)**: Smartly groups parallel `Range` chunks from the same client IP + file into **1 logical download**, and automatically closes the server + UPnP port once completed.
- **📦 Zero-Temp-File Folder Archiving**:
  - Stream any folder on-the-fly as an **uncompressed `.zip`** (`Compression::Stored` for zero CPU bottleneck at 10 Gbps) or **`.tar`** directly to your friend's browser.
- **📊 Live Terminal Dashboard (TUI)**:
  - Built with `ratatui` — displays Public & LAN share URLs, UPnP status, live throughput in **Gbps & MiB/s**, a bandwidth sparkline, active connections, TTL & quota counters, and interactive IP ban controls.

---

## 🚀 Quick Start

### Option 1: Download Prebuilt Binary
Download the latest prebuilt archive for **Windows**, **Linux**, or **macOS** from the [**GitHub Releases**](https://github.com/hironichu/fastshare/releases) page.

### Option 2: Build from Source
```bash
git clone git@github.com:hironichu/fastshare.git
cd fastshare
cargo build --release
```
The optimized binary will be generated at `target/release/fastshare` (`target\release\fastshare.exe` on Windows).

---

## 💻 Usage Examples

```powershell
# 1. Share a folder on a random port with automatic UPnP + random 24-char token
fastshare "D:\SharedWithFriend"

# 2. Password-protected share that expires in 45 minutes and allows at most 3 downloads
fastshare "D:\SharedWithFriend" -P "MySecretPass" --ttl 45m --max-downloads 3

# 3. Cap total data transfer to 50 GiB and block specific IP/CIDR ranges
fastshare "D:\SharedWithFriend" --max-gb 50 --blacklist "198.51.100.0/24,203.0.113.50"

# 4. Use a specific port with manual port forwarding (disable UPnP)
fastshare "D:\SharedWithFriend" --port 28080 --no-upnp

# 5. Register 1-Click Browser Protocol Handler (`fastshare://`) on the client machine
fastshare --register-protocol

# 6. Download a file directly using the built-in 16-stream 10GbE client
fastshare --download "http://<IP>:<PORT>/<TOKEN>/large_file.iso"
```

---

## ⚙️ CLI Options

```text
Usage: fastshare [OPTIONS] [PATH]

Arguments:
  [PATH]  Directory to share (defaults to current working directory) [default: .]

Options:
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
      --chunk-size-kb <CHUNK_SIZE_KB>        Read chunk size in KiB for 10GbE streaming [default: 2048]
  -h, --help                                 Print help
  -V, --version                              Print version
```

---

## 📄 License

Licensed under the [MIT License](LICENSE).
