use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Constant-time byte slice comparison to prevent timing side-channel attacks.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ============================================================================
// Pure-Rust FIPS 180-4 SHA-256 & RFC 2104 HMAC-SHA256
// ============================================================================

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity((data.len() + 9).div_ceil(64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner_data = Vec::with_capacity(64 + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner_hash = sha256(&inner_data);

    let mut outer_data = Vec::with_capacity(64 + 32);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner_hash);
    sha256(&outer_data)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut buf = 0u32;
    let mut bits = 0u8;

    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

// ============================================================================
// IP / CIDR Blacklist & Brute-Force Protection
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpRule {
    Exact(IpAddr),
    V4Cidr {
        network: u32,
        mask: u32,
        prefix: u8,
    },
    V6Cidr {
        network: u128,
        mask: u128,
        prefix: u8,
    },
}

impl IpRule {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() || s.starts_with('#') {
            return None;
        }
        if let Some((ip_part, prefix_part)) = s.split_once('/') {
            let ip: IpAddr = ip_part.trim().parse().ok()?;
            let prefix: u8 = prefix_part.trim().parse().ok()?;
            match ip {
                IpAddr::V4(v4) if prefix <= 32 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        !0u32 << (32 - prefix)
                    };
                    let net = u32::from(v4) & mask;
                    Some(IpRule::V4Cidr {
                        network: net,
                        mask,
                        prefix,
                    })
                }
                IpAddr::V6(v6) if prefix <= 128 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        !0u128 << (128 - prefix)
                    };
                    let net = u128::from(v6) & mask;
                    Some(IpRule::V6Cidr {
                        network: net,
                        mask,
                        prefix,
                    })
                }
                _ => None,
            }
        } else {
            let ip: IpAddr = s.parse().ok()?;
            Some(IpRule::Exact(ip))
        }
    }

    pub fn matches(&self, addr: &IpAddr) -> bool {
        // Normalize IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to IPv4
        let normalized = match addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(*v6),
            },
            IpAddr::V4(v4) => IpAddr::V4(*v4),
        };

        match (self, normalized) {
            (IpRule::Exact(rule_ip), ip) => *rule_ip == ip,
            (IpRule::V4Cidr { network, mask, .. }, IpAddr::V4(v4)) => {
                (u32::from(v4) & *mask) == *network
            }
            (IpRule::V6Cidr { network, mask, .. }, IpAddr::V6(v6)) => {
                (u128::from(v6) & *mask) == *network
            }
            _ => false,
        }
    }

    pub fn display_str(&self) -> String {
        match self {
            IpRule::Exact(ip) => ip.to_string(),
            IpRule::V4Cidr {
                network, prefix, ..
            } => format!("{}/{}", Ipv4Addr::from(*network), prefix),
            IpRule::V6Cidr {
                network, prefix, ..
            } => format!("{}/{}", Ipv6Addr::from(*network), prefix),
        }
    }
}

pub struct SecurityConfig {
    pub password: Option<String>,
    pub max_downloads: Option<u64>,
    pub max_bytes: Option<u64>,
    pub max_concurrent: usize,
    pub ttl: Option<Duration>,
    pub max_auth_failures: u32,
    pub initial_blacklist: Vec<IpRule>,
}

pub struct SecurityManager {
    signing_secret: [u8; 32],
    password_hmac: Option<[u8; 32]>,
    pub blacklist: RwLock<HashSet<IpRule>>,
    failed_attempts: RwLock<HashMap<IpAddr, u32>>,
    pub max_auth_failures: u32,
    pub max_downloads: Option<u64>,
    pub downloads_used: AtomicU64,
    /// Tracks recent `(IpAddr, relative_file_path)` download sessions so multi-connection Range
    /// requests (like `aria2c -x 16`) for the same file only consume 1 download credit.
    recent_download_sessions: RwLock<HashMap<(IpAddr, String), Instant>>,
    pub max_bytes: Option<u64>,
    pub max_concurrent: usize,
    pub started_at: Instant,
    pub ttl: Option<Duration>,
    pub expires_unix: Option<u64>,
    pub link_disabled: AtomicBool,
    pub disable_reason: RwLock<Option<String>>,
}

impl SecurityManager {
    pub fn new(cfg: SecurityConfig) -> Self {
        let mut signing_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut signing_secret);

        let password_hmac = cfg
            .password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| hmac_sha256(&signing_secret, p.as_bytes()));

        let mut bl = HashSet::new();
        for rule in cfg.initial_blacklist {
            bl.insert(rule);
        }

        let started_at = Instant::now();
        let expires_unix = cfg.ttl.map(|d| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .saturating_add(d)
                .as_secs()
        });

        Self {
            signing_secret,
            password_hmac,
            blacklist: RwLock::new(bl),
            failed_attempts: RwLock::new(HashMap::new()),
            max_auth_failures: cfg.max_auth_failures,
            max_downloads: cfg.max_downloads,
            downloads_used: AtomicU64::new(0),
            recent_download_sessions: RwLock::new(HashMap::new()),
            max_bytes: cfg.max_bytes,
            max_concurrent: cfg.max_concurrent,
            started_at,
            ttl: cfg.ttl,
            expires_unix,
            link_disabled: AtomicBool::new(false),
            disable_reason: RwLock::new(None),
        }
    }

    pub fn requires_password(&self) -> bool {
        self.password_hmac.is_some()
    }

    /// Verify a candidate password in constant time.
    pub fn verify_password(&self, candidate: &str) -> bool {
        match &self.password_hmac {
            None => true,
            Some(expected) => {
                let candidate_hmac = hmac_sha256(&self.signing_secret, candidate.as_bytes());
                constant_time_eq(&candidate_hmac, expected)
            }
        }
    }

    /// Generate an HMAC-SHA256 token bound to client IP (for session cookies and aria2c download tickets).
    pub fn create_client_ticket(&self, client_ip: IpAddr) -> String {
        let canonical_ip = normalize_ip(client_ip);
        let msg = format!("fastshare-ticket:{}", canonical_ip);
        let sig = hmac_sha256(&self.signing_secret, msg.as_bytes());
        hex_encode(&sig[..16]) // 128-bit hex tag
    }

    /// Verify a session cookie or `?key=` download ticket in constant time.
    pub fn verify_client_ticket(&self, client_ip: IpAddr, ticket: &str) -> bool {
        let expected = self.create_client_ticket(client_ip);
        constant_time_eq(expected.as_bytes(), ticket.trim().as_bytes())
    }

    /// Check if an IP address is blacklisted.
    pub fn is_blacklisted(&self, addr: &IpAddr) -> bool {
        if let Ok(bl) = self.blacklist.read() {
            bl.iter().any(|rule| rule.matches(addr))
        } else {
            false
        }
    }

    /// Manually add an IP or CIDR rule to the blacklist.
    pub fn add_blacklist_rule(&self, rule: IpRule) -> bool {
        if let Ok(mut bl) = self.blacklist.write() {
            bl.insert(rule)
        } else {
            false
        }
    }

    /// Remove an exact IP or CIDR rule from the blacklist by its display string.
    pub fn remove_blacklist_str(&self, target: &str) -> bool {
        if let Ok(mut bl) = self.blacklist.write() {
            let found = bl
                .iter()
                .find(|r| r.display_str() == target.trim())
                .cloned();
            if let Some(r) = found {
                return bl.remove(&r);
            }
        }
        false
    }

    pub fn list_blacklist(&self) -> Vec<String> {
        if let Ok(bl) = self.blacklist.read() {
            let mut v: Vec<String> = bl.iter().map(|r| r.display_str()).collect();
            v.sort();
            v
        } else {
            Vec::new()
        }
    }

    /// Record a failed token or password attempt. Returns `true` if the IP was newly auto-blacklisted.
    pub fn record_auth_failure(&self, addr: IpAddr) -> (u32, bool) {
        let norm = normalize_ip(addr);
        // Never auto-ban localhost during local testing unless configured
        let count = {
            let mut map = self.failed_attempts.write().unwrap();
            let entry = map.entry(norm).or_insert(0);
            *entry += 1;
            *entry
        };

        if self.max_auth_failures > 0 && count >= self.max_auth_failures && !norm.is_loopback() {
            let newly_added = self.add_blacklist_rule(IpRule::Exact(norm));
            return (count, newly_added);
        }
        (count, false)
    }

    pub fn clear_auth_failures(&self, addr: IpAddr) {
        let norm = normalize_ip(addr);
        if let Ok(mut map) = self.failed_attempts.write() {
            map.remove(&norm);
        }
    }

    /// Remaining duration before the link expires (if `--ttl` was set).
    pub fn remaining_ttl(&self) -> Option<Duration> {
        self.ttl.map(|total| {
            let elapsed = self.started_at.elapsed();
            total.saturating_sub(elapsed)
        })
    }

    pub fn is_expired(&self) -> bool {
        if let Some(rem) = self.remaining_ttl() {
            if rem.is_zero() {
                self.disable_link("Link timer expired (--ttl)");
                return true;
            }
        }
        false
    }

    pub fn disable_link(&self, reason: impl Into<String>) {
        if !self.link_disabled.swap(true, Ordering::SeqCst) {
            if let Ok(mut r) = self.disable_reason.write() {
                *r = Some(reason.into());
            }
        }
    }

    pub fn is_disabled(&self) -> bool {
        let _ = self.is_expired();
        self.link_disabled.load(Ordering::Relaxed)
    }

    /// Check and reserve a download slot for `(client_ip, file_key)`.
    /// Multi-connection Range requests from the same client IP for the same file within 180s
    /// share the existing logical download slot so `aria2c -x 16` counts as 1 download.
    pub fn try_acquire_download(
        &self,
        client_ip: IpAddr,
        file_key: &str,
        total_bytes_sent: u64,
    ) -> Result<u64, String> {
        if self.is_disabled() {
            let reason = self
                .disable_reason
                .read()
                .ok()
                .and_then(|r| r.clone())
                .unwrap_or_else(|| "Share link is disabled".to_string());
            return Err(reason);
        }

        if let Some(max_b) = self.max_bytes {
            if total_bytes_sent >= max_b {
                self.disable_link("Maximum data transfer quota reached");
                return Err("Maximum data transfer quota reached".to_string());
            }
        }

        let norm_ip = normalize_ip(client_ip);
        let now = Instant::now();
        let session_window = Duration::from_secs(180);

        // Check if this (IP, file) is already part of an active/recent multi-stream download
        if let Ok(mut sessions) = self.recent_download_sessions.write() {
            sessions.retain(|_, ts| now.duration_since(*ts) < session_window);
            let key = (norm_ip, file_key.to_string());
            if let Some(last_ts) = sessions.get_mut(&key) {
                *last_ts = now;
                return Ok(self.downloads_used.load(Ordering::Relaxed));
            }

            if let Some(max_dl) = self.max_downloads {
                let current = self.downloads_used.load(Ordering::SeqCst);
                if current >= max_dl {
                    self.disable_link(format!("Download limit reached ({}/{})", current, max_dl));
                    return Err(format!(
                        "Maximum download limit reached ({}/{})",
                        current, max_dl
                    ));
                }
                let next = self.downloads_used.fetch_add(1, Ordering::SeqCst) + 1;
                sessions.insert(key, now);
                return Ok(next);
            } else {
                let next = self.downloads_used.fetch_add(1, Ordering::Relaxed) + 1;
                sessions.insert(key, now);
                return Ok(next);
            }
        }

        Ok(self.downloads_used.load(Ordering::Relaxed))
    }

    /// Check if all configured quotas have been exhausted and no transfers remain in flight.
    pub fn check_quota_exhausted(
        &self,
        active_transfers: usize,
        total_bytes_sent: u64,
    ) -> Option<String> {
        if let Some(rem) = self.remaining_ttl() {
            if rem.is_zero() {
                let msg = "Link expiration timer (--ttl) reached".to_string();
                self.disable_link(msg.clone());
                return Some(msg);
            }
        }
        if let Some(max_b) = self.max_bytes {
            if total_bytes_sent >= max_b {
                let msg = "Maximum data transfer limit (--max-gb) reached".to_string();
                self.disable_link(msg.clone());
                return Some(msg);
            }
        }
        if let Some(max_dl) = self.max_downloads {
            let used = self.downloads_used.load(Ordering::Relaxed);
            if used >= max_dl && active_transfers == 0 {
                let msg = format!("Maximum download limit ({}/{}) completed", used, max_dl);
                self.disable_link(msg.clone());
                return Some(msg);
            }
        }
        None
    }
}

pub fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Parse human-friendly duration strings like `"30m"`, `"2h"`, `"90s"`, `"1h30m"`, or plain minutes `"45"`.
pub fn parse_duration_str(input: &str) -> Result<Duration, String> {
    let s = input.trim().to_lowercase();
    if s.is_empty() {
        return Err("Empty duration string".to_string());
    }
    // If purely digits, interpret as minutes for convenience
    if let Ok(mins) = s.parse::<u64>() {
        if mins == 0 {
            return Err("Duration must be greater than 0".to_string());
        }
        return Ok(Duration::from_secs(mins * 60));
    }

    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            num_buf.push(ch);
        } else if ch.is_whitespace() {
            continue;
        } else {
            let val: u64 = num_buf
                .parse()
                .map_err(|_| format!("Invalid duration number in '{}'", input))?;
            num_buf.clear();
            let mult = match ch {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                _ => {
                    return Err(format!(
                        "Unsupported duration unit '{}' (use s, m, h, d)",
                        ch
                    ))
                }
            };
            total_secs = total_secs.saturating_add(val.saturating_mul(mult));
        }
    }

    if !num_buf.is_empty() {
        let val: u64 = num_buf
            .parse()
            .map_err(|_| format!("Invalid trailing number in '{}'", input))?;
        total_secs = total_secs.saturating_add(val * 60);
    }

    if total_secs == 0 {
        return Err("Duration must be greater than 0 seconds".to_string());
    }
    Ok(Duration::from_secs(total_secs))
}

/// Load IP/CIDR rules from CLI strings and an optional blacklist file.
pub fn load_blacklist_rules(
    inline_list: &[String],
    file_path: Option<&Path>,
) -> anyhow::Result<Vec<IpRule>> {
    let mut rules = Vec::new();
    for item in inline_list {
        for part in item.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rule = IpRule::parse(trimmed)
                .ok_or_else(|| anyhow::anyhow!("Invalid IP or CIDR in blacklist: '{}'", trimmed))?;
            rules.push(rule);
        }
    }

    if let Some(path) = file_path {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read blacklist file {:?}: {}", path, e))?;
        for (idx, line) in content.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let rule = IpRule::parse(line).ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid IP or CIDR on line {} of {:?}: '{}'",
                    idx + 1,
                    path,
                    line
                )
            })?;
            rules.push(rule);
        }
    }

    Ok(rules)
}
