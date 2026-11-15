use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "fastshare",
    version,
    about = "10GbE ultra-fast & secure direct folder sharing server with UPnP, password/token auth, quotas, IP blacklist & live TUI"
)]
pub struct Args {
    /// Directory to share (defaults to current working directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Port to listen on (defaults to a random unprivileged port between 10000 and 60000)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0")]
    pub bind: String,

    /// Custom secret token in the URL (auto-generated 24-char random token if omitted)
    #[arg(short, long)]
    pub token: Option<String>,

    /// Optional password to protect the share link (enables web lock screen + HTTP Basic Auth + signed aria2c tickets)
    #[arg(short = 'P', long)]
    pub password: Option<String>,

    /// Auto-expire and close the server & UPnP port after a duration (e.g. "30m", "2h", "90s", "1d")
    #[arg(short = 'e', long = "ttl", visible_alias = "expires")]
    pub ttl: Option<String>,

    /// Maximum number of logical file/archive downloads allowed before disabling the link
    #[arg(short = 'm', long)]
    pub max_downloads: Option<u64>,

    /// Maximum total data transfer allowed in GiB (e.g. 50.0) before disabling the link
    #[arg(long)]
    pub max_gb: Option<f64>,

    /// Maximum simultaneous active transfer connections
    #[arg(long, default_value_t = 64)]
    pub max_concurrent: usize,

    /// Comma-separated or repeatable list of IPs or CIDRs to blacklist (e.g. "1.2.3.4,198.51.100.0/24")
    #[arg(long)]
    pub blacklist: Vec<String>,

    /// Path to a text file containing blacklisted IPs or CIDRs (one per line)
    #[arg(long)]
    pub blacklist_file: Option<PathBuf>,

    /// Automatically blacklist any IP after this many failed token or password attempts (0 to disable)
    #[arg(long, default_value_t = 5)]
    pub max_auth_failures: u32,

    /// Allow serving hidden files / dotfiles (blocked by default for security)
    #[arg(long)]
    pub allow_hidden: bool,

    /// Disable automatic UPnP port forwarding
    #[arg(long)]
    pub no_upnp: bool,

    /// Disable interactive TUI and print logs to stdout instead
    #[arg(long)]
    pub no_tui: bool,

    /// Read chunk size in KiB for 10GbE streaming (default: 2048 KiB = 2 MiB)
    #[arg(long, default_value_t = 2048)]
    pub chunk_size_kb: usize,
}
