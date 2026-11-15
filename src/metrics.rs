use crate::security::{SecurityConfig, SecurityManager};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TransferSnapshot {
    pub id: u64,
    pub client_ip: String,
    pub file_path: String,
    pub total_size: Option<u64>,
    pub bytes_sent: u64,
    pub current_bps: f64, // bytes per second
    pub started_at: Instant,
    pub is_range: bool,
}

pub struct ActiveTransfer {
    pub id: u64,
    pub client_ip: String,
    pub file_path: String,
    pub total_size: Option<u64>,
    pub bytes_sent: AtomicU64,
    pub last_tick_bytes: AtomicU64,
    pub current_bps: RwLock<f64>,
    pub started_at: Instant,
    pub is_range: bool,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub local_ip: String,
    pub public_ip: Option<String>,
    pub port: u16,
    pub upnp_status: String,
    pub token: String,
    pub shared_dir: String,
}

pub struct Metrics {
    next_id: AtomicU64,
    pub total_bytes_sent: AtomicU64,
    last_total_bytes: AtomicU64,
    pub current_total_bps: RwLock<f64>,
    pub peak_total_bps: RwLock<f64>,
    pub speed_history_mbps: RwLock<VecDeque<u64>>, // Megabits per second history for sparkline
    pub active_transfers: RwLock<HashMap<u64, Arc<ActiveTransfer>>>,
    pub logs: RwLock<VecDeque<LogEntry>>,
    pub net_info: RwLock<NetworkInfo>,
    pub last_tick: RwLock<Instant>,
    pub security: Arc<SecurityManager>,
}

impl Metrics {
    pub fn new(net_info: NetworkInfo) -> Arc<Self> {
        Self::with_security(
            net_info,
            SecurityConfig {
                password: None,
                max_downloads: None,
                max_bytes: None,
                max_concurrent: 64,
                ttl: None,
                max_auth_failures: 5,
                initial_blacklist: Vec::new(),
            },
        )
    }

    pub fn with_security(net_info: NetworkInfo, sec_cfg: SecurityConfig) -> Arc<Self> {
        let mut history = VecDeque::with_capacity(120);
        for _ in 0..120 {
            history.push_back(0);
        }
        Arc::new(Self {
            next_id: AtomicU64::new(1),
            total_bytes_sent: AtomicU64::new(0),
            last_total_bytes: AtomicU64::new(0),
            current_total_bps: RwLock::new(0.0),
            peak_total_bps: RwLock::new(0.0),
            speed_history_mbps: RwLock::new(history),
            active_transfers: RwLock::new(HashMap::new()),
            logs: RwLock::new(VecDeque::with_capacity(200)),
            net_info: RwLock::new(net_info),
            last_tick: RwLock::new(Instant::now()),
            security: Arc::new(SecurityManager::new(sec_cfg)),
        })
    }

    pub fn log(&self, msg: impl Into<String>) {
        let now = chrono::Local::now().format("%H:%M:%S").to_string();
        let entry = LogEntry {
            timestamp: now,
            message: msg.into(),
        };
        if let Ok(mut logs) = self.logs.write() {
            if logs.len() >= 200 {
                logs.pop_front();
            }
            logs.push_back(entry);
        }
    }

    pub fn update_upnp(&self, public_ip: Option<String>, status: impl Into<String>) {
        if let Ok(mut info) = self.net_info.write() {
            if public_ip.is_some() {
                info.public_ip = public_ip;
            }
            info.upnp_status = status.into();
        }
    }

    pub fn active_count(&self) -> usize {
        self.active_transfers.read().map(|m| m.len()).unwrap_or(0)
    }

    pub fn start_transfer(
        self: &Arc<Self>,
        client: Option<SocketAddr>,
        file_path: String,
        total_size: Option<u64>,
        is_range: bool,
    ) -> TransferGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let client_ip = client
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let transfer = Arc::new(ActiveTransfer {
            id,
            client_ip: client_ip.clone(),
            file_path: file_path.clone(),
            total_size,
            bytes_sent: AtomicU64::new(0),
            last_tick_bytes: AtomicU64::new(0),
            current_bps: RwLock::new(0.0),
            started_at: Instant::now(),
            is_range,
        });

        if let Ok(mut map) = self.active_transfers.write() {
            map.insert(id, transfer.clone());
        }

        self.log(format!(
            "Start [{}] -> {} {}",
            client_ip,
            file_path,
            if is_range { "(Range)" } else { "" }
        ));

        TransferGuard {
            id,
            metrics: Arc::clone(self),
            transfer,
        }
    }

    /// Called periodically (e.g. every 200ms) to compute instantaneous bandwidth
    pub fn tick(&self) {
        let now = Instant::now();
        let elapsed = {
            let mut last = self.last_tick.write().unwrap();
            let dt = now.duration_since(*last);
            if dt < Duration::from_millis(50) {
                return;
            }
            *last = now;
            dt.as_secs_f64()
        };

        let total_now = self.total_bytes_sent.load(Ordering::Relaxed);
        let total_prev = self.last_total_bytes.swap(total_now, Ordering::Relaxed);
        let delta_total = total_now.saturating_sub(total_prev);
        let total_bps = (delta_total as f64) / elapsed;

        if let Ok(mut cur) = self.current_total_bps.write() {
            *cur = total_bps;
        }
        if let Ok(mut peak) = self.peak_total_bps.write() {
            if total_bps > *peak {
                *peak = total_bps;
            }
        }
        if let Ok(mut hist) = self.speed_history_mbps.write() {
            if hist.len() >= 120 {
                hist.pop_front();
            }
            let mbps = ((total_bps * 8.0) / 1_000_000.0).round() as u64;
            hist.push_back(mbps);
        }

        if let Ok(map) = self.active_transfers.read() {
            for t in map.values() {
                let b_now = t.bytes_sent.load(Ordering::Relaxed);
                let b_prev = t.last_tick_bytes.swap(b_now, Ordering::Relaxed);
                let db = b_now.saturating_sub(b_prev);
                if let Ok(mut bps) = t.current_bps.write() {
                    *bps = (db as f64) / elapsed;
                }
            }
        }
    }

    pub fn snapshot_transfers(&self) -> Vec<TransferSnapshot> {
        let mut list = Vec::new();
        if let Ok(map) = self.active_transfers.read() {
            for t in map.values() {
                let bps = t.current_bps.read().map(|v| *v).unwrap_or(0.0);
                list.push(TransferSnapshot {
                    id: t.id,
                    client_ip: t.client_ip.clone(),
                    file_path: t.file_path.clone(),
                    total_size: t.total_size,
                    bytes_sent: t.bytes_sent.load(Ordering::Relaxed),
                    current_bps: bps,
                    started_at: t.started_at,
                    is_range: t.is_range,
                });
            }
        }
        list.sort_by_key(|t| t.id);
        list
    }
}

pub struct TransferGuard {
    id: u64,
    metrics: Arc<Metrics>,
    transfer: Arc<ActiveTransfer>,
}

impl TransferGuard {
    #[inline]
    pub fn record_bytes(&self, n: usize) {
        let n64 = n as u64;
        self.transfer.bytes_sent.fetch_add(n64, Ordering::Relaxed);
        self.metrics
            .total_bytes_sent
            .fetch_add(n64, Ordering::Relaxed);
    }
}

impl Drop for TransferGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.metrics.active_transfers.write() {
            map.remove(&self.id);
        }
        let sent = self.transfer.bytes_sent.load(Ordering::Relaxed);
        let dur = self.transfer.started_at.elapsed().as_secs_f64().max(0.001);
        let avg_mb_s = (sent as f64 / 1_048_576.0) / dur;
        self.metrics.log(format!(
            "Done  [{}] {} ({} in {:.1}s @ {:.1} MiB/s)",
            self.transfer.client_ip,
            self.transfer.file_path,
            format_bytes(sent),
            dur,
            avg_mb_s
        ));
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;
    let b = bytes as f64;
    if b >= TB {
        format!("{:.2} TiB", b / TB)
    } else if b >= GB {
        format!("{:.2} GiB", b / GB)
    } else if b >= MB {
        format!("{:.2} MiB", b / MB)
    } else if b >= KB {
        format!("{:.1} KiB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

pub fn format_speed_bps(bytes_per_sec: f64) -> String {
    let bits_per_sec = bytes_per_sec * 8.0;
    let gbps = bits_per_sec / 1_000_000_000.0;
    let mbps = bits_per_sec / 1_000_000.0;
    let mib_s = bytes_per_sec / 1_048_576.0;

    if gbps >= 1.0 {
        format!("{:.2} Gbps ({:.0} MiB/s)", gbps, mib_s)
    } else {
        format!("{:.1} Mbps ({:.1} MiB/s)", mbps, mib_s)
    }
}

pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let rem_secs = secs % 60;
    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, mins, rem_secs)
    } else {
        format!("{:02}:{:02}", mins, rem_secs)
    }
}
