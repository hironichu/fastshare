use anyhow::{Context, Result};
use clap::Parser;
use fastshare::cli::Args;
use fastshare::metrics::{format_duration, Metrics, NetworkInfo};
use fastshare::net::{detect_local_ip, setup_upnp_and_public_ip};
use fastshare::security::{load_blacklist_rules, parse_duration_str, SecurityConfig};
use fastshare::server::{build_router, AppState};
use fastshare::tui::run_tui;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use rand::distributions::Alphanumeric;
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower::Service;

fn generate_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// Create a TCP listener tuned for 10GbE throughput (large kernel send buffer + TCP_NODELAY)
fn create_10g_listener(addr: SocketAddr) -> Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024); // 4 MiB socket send buffer
    let _ = socket.set_nodelay(true);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}

/// Bind to either a user-specified port or a cryptographically randomized high port in `10000..=60000`
fn bind_10g_listener(bind_ip: &str, requested_port: Option<u16>) -> Result<(TcpListener, SocketAddr)> {
    match requested_port {
        Some(port) if port > 0 => {
            let addr: SocketAddr = format!("{}:{}", bind_ip, port)
                .parse()
                .with_context(|| format!("Invalid bind address {}:{}", bind_ip, port))?;
            let listener = create_10g_listener(addr)
                .with_context(|| format!("Failed to bind TCP port {}", addr))?;
            let actual = listener.local_addr()?;
            Ok((listener, actual))
        }
        _ => {
            let mut rng = rand::thread_rng();
            let mut last_err = None;
            for _ in 0..32 {
                let random_port: u16 = rng.gen_range(10000..=60000);
                let addr: SocketAddr = format!("{}:{}", bind_ip, random_port)
                    .parse()
                    .with_context(|| format!("Invalid bind address {}:{}", bind_ip, random_port))?;
                match create_10g_listener(addr) {
                    Ok(listener) => {
                        let actual = listener.local_addr()?;
                        return Ok((listener, actual));
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Failed to bind random port")))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.register_protocol {
        return fastshare::client::register_protocol_handler();
    }

    if let Some(dl_url) = &args.download {
        return fastshare::client::run_parallel_download(
            dl_url,
            args.connections,
            args.output.as_deref(),
        )
        .await;
    }

    if args.path.starts_with("http://") || args.path.starts_with("fastshare://") {
        return fastshare::client::run_parallel_download(
            &args.path,
            args.connections,
            args.output.as_deref(),
        )
        .await;
    }

    let root_dir = std::fs::canonicalize(&args.path)
        .with_context(|| format!("Failed to resolve directory: {:?}", args.path))?;
    if !root_dir.is_dir() {
        anyhow::bail!("Path {:?} is not a directory", root_dir);
    }

    let ttl = match &args.ttl {
        Some(s) => Some(
            parse_duration_str(s)
                .map_err(|e| anyhow::anyhow!("Invalid --ttl '{}': {}", s, e))?,
        ),
        None => None,
    };

    let initial_blacklist =
        load_blacklist_rules(&args.blacklist, args.blacklist_file.as_deref())?;

    let max_bytes = args
        .max_gb
        .filter(|&gb| gb > 0.0)
        .map(|gb| (gb * 1_073_741_824.0) as u64);

    let token = args.token.unwrap_or_else(|| generate_token(24));
    let local_ip = detect_local_ip();

    let (listener, bind_addr) = bind_10g_listener(&args.bind, args.port)?;
    let actual_port = bind_addr.port();

    let net_info = NetworkInfo {
        local_ip: local_ip.to_string(),
        public_ip: None,
        port: actual_port,
        upnp_status: "Initializing...".to_string(),
        token: token.clone(),
        shared_dir: root_dir.display().to_string(),
    };

    let sec_cfg = SecurityConfig {
        password: args.password.clone(),
        max_downloads: args.max_downloads,
        max_bytes,
        max_concurrent: args.max_concurrent.max(1),
        ttl,
        max_auth_failures: args.max_auth_failures,
        initial_blacklist,
    };

    let metrics = Metrics::with_security(net_info, sec_cfg);
    metrics.log(format!(
        "Serving directory {} on {} (randomized port: {})",
        root_dir.display(),
        bind_addr,
        args.port.is_none()
    ));

    if metrics.security.requires_password() {
        metrics.log("Security: Password protection enabled (HMAC-SHA256 session & Basic Auth)");
    }
    if let Some(d) = ttl {
        metrics.log(format!(
            "Timer: Link will auto-expire and close UPnP in {}",
            format_duration(d)
        ));
    }
    if let Some(max_dl) = args.max_downloads {
        metrics.log(format!("Quota: Max {} logical download(s)", max_dl));
    }

    let state = AppState {
        root_dir: root_dir.clone(),
        token: token.clone(),
        chunk_size: args.chunk_size_kb * 1024,
        allow_hidden: args.allow_hidden,
        metrics: Arc::clone(&metrics),
    };

    let app = build_router(state);
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    // Spawn UPnP port mapping + public IP discovery in background
    let metrics_upnp = Arc::clone(&metrics);
    let enable_upnp = !args.no_upnp;
    let upnp_handle = tokio::spawn(async move {
        setup_upnp_and_public_ip(local_ip, actual_port, enable_upnp, metrics_upnp).await
    });

    // Spawn high-speed HTTP/1.1 + HTTP/2 accept loop with per-socket 10GbE tuning
    let server_shutdown_rx = shutdown_rx.clone();
    let server_handle = tokio::spawn(async move {
        let mut rx = server_shutdown_rx;
        loop {
            tokio::select! {
                _ = rx.changed() => {
                    if *rx.borrow() {
                        break;
                    }
                }
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let _ = stream.set_nodelay(true);
                    let sock_ref = socket2::SockRef::from(&stream);
                    let _ = sock_ref.set_send_buffer_size(4 * 1024 * 1024);

                    let tower_service = app.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let hyper_service = service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                            let mut svc = tower_service.clone();
                            req.extensions_mut().insert(axum::extract::ConnectInfo(remote_addr));
                            async move { svc.call(req).await }
                        });

                        let mut builder = AutoServerBuilder::new(TokioExecutor::new());
                        builder.http2().initial_stream_window_size(4 * 1024 * 1024);
                        builder.http2().initial_connection_window_size(16 * 1024 * 1024);
                        let _ = builder.serve_connection(io, hyper_service).await;
                    });
                }
            }
        }
    });

    let use_tui = !args.no_tui && std::io::stdout().is_terminal();

    if use_tui {
        run_tui(
            Arc::clone(&metrics),
            shutdown_tx.clone(),
            shutdown_rx.clone(),
        )
        .await?;
    } else {
        println!("============================================================");
        println!(" ⚡ FastShare 10GbE — Secure Direct Folder Server");
        println!("============================================================");
        println!(" Shared Folder : {}", root_dir.display());
        println!(
            " LAN Share URL : http://{}:{}/{}/",
            local_ip, actual_port, token
        );
        if metrics.security.requires_password() {
            println!(" Auth Mode     : Password Protected + Secret Token");
        } else {
            println!(" Auth Mode     : Secret Token URL");
        }
        if let Some(d) = ttl {
            println!(" Auto-Expire   : {}", format_duration(d));
        }
        if let Some(m) = args.max_downloads {
            println!(" Max Downloads : {}", m);
        }
        println!(" Press Ctrl+C to stop the server & close the UPnP port.");
        println!("------------------------------------------------------------");

        let metrics_log = Arc::clone(&metrics);
        let mut last_log_count = 0usize;
        let mut printed_public = false;

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("\nShutting down server and closing UPnP port...");
                    let _ = shutdown_tx.send(true);
                    break;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    metrics_log.tick();

                    let active_cnt = metrics_log.active_count();
                    let total_sent = metrics_log.total_bytes_sent.load(Ordering::Relaxed);
                    if let Some(reason) = metrics_log.security.check_quota_exhausted(active_cnt, total_sent) {
                        println!("\n[AUTO-SHUTDOWN] {} — Closing server and UPnP port...", reason);
                        let _ = shutdown_tx.send(true);
                        break;
                    }

                    if !printed_public {
                        if let Ok(info) = metrics_log.net_info.read() {
                            if let Some(pub_ip) = &info.public_ip {
                                println!(" Public URL    : http://{}:{}/{}/", pub_ip, actual_port, token);
                                println!(" UPnP Status   : {}", info.upnp_status);
                                printed_public = true;
                            }
                        }
                    }
                    if let Ok(logs) = metrics_log.logs.read() {
                        if logs.len() > last_log_count {
                            for entry in logs.iter().skip(last_log_count) {
                                println!("[{}] {}", entry.timestamp, entry.message);
                            }
                            last_log_count = logs.len();
                        }
                    }
                }
            }
        }
    }

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;

    if let Ok(Some(lease)) = upnp_handle.await {
        lease.release(&metrics).await;
    }

    Ok(())
}
