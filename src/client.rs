use crate::metrics::{format_bytes, format_speed_bps};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::SeekFrom;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Register the `fastshare://` custom URL protocol handler for the current user (no Admin required on Windows).
/// Once registered, clicking "⚡ Launch App (16x)" in the web browser directly spawns `fastshare` in a terminal
/// and starts a 16-connection parallel 10GbE download!
pub fn register_protocol_handler() -> Result<()> {
    let exe_path = std::env::current_exe().context("Failed to locate current executable path")?;
    // Strip Windows extended-length prefix `\\?\` if present
    let exe_str = exe_path
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let status1 = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Classes\fastshare",
                "/ve",
                "/d",
                "URL:FastShare 10G Protocol",
                "/f",
            ])
            .status()
            .context("Failed to execute reg.exe")?;

        let status2 = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Classes\fastshare",
                "/v",
                "URL Protocol",
                "/d",
                "",
                "/f",
            ])
            .status()?;

        let cmd_val = format!("\"{}\" --download \"%1\"", exe_str);
        let status3 = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Classes\fastshare\shell\open\command",
                "/ve",
                "/d",
                &cmd_val,
                "/f",
            ])
            .status()?;

        if status1.success() && status2.success() && status3.success() {
            println!("============================================================");
            println!(" ✅ Registered `fastshare://` 1-Click Browser Protocol!");
            println!("============================================================");
            println!(" Executable : {}", exe_str);
            println!(" Registry   : HKCU\\Software\\Classes\\fastshare");
            println!(" You can now click [⚡ Open 10G Shell] in any browser to");
            println!(" automatically launch a 16-stream 10GbE native download!");
            return Ok(());
        } else {
            anyhow::bail!("reg.exe returned a non-zero exit code while registering protocol");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        let apps_dir = PathBuf::from(&home).join(".local/share/applications");
        std::fs::create_dir_all(&apps_dir)?;
        let desktop_file = apps_dir.join("fastshare-handler.desktop");
        let content = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=FastShare 10G Downloader\n\
             Exec=\"{}\" --download %u\n\
             Terminal=true\n\
             MimeType=x-scheme-handler/fastshare;\n",
            exe_str
        );
        std::fs::write(&desktop_file, content)?;
        let _ = std::process::Command::new("xdg-mime")
            .args([
                "default",
                "fastshare-handler.desktop",
                "x-scheme-handler/fastshare",
            ])
            .status();
        println!("✅ Registered `fastshare://` protocol handler in {:?}", desktop_file);
        Ok(())
    }
}

struct ParsedUrl {
    host: String,
    port: u16,
    path_and_query: String,
    fallback_filename: String,
}

fn parse_download_target(raw_input: &str) -> Result<ParsedUrl> {
    let trimmed = raw_input.trim().trim_matches('"');

    // Support `fastshare://http://host:port/path` or `fastshare://host:port/path` or `http://host:port/path`
    let without_scheme = if let Some(rest) = trimmed.strip_prefix("fastshare://") {
        let rest = rest.strip_prefix("http://").or_else(|| rest.strip_prefix("http/")).unwrap_or(rest);
        rest
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        rest
    } else {
        anyhow::bail!("Unsupported URL scheme in '{}' (expected http:// or fastshare://)", trimmed);
    };

    let (host_port, path_part) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };

    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .with_context(|| format!("Invalid port in '{}'", host_port))?,
        ),
        None => (host_port.to_string(), 80),
    };

    let clean_path = path_part.split('?').next().unwrap_or(path_part);
    let raw_name = clean_path
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("download.bin");
    let decoded_name = percent_encoding::percent_decode_str(raw_name)
        .decode_utf8_lossy()
        .to_string();

    Ok(ParsedUrl {
        host,
        port,
        path_and_query: path_part.to_string(),
        fallback_filename: sanitize_filename(&decoded_name),
    })
}

fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0' => '_',
            _ => c,
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "download.bin".to_string()
    } else {
        cleaned
    }
}

fn default_downloads_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let dl = PathBuf::from(profile).join("Downloads");
            if dl.is_dir() {
                return dl;
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let dl = PathBuf::from(home).join("Downloads");
            if dl.is_dir() {
                return dl;
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn connect_10g_stream(addr: SocketAddr) -> Result<TcpStream> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024); // 4 MiB receive buffer
    let _ = socket.set_nodelay(true);
    socket.connect_timeout(&addr.into(), Duration::from_secs(5))?;
    socket.set_nonblocking(true)?;
    Ok(TcpStream::from_std(socket.into())?)
}

/// Run the built-in 16-connection 10GbE parallel downloader.
pub async fn run_parallel_download(
    target_url: &str,
    connections: usize,
    output_dir: Option<&Path>,
) -> Result<()> {
    let parsed = parse_download_target(target_url)?;
    let num_conns = connections.clamp(1, 32);

    println!("============================================================");
    println!(" ⚡ FastShare 10GbE — Native {}-Stream Parallel Downloader", num_conns);
    println!("============================================================");
    println!(" Connecting to {}:{} ...", parsed.host, parsed.port);

    let sock_addr = format!("{}:{}", parsed.host, parsed.port)
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {}:{}", parsed.host, parsed.port))?
        .next()
        .context("No IP addresses resolved for host")?;

    // 1. Send HEAD request to inspect Content-Length and Content-Disposition
    let stream = connect_10g_stream(sock_addr)?;
    let mut reader = BufReader::new(stream);
    let head_req = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare-10g/0.1\r\nConnection: close\r\n\r\n",
        parsed.path_and_query, parsed.host, parsed.port
    );
    reader.get_mut().write_all(head_req.as_bytes()).await?;

    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if status_code != 200 && status_code != 206 {
        anyhow::bail!("Server returned HTTP {} ({})", status_code, status_line.trim());
    }

    let mut content_length: Option<u64> = None;
    let mut filename = parsed.fallback_filename.clone();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if key == "content-length" {
                content_length = val.parse::<u64>().ok();
            } else if key == "content-disposition" {
                if let Some(pos) = val.find("filename=\"") {
                    let rest = &val[pos + 10..];
                    if let Some(end) = rest.find('"') {
                        filename = sanitize_filename(&rest[..end]);
                    }
                }
            }
        }
    }

    let dest_dir = output_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_downloads_dir);
    std::fs::create_dir_all(&dest_dir)?;
    let dest_path = dest_dir.join(&filename);

    let total_size = content_length.unwrap_or(0);
    println!(" File Name   : {}", filename);
    println!(
        " File Size   : {}",
        if total_size > 0 {
            format_bytes(total_size)
        } else {
            "Stream (unknown size)".to_string()
        }
    );
    println!(" Saving To   : {}", dest_path.display());
    println!("------------------------------------------------------------");

    // Pre-allocate destination file
    {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dest_path)
            .await
            .with_context(|| format!("Failed to create output file {:?}", dest_path))?;
        if total_size > 0 {
            file.set_len(total_size).await?;
        }
    }

    let start_instant = Instant::now();
    let bytes_downloaded = Arc::new(AtomicU64::new(0));

    // Spawn progress reporter
    let bytes_reporter = Arc::clone(&bytes_downloaded);
    let progress_handle = tokio::spawn(async move {
        let mut last_bytes = 0u64;
        let mut last_tick = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let now = Instant::now();
            let dt = now.duration_since(last_tick).as_secs_f64();
            if dt < 0.05 {
                continue;
            }
            let curr = bytes_reporter.load(Ordering::Relaxed);
            let bps = ((curr.saturating_sub(last_bytes)) as f64) / dt;
            last_bytes = curr;
            last_tick = now;

            if total_size > 0 {
                let pct = ((curr as f64 / total_size as f64) * 100.0).min(100.0);
                print!(
                    "\r 🚀 {:5.1}% | {} / {} | {}          ",
                    pct,
                    format_bytes(curr),
                    format_bytes(total_size),
                    format_speed_bps(bps)
                );
            } else {
                print!(
                    "\r 🚀 Downloaded {} | {}          ",
                    format_bytes(curr),
                    format_speed_bps(bps)
                );
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    });

    if total_size == 0 {
        // Single stream download if size is unknown (e.g. streaming .zip/.tar archive)
        download_range_worker(
            sock_addr,
            parsed.host.clone(),
            parsed.port,
            parsed.path_and_query.clone(),
            dest_path.clone(),
            None,
            Arc::clone(&bytes_downloaded),
        )
        .await?;
    } else {
        // Split file across `num_conns` parallel TCP Range streams
        let actual_conns = if total_size < 4 * 1024 * 1024 {
            1
        } else {
            num_conns
        };
        let part_size = total_size / (actual_conns as u64);
        let mut handles = Vec::with_capacity(actual_conns);

        for i in 0..actual_conns {
            let start_byte = (i as u64) * part_size;
            let end_byte = if i == actual_conns - 1 {
                total_size - 1
            } else {
                (i as u64 + 1) * part_size - 1
            };

            let host = parsed.host.clone();
            let port = parsed.port;
            let pq = parsed.path_and_query.clone();
            let out = dest_path.clone();
            let counter = Arc::clone(&bytes_downloaded);

            handles.push(tokio::spawn(async move {
                download_range_worker(
                    sock_addr,
                    host,
                    port,
                    pq,
                    out,
                    Some((start_byte, end_byte)),
                    counter,
                )
                .await
            }));
        }

        for h in handles {
            h.await.context("Worker task panicked")??;
        }
    }

    progress_handle.abort();
    let elapsed = start_instant.elapsed().as_secs_f64().max(0.001);
    let final_bytes = bytes_downloaded.load(Ordering::Relaxed);
    let avg_bps = (final_bytes as f64) / elapsed;

    println!(
        "\r ✅ 100.0% | {} in {:.2}s | Avg: {}                    ",
        format_bytes(final_bytes),
        elapsed,
        format_speed_bps(avg_bps)
    );
    println!("============================================================");
    println!(" Saved to: {}", dest_path.display());

    // If launched from browser protocol (`fastshare://`), pause briefly so the user can see the result
    if target_url.trim().starts_with("fastshare://") {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    Ok(())
}

async fn download_range_worker(
    sock_addr: SocketAddr,
    host: String,
    port: u16,
    path_and_query: String,
    dest_path: PathBuf,
    range: Option<(u64, u64)>,
    bytes_counter: Arc<AtomicU64>,
) -> Result<()> {
    let stream = connect_10g_stream(sock_addr)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, stream);

    let req = match range {
        Some((start, end)) => format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare-10g/0.1\r\nRange: bytes={}-{}\r\nConnection: close\r\n\r\n",
            path_and_query, host, port, start, end
        ),
        None => format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare-10g/0.1\r\nConnection: close\r\n\r\n",
            path_and_query, host, port
        ),
    };

    reader.get_mut().write_all(req.as_bytes()).await?;

    // Read HTTP response headers
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status_code != 200 && status_code != 206 {
        anyhow::bail!("Worker received HTTP {}", status_code);
    }

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let mut file = OpenOptions::new().write(true).open(&dest_path).await?;
    if let Some((start, _)) = range {
        file.seek(SeekFrom::Start(start)).await?;
    }

    let mut buf = vec![0u8; 1024 * 1024]; // 1 MiB write buffer per worker
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).await?;
        bytes_counter.fetch_add(n as u64, Ordering::Relaxed);
    }
    file.flush().await?;
    Ok(())
}
