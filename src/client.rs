use crate::metrics::{format_bytes, format_speed_bps};
use crate::server::FolderManifest;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::SeekFrom;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Register the `fastshare://` URI scheme for the current user (`HKCU\Software\Classes\fastshare` on Windows,
/// or XDG desktop entry on Linux). When triggered from the browser, `fastshare` launches `aria2c` directly
/// (or falls back to the built-in multi-stream HTTP Range client if `aria2c` is not in `PATH`).
pub fn register_protocol_handler() -> Result<()> {
    let exe_path = std::env::current_exe().context("Failed to locate current executable path")?;
    let exe_str = exe_path
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();

    #[cfg(target_os = "windows")]
    {
        let status1 = Command::new("reg")
            .args([
                "add",
                r"HKCU\Software\Classes\fastshare",
                "/ve",
                "/d",
                "URL:FastShare Protocol",
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
            println!("Registered 'fastshare://' URI scheme in HKCU\\Software\\Classes\\fastshare");
            println!("Handler command: {}", cmd_val);
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
             Name=FastShare Handler\n\
             Exec=\"{}\" --download %u\n\
             Terminal=true\n\
             MimeType=x-scheme-handler/fastshare;\n",
            exe_str
        );
        std::fs::write(&desktop_file, content)?;
        let _ = Command::new("xdg-mime")
            .args([
                "default",
                "fastshare-handler.desktop",
                "x-scheme-handler/fastshare",
            ])
            .status();
        println!("Registered 'fastshare://' URI handler at {:?}", desktop_file);
        Ok(())
    }
}

struct ParsedUrl {
    http_url: String,
    host: String,
    port: u16,
    path_and_query: String,
    fallback_filename: String,
}

fn parse_download_target(raw_input: &str) -> Result<ParsedUrl> {
    let trimmed = raw_input.trim().trim_matches('"');

    let without_scheme = if let Some(rest) = trimmed.strip_prefix("fastshare://") {
        rest.strip_prefix("http://")
            .or_else(|| rest.strip_prefix("http/"))
            .unwrap_or(rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        rest
    } else {
        anyhow::bail!(
            "Unsupported URI scheme in '{}' (expected http:// or fastshare://)",
            trimmed
        );
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

    let http_url = format!("http://{}:{}{}", host, port, path_part);

    Ok(ParsedUrl {
        http_url,
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

fn safe_relative_path(base_dir: &Path, rel: &str) -> Option<PathBuf> {
    let mut out = base_dir.to_path_buf();
    let mut pushed = false;
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_str()?;
                if s.is_empty() || s == "." || s == ".." {
                    return None;
                }
                out.push(sanitize_filename(s));
                pushed = true;
            }
            Component::CurDir => continue,
            _ => return None,
        }
    }
    if pushed {
        Some(out)
    } else {
        None
    }
}

fn append_query_param(path_and_query: &str, param: &str) -> String {
    if path_and_query.contains('?') {
        format!("{}&{}", path_and_query, param)
    } else {
        format!("{}?{}", path_and_query, param)
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

fn connect_stream(addr: SocketAddr) -> Result<TcpStream> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_nodelay(true);
    socket.connect_timeout(&addr.into(), Duration::from_secs(5))?;
    socket.set_nonblocking(true)?;
    Ok(TcpStream::from_std(socket.into())?)
}

struct HeadInfo {
    is_directory: bool,
    content_length: Option<u64>,
    filename: String,
}

async fn probe_head(sock_addr: SocketAddr, parsed: &ParsedUrl) -> Result<HeadInfo> {
    let stream = connect_stream(sock_addr)?;
    let mut reader = BufReader::new(stream);
    let head_req = format!(
        "HEAD {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare/0.1\r\nConnection: close\r\n\r\n",
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
        anyhow::bail!(
            "Server returned HTTP {} ({})",
            status_code,
            status_line.trim()
        );
    }

    let mut is_directory = false;
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
            if key == "x-fastshare-type" && val.eq_ignore_ascii_case("directory") {
                is_directory = true;
            } else if key == "content-type" && val.to_ascii_lowercase().starts_with("text/html") {
                is_directory = true;
            } else if key == "content-length" {
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

    Ok(HeadInfo {
        is_directory,
        content_length,
        filename,
    })
}

async fn fetch_http_body(
    sock_addr: SocketAddr,
    host: &str,
    port: u16,
    path_and_query: &str,
) -> Result<Vec<u8>> {
    let stream = connect_stream(sock_addr)?;
    let mut reader = BufReader::new(stream);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare/0.1\r\nConnection: close\r\n\r\n",
        path_and_query, host, port
    );
    reader.get_mut().write_all(req.as_bytes()).await?;

    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status_code != 200 {
        anyhow::bail!(
            "Failed to fetch manifest: HTTP {} ({})",
            status_code,
            status_line.trim()
        );
    }

    let mut is_chunked = false;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
        }
    }

    if is_chunked {
        let mut out = Vec::new();
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line).await? == 0 {
                break;
            }
            let size_hex = size_line.split(';').next().unwrap_or("").trim();
            let chunk_len = usize::from_str_radix(size_hex, 16).unwrap_or(0);
            if chunk_len == 0 {
                break;
            }
            let mut chunk = vec![0u8; chunk_len];
            reader.read_exact(&mut chunk).await?;
            out.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf).await;
        }
        Ok(out)
    } else {
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await?;
        Ok(out)
    }
}

/// Download a target file or recursive directory URL without compression:
/// 1. Probes the target via `HEAD` to detect whether it is a single file or a directory.
/// 2. Invokes `aria2c` directly in the terminal if installed on `PATH` (using `-i -` for recursive folders).
/// 3. Falls back to the built-in multi-stream HTTP Range client if `aria2c` is unavailable.
pub async fn run_parallel_download(
    target_url: &str,
    connections: usize,
    output_dir: Option<&Path>,
) -> Result<()> {
    let is_protocol_launch = target_url.trim().starts_with("fastshare://");
    let parsed = parse_download_target(target_url)?;
    let num_conns = connections.clamp(1, 32);

    let dest_dir = output_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_downloads_dir);
    std::fs::create_dir_all(&dest_dir)?;

    let sock_addr = format!("{}:{}", parsed.host, parsed.port)
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {}:{}", parsed.host, parsed.port))?
        .next()
        .context("No IP addresses resolved for host")?;

    let head = probe_head(sock_addr, &parsed).await?;

    if head.is_directory {
        let res = download_directory_parallel(
            sock_addr,
            &parsed,
            num_conns,
            &dest_dir,
        )
        .await;
        if is_protocol_launch {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        return res;
    }

    // Single-file mode: prefer `aria2c` directly if available on PATH
    let conns_str = num_conns.to_string();
    let dir_str = dest_dir.to_string_lossy().to_string();
    let aria2_status = Command::new("aria2c")
        .args([
            "-x",
            &conns_str,
            "-s",
            &conns_str,
            "-k",
            "4M",
            "--file-allocation=none",
            "-d",
            &dir_str,
            "-o",
            &head.filename,
            &parsed.http_url,
        ])
        .status();

    match aria2_status {
        Ok(status) => {
            if is_protocol_launch {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            if status.success() {
                return Ok(());
            } else {
                anyhow::bail!("aria2c exited with status {}", status);
            }
        }
        Err(_) => {
            println!(
                "aria2c not found in PATH; using built-in {}-stream HTTP Range client.",
                num_conns
            );
        }
    }

    let res = download_single_file_builtin(
        sock_addr,
        &parsed.host,
        parsed.port,
        &parsed.path_and_query,
        &dest_dir.join(&head.filename),
        head.content_length.unwrap_or(0),
        num_conns,
    )
    .await;

    if is_protocol_launch {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    res
}

async fn download_directory_parallel(
    sock_addr: SocketAddr,
    parsed: &ParsedUrl,
    num_conns: usize,
    dest_dir: &Path,
) -> Result<()> {
    let manifest_pq = append_query_param(&parsed.path_and_query, "manifest=1");
    let body = fetch_http_body(sock_addr, &parsed.host, parsed.port, &manifest_pq).await?;
    let manifest: FolderManifest = serde_json::from_slice(&body)
        .context("Failed to parse directory JSON manifest from server")?;

    if manifest.files.is_empty() {
        println!("Directory '{}' contains no files.", manifest.root);
        return Ok(());
    }

    let folder_name = sanitize_filename(&manifest.root);
    let target_root = dest_dir.join(&folder_name);
    std::fs::create_dir_all(&target_root)?;

    println!("------------------------------------------------------------");
    println!(
        "FastShare Directory Sync (uncompressed, {} files, {})",
        manifest.total_files,
        format_bytes(manifest.total_bytes)
    );
    println!("Destination : {}", target_root.display());
    println!("------------------------------------------------------------");

    // 1. Try spawning `aria2c -i -` directly so all files download concurrently with preserved paths
    let conns_str = num_conns.to_string();
    let dir_str = target_root.to_string_lossy().to_string();
    let spawn_res = Command::new("aria2c")
        .args([
            "-i",
            "-",
            "-j",
            "4",
            "-x",
            &conns_str,
            "-s",
            &conns_str,
            "-k",
            "4M",
            "--file-allocation=none",
            "--auto-file-renaming=false",
            "--allow-overwrite=true",
            "-d",
            &dir_str,
        ])
        .stdin(Stdio::piped())
        .spawn();

    if let Ok(mut child) = spawn_res {
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            for f in &manifest.files {
                // Ensure no path traversal inside out=
                if safe_relative_path(&target_root, &f.path).is_some() {
                    let line = format!(
                        "http://{}:{}{}\n  out={}\n",
                        parsed.host, parsed.port, f.url, f.path
                    );
                    let _ = stdin.write_all(line.as_bytes());
                }
            }
        }
        let status = child.wait()?;
        if status.success() {
            return Ok(());
        } else {
            anyhow::bail!("aria2c exited with status {}", status);
        }
    }

    println!(
        "aria2c not found in PATH; downloading {} files using built-in {}-stream HTTP Range client.",
        manifest.total_files, num_conns
    );

    let start_instant = Instant::now();
    let total_downloaded = Arc::new(AtomicU64::new(0));
    let total_expected = manifest.total_bytes;

    let bytes_reporter = Arc::clone(&total_downloaded);
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

            if total_expected > 0 {
                let pct = ((curr as f64 / total_expected as f64) * 100.0).min(100.0);
                print!(
                    "\r[{:5.1}%] {} / {} | {}          ",
                    pct,
                    format_bytes(curr),
                    format_bytes(total_expected),
                    format_speed_bps(bps)
                );
            } else {
                print!(
                    "\rDownloaded {} | {}          ",
                    format_bytes(curr),
                    format_speed_bps(bps)
                );
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    });

    for f in &manifest.files {
        let dest_path = match safe_relative_path(&target_root, &f.path) {
            Some(p) => p,
            None => continue,
        };
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        download_file_into(
            sock_addr,
            &parsed.host,
            parsed.port,
            &f.url,
            &dest_path,
            f.size,
            num_conns,
            Arc::clone(&total_downloaded),
        )
        .await?;
    }

    progress_handle.abort();
    let elapsed = start_instant.elapsed().as_secs_f64().max(0.001);
    let final_bytes = total_downloaded.load(Ordering::Relaxed);
    let avg_bps = (final_bytes as f64) / elapsed;
    println!(
        "\r[100.0%] {} files ({}) in {:.2}s | Avg: {}                    ",
        manifest.total_files,
        format_bytes(final_bytes),
        elapsed,
        format_speed_bps(avg_bps)
    );
    println!("Saved directory: {}", target_root.display());
    Ok(())
}

async fn download_single_file_builtin(
    sock_addr: SocketAddr,
    host: &str,
    port: u16,
    path_and_query: &str,
    dest_path: &Path,
    total_size: u64,
    num_conns: usize,
) -> Result<()> {
    println!("------------------------------------------------------------");
    println!("FastShare Client ({} parallel connections)", num_conns);
    println!(
        "File        : {}",
        dest_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    );
    println!(
        "Size        : {}",
        if total_size > 0 {
            format_bytes(total_size)
        } else {
            "Unknown (stream)".to_string()
        }
    );
    println!("Destination : {}", dest_path.display());
    println!("------------------------------------------------------------");

    let start_instant = Instant::now();
    let bytes_downloaded = Arc::new(AtomicU64::new(0));

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
                    "\r[{:5.1}%] {} / {} | {}          ",
                    pct,
                    format_bytes(curr),
                    format_bytes(total_size),
                    format_speed_bps(bps)
                );
            } else {
                print!(
                    "\rDownloaded {} | {}          ",
                    format_bytes(curr),
                    format_speed_bps(bps)
                );
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    });

    download_file_into(
        sock_addr,
        host,
        port,
        path_and_query,
        dest_path,
        total_size,
        num_conns,
        Arc::clone(&bytes_downloaded),
    )
    .await?;

    progress_handle.abort();
    let elapsed = start_instant.elapsed().as_secs_f64().max(0.001);
    let final_bytes = bytes_downloaded.load(Ordering::Relaxed);
    let avg_bps = (final_bytes as f64) / elapsed;

    println!(
        "\r[100.0%] {} in {:.2}s | Avg: {}                    ",
        format_bytes(final_bytes),
        elapsed,
        format_speed_bps(avg_bps)
    );
    println!("Saved: {}", dest_path.display());
    Ok(())
}

async fn download_file_into(
    sock_addr: SocketAddr,
    host: &str,
    port: u16,
    path_and_query: &str,
    dest_path: &Path,
    total_size: u64,
    num_conns: usize,
    bytes_downloaded: Arc<AtomicU64>,
) -> Result<()> {
    {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(dest_path)
            .await
            .with_context(|| format!("Failed to create output file {:?}", dest_path))?;
        if total_size > 0 {
            file.set_len(total_size).await?;
        }
    }

    if total_size == 0 {
        return download_range_worker(
            sock_addr,
            host.to_string(),
            port,
            path_and_query.to_string(),
            dest_path.to_path_buf(),
            None,
            bytes_downloaded,
        )
        .await;
    }

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

        let host_s = host.to_string();
        let pq = path_and_query.to_string();
        let out = dest_path.to_path_buf();
        let counter = Arc::clone(&bytes_downloaded);

        handles.push(tokio::spawn(async move {
            download_range_worker(
                sock_addr,
                host_s,
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
    let stream = connect_stream(sock_addr)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, stream);

    let req = match range {
        Some((start, end)) => format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare/0.1\r\nRange: bytes={}-{}\r\nConnection: close\r\n\r\n",
            path_and_query, host, port, start, end
        ),
        None => format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare/0.1\r\nConnection: close\r\n\r\n",
            path_and_query, host, port
        ),
    };

    reader.get_mut().write_all(req.as_bytes()).await?;

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

    let mut buf = vec![0u8; 1024 * 1024];
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
