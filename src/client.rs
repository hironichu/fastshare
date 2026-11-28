use crate::metrics::{format_bytes, format_speed_bps};
use crate::server::FolderManifest;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::ffi::OsString;
use std::io::SeekFrom;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Register the `fastshare://` URI scheme for the current user (`HKCU\Software\Classes\fastshare` on Windows,
/// or XDG desktop entry on Linux). When triggered from the browser, `fastshare` asks for a destination
/// folder, launches `aria2c`, or falls back to the built-in multi-stream HTTP Range client.
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
            Ok(())
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
        println!(
            "Registered 'fastshare://' URI handler at {:?}",
            desktop_file
        );
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

#[derive(Clone)]
struct DownloadSource {
    sock_addr: SocketAddr,
    host: String,
    port: u16,
    path_and_query: String,
    etag: Option<String>,
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

#[cfg(target_os = "windows")]
fn choose_download_directory() -> Result<PathBuf> {
    let script = r#"
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = 'Choose where FastShare should save this folder'
$dialog.ShowNewFolderButton = $true
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.SelectedPath)
    exit 0
}
exit 2
"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-STA", "-Command", script])
        .output()
        .context("Failed to open the Windows folder picker")?;
    if !output.status.success() {
        anyhow::bail!("Folder selection was cancelled");
    }
    let selected = String::from_utf8(output.stdout)
        .context("Folder picker returned an invalid path")?
        .trim()
        .to_string();
    if selected.is_empty() {
        anyhow::bail!("Folder selection was cancelled");
    }
    Ok(PathBuf::from(selected))
}

#[cfg(target_os = "macos")]
fn choose_download_directory() -> Result<PathBuf> {
    let output = Command::new("osascript")
        .args([
            "-e",
            "POSIX path of (choose folder with prompt \"Choose where FastShare should save this folder\")",
        ])
        .output()
        .context("Failed to open the macOS folder picker")?;
    if !output.status.success() {
        anyhow::bail!("Folder selection was cancelled");
    }
    let selected = String::from_utf8(output.stdout)
        .context("Folder picker returned an invalid path")?
        .trim()
        .to_string();
    if selected.is_empty() {
        anyhow::bail!("Folder selection was cancelled");
    }
    Ok(PathBuf::from(selected))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn choose_download_directory() -> Result<PathBuf> {
    for (program, arguments) in [
        (
            "zenity",
            vec![
                "--file-selection",
                "--directory",
                "--title=Choose where FastShare should save this folder",
            ],
        ),
        (
            "kdialog",
            vec![
                "--getexistingdirectory",
                ".",
                "--title",
                "Choose where FastShare should save this folder",
            ],
        ),
    ] {
        let Ok(output) = Command::new(program).args(arguments).output() else {
            continue;
        };
        if output.status.success() {
            let selected = String::from_utf8(output.stdout)
                .context("Folder picker returned an invalid path")?
                .trim()
                .to_string();
            if !selected.is_empty() {
                return Ok(PathBuf::from(selected));
            }
        }
    }
    anyhow::bail!("No supported graphical folder picker was found (install zenity or kdialog)")
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
    etag: Option<String>,
    max_concurrent: Option<usize>,
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
    let mut etag = None;
    let mut max_concurrent = None;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if (key == "x-fastshare-type" && val.eq_ignore_ascii_case("directory"))
                || (key == "content-type" && val.to_ascii_lowercase().starts_with("text/html"))
            {
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
            } else if key == "etag" {
                etag = Some(val.to_string());
            } else if key == "x-fastshare-max-concurrent" {
                max_concurrent = val.parse::<usize>().ok();
            }
        }
    }

    Ok(HeadInfo {
        is_directory,
        content_length,
        filename,
        etag,
        max_concurrent,
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

    let dest_dir = match output_dir {
        Some(path) => path.to_path_buf(),
        None if is_protocol_launch => choose_download_directory()?,
        None => default_downloads_dir(),
    };
    std::fs::create_dir_all(&dest_dir)?;

    let sock_addr = format!("{}:{}", parsed.host, parsed.port)
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {}:{}", parsed.host, parsed.port))?
        .next()
        .context("No IP addresses resolved for host")?;

    let head = probe_head(sock_addr, &parsed).await?;

    if head.is_directory {
        let res = download_directory_parallel(sock_addr, &parsed, num_conns, &dest_dir).await;
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
        DownloadSource {
            sock_addr,
            host: parsed.host.clone(),
            port: parsed.port,
            path_and_query: parsed.path_and_query.clone(),
            etag: head.etag.clone(),
        },
        &dest_dir.join(&head.filename),
        head.content_length.unwrap_or(0),
        head.max_concurrent
            .map(|limit| num_conns.min(limit.max(1)))
            .unwrap_or(num_conns),
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

    use futures::{stream, StreamExt};

    let small_files: Vec<_> = manifest
        .files
        .iter()
        .filter(|file| file.size < 32 * 1024 * 1024)
        .collect();
    let server_limit = manifest.max_concurrent.unwrap_or(num_conns).max(1);
    let small_parallelism = num_conns.min(server_limit).clamp(1, 8);
    let small_results = stream::iter(small_files)
        .map(|f| {
            let target_root = &target_root;
            let total_downloaded = Arc::clone(&total_downloaded);
            async move {
                let dest_path = safe_relative_path(target_root, &f.path)
                    .context("Manifest contained an unsafe relative path")?;
                if let Some(parent) = dest_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                let source = DownloadSource {
                    sock_addr,
                    host: parsed.host.clone(),
                    port: parsed.port,
                    path_and_query: f.url.clone(),
                    etag: Some(f.etag.clone()),
                };
                download_file_into(&source, &dest_path, f.size, 1, total_downloaded).await
            }
        })
        .buffer_unordered(small_parallelism)
        .collect::<Vec<_>>()
        .await;
    for result in small_results {
        result?;
    }

    for f in manifest
        .files
        .iter()
        .filter(|file| file.size >= 32 * 1024 * 1024)
    {
        let dest_path = match safe_relative_path(&target_root, &f.path) {
            Some(p) => p,
            None => continue,
        };
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let source = DownloadSource {
            sock_addr,
            host: parsed.host.clone(),
            port: parsed.port,
            path_and_query: f.url.clone(),
            etag: Some(f.etag.clone()),
        };
        download_file_into(
            &source,
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
    source: DownloadSource,
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
        &source,
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
    source: &DownloadSource,
    dest_path: &Path,
    total_size: u64,
    num_conns: usize,
    bytes_downloaded: Arc<AtomicU64>,
) -> Result<()> {
    let requested_etag = source.etag.clone().unwrap_or_default();
    if total_size > 0 {
        if let Ok(metadata) = tokio::fs::metadata(dest_path).await {
            if metadata.is_file() && metadata.len() == total_size {
                bytes_downloaded.fetch_add(total_size, Ordering::Relaxed);
                return Ok(());
            }
        }
    }

    let part_path = append_path_suffix(dest_path, ".fastshare.part");
    let resume_path = append_path_suffix(dest_path, ".fastshare.resume");

    {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&part_path)
            .await
            .with_context(|| format!("Failed to create partial output file {:?}", part_path))?;
        if total_size > 0 {
            file.set_len(total_size).await?;
        } else {
            file.set_len(0).await?;
        }
    }

    if total_size == 0 {
        download_range_worker(source.clone(), part_path.clone(), None, bytes_downloaded).await?;
        finish_partial_download(&part_path, &resume_path, dest_path).await?;
        return Ok(());
    }

    const RESUME_CHUNK_SIZE: u64 = 64 * 1024 * 1024;
    let chunk_count = total_size.div_ceil(RESUME_CHUNK_SIZE) as usize;
    let resume = tokio::fs::read(&resume_path)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<DownloadResume>(&bytes).ok())
        .filter(|state| {
            !requested_etag.is_empty()
                && state.total_size == total_size
                && state.chunk_size == RESUME_CHUNK_SIZE
                && state.etag == requested_etag
                && state.completed.len() == chunk_count
        })
        .unwrap_or_else(|| DownloadResume {
            total_size,
            chunk_size: RESUME_CHUNK_SIZE,
            etag: requested_etag.clone(),
            completed: vec![false; chunk_count],
        });

    let resumed_bytes = resume
        .completed
        .iter()
        .enumerate()
        .filter(|(_, completed)| **completed)
        .map(|(index, _)| {
            let start = index as u64 * RESUME_CHUNK_SIZE;
            (total_size - start).min(RESUME_CHUNK_SIZE)
        })
        .sum::<u64>();
    bytes_downloaded.fetch_add(resumed_bytes, Ordering::Relaxed);

    if !resume.completed.iter().any(|completed| *completed) {
        persist_resume_state(&resume_path, &resume).await?;
    }

    let actual_conns = if total_size < 4 * 1024 * 1024 {
        1usize
    } else {
        num_conns.min(chunk_count)
    };
    let resume = Arc::new(Mutex::new(resume));
    let next_chunk = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(actual_conns);

    for _ in 0..actual_conns {
        let worker_source = source.clone();
        let out = part_path.clone();
        let state_path = resume_path.clone();
        let state = Arc::clone(&resume);
        let cursor = Arc::clone(&next_chunk);
        let counter = Arc::clone(&bytes_downloaded);

        handles.push(tokio::spawn(async move {
            loop {
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                if index >= chunk_count {
                    return Ok::<(), anyhow::Error>(());
                }
                if state.lock().await.completed[index] {
                    continue;
                }

                let start_byte = index as u64 * RESUME_CHUNK_SIZE;
                let end_byte = (start_byte + RESUME_CHUNK_SIZE - 1).min(total_size - 1);
                let mut last_error = None;
                for attempt in 0..3 {
                    match download_range_worker(
                        worker_source.clone(),
                        out.clone(),
                        Some((start_byte, end_byte)),
                        Arc::clone(&counter),
                    )
                    .await
                    {
                        Ok(()) => {
                            last_error = None;
                            break;
                        }
                        Err(error) => {
                            last_error = Some(error);
                            if attempt < 2 {
                                tokio::time::sleep(Duration::from_millis(250 * (1u64 << attempt)))
                                    .await;
                            }
                        }
                    }
                }
                if let Some(error) = last_error {
                    return Err(error);
                }

                let mut locked = state.lock().await;
                locked.completed[index] = true;
                persist_resume_state(&state_path, &locked).await?;
            }
        }));
    }

    for h in handles {
        h.await.context("Worker task panicked")??;
    }

    if !resume
        .lock()
        .await
        .completed
        .iter()
        .all(|completed| *completed)
    {
        anyhow::bail!("Download stopped before all ranges completed");
    }
    finish_partial_download(&part_path, &resume_path, dest_path).await?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct DownloadResume {
    total_size: u64,
    chunk_size: u64,
    etag: String,
    completed: Vec<bool>,
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

async fn persist_resume_state(path: &Path, state: &DownloadResume) -> Result<()> {
    let encoded = serde_json::to_vec(state)?;
    tokio::fs::write(path, encoded).await?;
    Ok(())
}

async fn finish_partial_download(
    part_path: &Path,
    resume_path: &Path,
    dest_path: &Path,
) -> Result<()> {
    if tokio::fs::try_exists(dest_path).await.unwrap_or(false) {
        tokio::fs::remove_file(dest_path).await?;
    }
    tokio::fs::rename(part_path, dest_path).await?;
    if tokio::fs::try_exists(resume_path).await.unwrap_or(false) {
        tokio::fs::remove_file(resume_path).await?;
    }
    Ok(())
}

async fn download_range_worker(
    source: DownloadSource,
    dest_path: PathBuf,
    range: Option<(u64, u64)>,
    bytes_counter: Arc<AtomicU64>,
) -> Result<()> {
    let stream = connect_stream(source.sock_addr)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, stream);

    let req = match range {
        Some((start, end)) => format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare/0.1\r\nRange: bytes={}-{}\r\n{}Connection: close\r\n\r\n",
            source.path_and_query,
            source.host,
            source.port,
            start,
            end,
            source
                .etag
                .as_ref()
                .map(|value| format!("If-Range: {}\r\n", value))
                .unwrap_or_default()
        ),
        None => format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: fastshare/0.1\r\nConnection: close\r\n\r\n",
            source.path_and_query, source.host, source.port
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
    let expected_status = if range.is_some() { 206 } else { 200 };
    if status_code != expected_status {
        anyhow::bail!("Worker received HTTP {}", status_code);
    }

    let mut response_length = None;
    let mut response_range = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("content-length") {
                response_length = value.trim().parse::<u64>().ok();
            } else if key.trim().eq_ignore_ascii_case("content-range") {
                response_range = Some(value.trim().to_string());
            }
        }
    }

    let expected_length = range.map(|(start, end)| end - start + 1);
    if let Some(expected) = expected_length {
        if response_length != Some(expected) {
            anyhow::bail!("Range length mismatch: expected {} bytes", expected);
        }
        let (start, end) = range.unwrap();
        let prefix = format!("bytes {}-{}/", start, end);
        if !response_range
            .as_deref()
            .is_some_and(|value| value.starts_with(&prefix))
        {
            anyhow::bail!("Invalid or missing Content-Range header");
        }
    }

    let mut file = OpenOptions::new().write(true).open(&dest_path).await?;
    if let Some((start, _)) = range {
        file.seek(SeekFrom::Start(start)).await?;
    }

    let mut buf = vec![0u8; 1024 * 1024];
    let mut received = 0u64;
    loop {
        let remaining = expected_length
            .map(|expected| expected.saturating_sub(received))
            .unwrap_or(buf.len() as u64);
        if remaining == 0 {
            break;
        }
        let read_len = (remaining as usize).min(buf.len());
        let n = reader.read(&mut buf[..read_len]).await?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).await?;
        received += n as u64;
    }
    file.flush().await?;
    if expected_length.is_some_and(|expected| received != expected) {
        anyhow::bail!(
            "Incomplete range: received {} of {} bytes",
            received,
            expected_length.unwrap()
        );
    }
    bytes_counter.fetch_add(received, Ordering::Relaxed);
    Ok(())
}
