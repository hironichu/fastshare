use crate::metrics::Metrics;
use crate::security::{base64_decode, constant_time_eq};
use crate::ui::{
    encode_path_segments, render_directory_page, render_login_page, render_status_page, FileEntry,
    UiContext,
};
use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipEntryBuilder};
use axum::body::Body;
use axum::extract::{ConnectInfo, Form, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;

#[derive(Clone)]
pub struct AppState {
    pub root_dir: PathBuf,
    pub token: String,
    pub chunk_size: usize,
    pub allow_hidden: bool,
    pub metrics: Arc<Metrics>,
}

#[derive(Deserialize, Default, Clone)]
pub struct RequestQuery {
    pub archive: Option<String>,
    pub manifest: Option<String>,
    pub key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ManifestFile {
    pub path: String,
    pub url: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FolderManifest {
    pub root: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub files: Vec<ManifestFile>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub password: String,
    pub redirect: Option<String>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/:token/__auth", post(handle_login))
        .route("/:token/__logout", get(handle_logout))
        .route(
            "/:token",
            get(handle_root).head(handle_root).options(handle_options),
        )
        .route(
            "/:token/",
            get(handle_root).head(handle_root).options(handle_options),
        )
        .route(
            "/:token/*rel_path",
            get(handle_path).head(handle_path).options(handle_options),
        )
        .fallback(handle_fallback)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers_and_ip_guard,
        ))
        .with_state(state)
}

async fn handle_options() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// Global security middleware:
/// 1. Blocks blacklisted IPs immediately with `403 Forbidden`.
/// 2. Checks if the link has expired or reached its quota (`410 Gone`).
/// 3. Attaches strict HTTP security headers to every response.
async fn security_headers_and_ip_guard(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let client_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    if let Some(ip) = client_ip {
        if state.metrics.security.is_blacklisted(&ip) {
            state
                .metrics
                .log(format!("Blocked blacklisted IP [{}]", ip));
            return attach_security_headers(
                (
                    StatusCode::FORBIDDEN,
                    Html(render_status_page(
                        "403 Access Denied",
                        "Client IP address is blocked by server policy.",
                        "HTTP 403",
                    )),
                )
                    .into_response(),
            );
        }
    }

    if state.metrics.security.is_disabled() {
        let reason = state
            .metrics
            .security
            .disable_reason
            .read()
            .ok()
            .and_then(|r| r.clone())
            .unwrap_or_else(|| "This share link has expired or reached its configured quota.".to_string());
        return attach_security_headers(
            (
                StatusCode::GONE,
                Html(render_status_page("410 Gone", &reason, "HTTP 410")),
            )
                .into_response(),
        );
    }

    let resp = next.run(req).await;
    attach_security_headers(resp)
}

fn attach_security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, HEAD, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Range, Authorization, Content-Type"),
    );
    h.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("Content-Length, Content-Range, Accept-Ranges"),
    );
    h.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("cross-origin"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src *; img-src 'self' data:; form-action 'self'; frame-ancestors 'none';",
        ),
    );
    resp
}

async fn handle_fallback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    record_invalid_attempt(&state, addr.ip(), "invalid URL path");
    not_found_token_response()
}

fn not_found_token_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(render_status_page(
            "404 Not Found",
            "A valid share token is required in the URL.",
            "HTTP 404",
        )),
    )
        .into_response()
}

fn record_invalid_attempt(state: &AppState, ip: std::net::IpAddr, context: &str) {
    let (count, banned) = state.metrics.security.record_auth_failure(ip);
    if banned {
        state.metrics.log(format!(
            "SECURITY: Auto-blacklisted IP [{}] after {} failed attempts ({})",
            ip, count, context
        ));
    } else {
        state.metrics.log(format!(
            "Rejected {} from [{}] (attempt {}/{})",
            context, ip, count, state.metrics.security.max_auth_failures
        ));
    }
}

async fn handle_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(token): AxumPath<String>,
    Form(form): Form<LoginForm>,
) -> Response {
    if !constant_time_eq(token.as_bytes(), state.token.as_bytes()) {
        record_invalid_attempt(&state, addr.ip(), "invalid token on login");
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    }

    let redirect_target = form
        .redirect
        .as_deref()
        .filter(|r| r.starts_with(&format!("/{}", state.token)))
        .unwrap_or("");
    let safe_redirect = if redirect_target.is_empty() {
        format!("/{}/", state.token)
    } else {
        redirect_target.to_string()
    };

    if state.metrics.security.verify_password(&form.password) {
        state.metrics.security.clear_auth_failures(addr.ip());
        state
            .metrics
            .log(format!("Auth  [{}] unlocked password-protected share", addr.ip()));
        let ticket = state.metrics.security.create_client_ticket(addr.ip());
        let cookie = format!(
            "fastshare_session={}; HttpOnly; SameSite=Strict; Path=/{}",
            ticket, state.token
        );

        let mut resp = Redirect::to(&safe_redirect).into_response();
        if let Ok(val) = HeaderValue::from_str(&cookie) {
            resp.headers_mut().insert(header::SET_COOKIE, val);
        }
        resp
    } else {
        record_invalid_attempt(&state, addr.ip(), "wrong password");
        let rem_ttl = state
            .metrics
            .security
            .remaining_ttl()
            .map(|d| d.as_secs());
        let html = render_login_page(
            &state.token,
            &safe_redirect,
            Some("Incorrect password. Please try again."),
            rem_ttl,
        );
        (StatusCode::UNAUTHORIZED, Html(html)).into_response()
    }
}

async fn handle_logout(
    State(state): State<AppState>,
    AxumPath(token): AxumPath<String>,
) -> Response {
    if !constant_time_eq(token.as_bytes(), state.token.as_bytes()) {
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    }
    let cookie = format!(
        "fastshare_session=deleted; HttpOnly; SameSite=Strict; Path=/{}; Max-Age=0",
        state.token
    );
    let mut resp = Redirect::to(&format!("/{}/", state.token)).into_response();
    if let Ok(val) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, val);
    }
    resp
}

/// Verify whether the request is authenticated when `--password` is active.
/// Accepts:
/// 1. Signed `fastshare_session` cookie
/// 2. Signed `?key=<ticket>` query parameter (for copied `aria2c` / `curl` commands)
/// 3. Standard `Authorization: Basic <base64>` header
fn is_request_authenticated(
    state: &AppState,
    client_ip: std::net::IpAddr,
    headers: &HeaderMap,
    query: &RequestQuery,
) -> bool {
    if !state.metrics.security.requires_password() {
        return true;
    }

    // 1. Check `?key=` query ticket
    if let Some(key) = &query.key {
        if state.metrics.security.verify_client_ticket(client_ip, key) {
            return true;
        }
    }

    // 2. Check `fastshare_session` cookie
    if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie_hdr.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k.trim() == "fastshare_session"
                    && state.metrics.security.verify_client_ticket(client_ip, v.trim())
                {
                    return true;
                }
            }
        }
    }

    // 3. Check `Authorization: Basic ...`
    if let Some(auth_hdr) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(b64) = auth_hdr.strip_prefix("Basic ").or_else(|| auth_hdr.strip_prefix("basic ")) {
            if let Some(decoded_bytes) = base64_decode(b64) {
                if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                    let pw = match decoded_str.split_once(':') {
                        Some((_, pass)) => pass,
                        None => decoded_str,
                    };
                    if state.metrics.security.verify_password(pw) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

async fn handle_root(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    Query(query): Query<RequestQuery>,
) -> Response {
    if !constant_time_eq(token.as_bytes(), state.token.as_bytes()) {
        record_invalid_attempt(&state, addr.ip(), "invalid token");
        return not_found_token_response();
    }
    if !is_request_authenticated(&state, addr.ip(), &headers, &query) {
        let rem_ttl = state
            .metrics
            .security
            .remaining_ttl()
            .map(|d| d.as_secs());
        let html = render_login_page(&state.token, &format!("/{}/", state.token), None, rem_ttl);
        return (StatusCode::UNAUTHORIZED, Html(html)).into_response();
    }
    serve_entry(&state, Some(addr), method, &headers, "", query).await
}

async fn handle_path(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    AxumPath((token, rel_path)): AxumPath<(String, String)>,
    Query(query): Query<RequestQuery>,
) -> Response {
    if !constant_time_eq(token.as_bytes(), state.token.as_bytes()) {
        record_invalid_attempt(&state, addr.ip(), "invalid token");
        return not_found_token_response();
    }
    if !is_request_authenticated(&state, addr.ip(), &headers, &query) {
        let rem_ttl = state
            .metrics
            .security
            .remaining_ttl()
            .map(|d| d.as_secs());
        let html = render_login_page(
            &state.token,
            &format!("/{}/{}", state.token, rel_path),
            None,
            rem_ttl,
        );
        return (StatusCode::UNAUTHORIZED, Html(html)).into_response();
    }
    serve_entry(&state, Some(addr), method, &headers, &rel_path, query).await
}

/// Safely resolve a relative URL path inside `root_dir`, preventing any path traversal (`..`, symlinks outside root, hidden files)
fn resolve_safe_path(
    root_dir: &Path,
    rel_url_path: &str,
    allow_hidden: bool,
) -> Option<(PathBuf, String)> {
    let decoded = percent_encoding::percent_decode_str(rel_url_path)
        .decode_utf8()
        .ok()?;
    if decoded.contains('\0') || decoded.contains('\\') {
        return None;
    }
    let trimmed = decoded.trim_matches('/');

    let mut candidate = root_dir.to_path_buf();
    let mut normalized_parts = Vec::new();

    for comp in Path::new(trimmed).components() {
        match comp {
            Component::Normal(os_str) => {
                let s = os_str.to_str()?;
                if s.is_empty() || s == "." {
                    continue;
                }
                if !allow_hidden && s.starts_with('.') {
                    return None;
                }
                candidate.push(os_str);
                normalized_parts.push(s.to_string());
            }
            Component::CurDir => continue,
            _ => return None, // Reject ParentDir (..), RootDir, Prefix
        }
    }

    let canon = std::fs::canonicalize(&candidate).ok()?;
    if !canon.starts_with(root_dir) {
        return None;
    }

    Some((canon, normalized_parts.join("/")))
}

async fn serve_entry(
    state: &AppState,
    client_addr: Option<SocketAddr>,
    method: Method,
    headers: &HeaderMap,
    rel_url_path: &str,
    query: RequestQuery,
) -> Response {
    let (target_path, clean_rel) =
        match resolve_safe_path(&state.root_dir, rel_url_path, state.allow_hidden) {
            Some(v) => v,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Html(render_status_page(
                        "404 Not Found",
                        "The requested file or directory does not exist.",
                        "HTTP 404",
                    )),
                )
                    .into_response()
            }
        };

    let metadata = match tokio::fs::metadata(&target_path).await {
        Ok(m) => m,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Html(render_status_page(
                    "404 Not Found",
                    "The requested file or directory could not be read.",
                    "HTTP 404",
                )),
            )
                .into_response()
        }
    };

    if metadata.is_dir() {
        if let Some(manifest_fmt) = query.manifest.as_deref() {
            return serve_directory_manifest(
                state,
                client_addr,
                headers,
                &target_path,
                &clean_rel,
                manifest_fmt,
            )
            .await;
        }
        if let Some(archive_fmt) = query.archive.as_deref() {
            if let Err(resp) = check_download_gates(state, client_addr, &format!("archive:{}", clean_rel)) {
                return resp;
            }
            match archive_fmt {
                "zip" => {
                    return stream_folder_zip(state, client_addr, &target_path, &clean_rel).await
                }
                "tar" => {
                    return stream_folder_tar(state, client_addr, &target_path, &clean_rel).await
                }
                _ => {
                    return (StatusCode::BAD_REQUEST, "Unsupported archive format").into_response()
                }
            }
        }
        if method == Method::HEAD {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header("X-FastShare-Type", "directory")
                .body(Body::empty())
                .unwrap();
        }
        let mut resp = serve_directory_ui(state, client_addr, headers, &target_path, &clean_rel).await;
        resp.headers_mut()
            .insert("X-FastShare-Type", HeaderValue::from_static("directory"));
        return resp;
    }

    if method != Method::HEAD {
        if let Err(resp) = check_download_gates(state, client_addr, &clean_rel) {
            return resp;
        }
    }

    serve_file_10g(
        state,
        client_addr,
        method,
        headers,
        &target_path,
        &clean_rel,
        metadata.len(),
    )
    .await
}

fn check_download_gates(
    state: &AppState,
    client_addr: Option<SocketAddr>,
    file_key: &str,
) -> Result<(), Response> {
    if state.metrics.active_count() >= state.metrics.security.max_concurrent {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Html(render_status_page(
                "429 Too Many Concurrent Streams",
                "Maximum simultaneous connections reached.",
                "HTTP 429",
            )),
        )
            .into_response());
    }

    if let Some(addr) = client_addr {
        let total_sent = state.metrics.total_bytes_sent.load(Ordering::Relaxed);
        if let Err(reason) = state
            .metrics
            .security
            .try_acquire_download(addr.ip(), file_key, total_sent)
        {
            state.metrics.log(format!(
                "Quota blocked download of '{}' from [{}]: {}",
                file_key,
                addr.ip(),
                reason
            ));
            return Err((
                StatusCode::GONE,
                Html(render_status_page("410 Quota Reached", &reason, "HTTP 410")),
            )
                .into_response());
        }
    }
    Ok(())
}

async fn serve_directory_ui(
    state: &AppState,
    client_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    dir_path: &Path,
    clean_rel: &str,
) -> Response {
    let mut read_dir = match tokio::fs::read_dir(dir_path).await {
        Ok(rd) => rd,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read directory").into_response()
        }
    };

    let mut entries = Vec::new();
    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !state.allow_hidden && name.starts_with('.') {
            continue;
        }
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let is_dir = meta.is_dir();
        let size = if is_dir { 0 } else { meta.len() };
        let mtime_sys = meta.modified().ok();
        let modified_ts = mtime_sys
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let modified = mtime_sys
            .map(|t| {
                let dt: DateTime<Local> = t.into();
                dt.format("%Y-%m-%d %H:%M").to_string()
            })
            .unwrap_or_else(|| "—".to_string());

        let child_rel = if clean_rel.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", clean_rel, name)
        };
        let rel_url = format!("/{}/{}", state.token, encode_path_segments(&child_rel));

        entries.push(FileEntry {
            name,
            rel_url,
            is_dir,
            size,
            modified,
            modified_ts,
        });
    }

    // Sort directories first, then alphabetically case-insensitively
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    let host_header = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let sec = &state.metrics.security;
    let dl_ticket = if sec.requires_password() {
        client_addr.map(|a| sec.create_client_ticket(a.ip()))
    } else {
        None
    };

    let ctx = UiContext {
        token: state.token.clone(),
        rel_dir: clean_rel.to_string(),
        host_header,
        dl_ticket,
        password_enabled: sec.requires_password(),
        remaining_ttl_secs: sec.remaining_ttl().map(|d| d.as_secs()),
        downloads_used: sec.downloads_used.load(Ordering::Relaxed),
        max_downloads: sec.max_downloads,
        bytes_used: state.metrics.total_bytes_sent.load(Ordering::Relaxed),
        max_bytes: sec.max_bytes,
    };

    let html = render_directory_page(&ctx, &entries);
    Html(html).into_response()
}

/// Serve a recursive uncompressed file manifest (`?manifest=1` / `?manifest=json` or `?manifest=aria2`)
/// so clients and the parallel browser engine can download an entire folder tree directly without compression.
async fn serve_directory_manifest(
    state: &AppState,
    client_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    dir_path: &Path,
    clean_rel: &str,
    format: &str,
) -> Response {
    let raw_files = collect_files_recursively(&state.root_dir, dir_path, state.allow_hidden).await;
    let sec = &state.metrics.security;
    let ticket = if sec.requires_password() {
        client_addr.map(|a| sec.create_client_ticket(a.ip()))
    } else {
        None
    };

    let root_name = if clean_rel.is_empty() {
        state
            .root_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "shared".to_string())
    } else {
        Path::new(clean_rel)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| clean_rel.to_string())
    };

    let mut files = Vec::with_capacity(raw_files.len());
    let mut total_bytes = 0u64;

    for (full_path, rel_within_dir) in raw_files {
        let size = tokio::fs::metadata(&full_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        total_bytes = total_bytes.saturating_add(size);

        let full_rel = if clean_rel.is_empty() {
            rel_within_dir.clone()
        } else {
            format!("{}/{}", clean_rel, rel_within_dir)
        };
        let encoded = format!("/{}/{}", state.token, encode_path_segments(&full_rel));
        let url = match &ticket {
            Some(t) if !t.is_empty() => format!("{}?key={}", encoded, t),
            _ => encoded,
        };

        files.push(ManifestFile {
            path: rel_within_dir,
            url,
            size,
        });
    }

    match format {
        "aria2" => {
            let host = headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("localhost");
            let mut out = String::new();
            for f in &files {
                out.push_str(&format!("http://{}{}\n  out={}\n", host, f.url, f.path));
            }
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .header("X-FastShare-Type", "manifest-aria2")
                .body(Body::from(out))
                .unwrap()
        }
        "1" | "json" => {
            let manifest = FolderManifest {
                root: root_name,
                total_files: files.len(),
                total_bytes,
                files,
            };
            let json = serde_json::to_string(&manifest).unwrap_or_else(|_| "{}".to_string());
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .header("X-FastShare-Type", "manifest-json")
                .body(Body::from(json))
                .unwrap()
        }
        _ => (StatusCode::BAD_REQUEST, "Unsupported manifest format (use 1, json, or aria2)").into_response(),
    }
}

/// High-throughput 10GbE file streaming with HTTP/1.1 & HTTP/2 Range support
async fn serve_file_10g(
    state: &AppState,
    client_addr: Option<SocketAddr>,
    method: Method,
    headers: &HeaderMap,
    file_path: &Path,
    clean_rel: &str,
    file_size: u64,
) -> Response {
    let file_name = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "download.bin".to_string());

    let mime_type = mime_guess::from_path(file_path).first_or_octet_stream();
    let encoded_filename =
        percent_encoding::utf8_percent_encode(&file_name, percent_encoding::NON_ALPHANUMERIC);
    let content_disposition = format!(
        "attachment; filename=\"{}\"; filename*=UTF-8''{}",
        file_name.replace('"', "_"),
        encoded_filename
    );

    // Check Range header for parallel downloader support (aria2c, IDM, curl)
    let mut start_byte: u64 = 0;
    let mut end_byte: u64 = file_size.saturating_sub(1);
    let mut is_range = false;

    if let Some(range_val) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        if file_size == 0 {
            return (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(header::CONTENT_RANGE, "bytes */0")],
                Body::empty(),
            )
                .into_response();
        }
        if let Ok(parsed) = http_range_header::parse_range_header(range_val) {
            if let Ok(ranges) = parsed.validate(file_size) {
                if let Some(first) = ranges.first() {
                    start_byte = *first.start();
                    end_byte = *first.end();
                    is_range = true;
                }
            } else {
                return (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [(header::CONTENT_RANGE, format!("bytes */{}", file_size))],
                    Body::empty(),
                )
                    .into_response();
            }
        }
    }

    let content_length = if file_size == 0 {
        0
    } else {
        end_byte - start_byte + 1
    };

    let status = if is_range {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };

    let mut resp_builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, mime_type.as_ref())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, content_length.to_string())
        .header(header::CONTENT_DISPOSITION, content_disposition);

    if is_range {
        resp_builder = resp_builder.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start_byte, end_byte, file_size),
        );
    }

    if method == Method::HEAD {
        return resp_builder.body(Body::empty()).unwrap();
    }

    let mut file = match File::open(file_path).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Unable to open file").into_response(),
    };

    if start_byte > 0 {
        if file.seek(SeekFrom::Start(start_byte)).await.is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Unable to seek file").into_response();
        }
    }

    let chunk_size = state.chunk_size.max(64 * 1024);
    let guard = state.metrics.start_transfer(
        client_addr,
        clean_rel.to_string(),
        Some(content_length),
        is_range,
    );

    // Stream file in large chunks (default 2 MiB) for minimal syscall overhead at 10GbE
    let stream = futures::stream::unfold(
        (file, content_length, guard, chunk_size),
        |(mut file, mut remaining, guard, chunk_size)| async move {
            if remaining == 0 {
                return None;
            }
            let to_read = (remaining as usize).min(chunk_size);
            let mut buf = vec![0u8; to_read];
            match file.read(&mut buf).await {
                Ok(0) => None,
                Ok(n) => {
                    buf.truncate(n);
                    remaining -= n as u64;
                    guard.record_bytes(n);
                    Some((
                        Ok::<Bytes, std::io::Error>(Bytes::from(buf)),
                        (file, remaining, guard, chunk_size),
                    ))
                }
                Err(e) => Some((Err(e), (file, 0, guard, chunk_size))),
            }
        },
    );

    resp_builder.body(Body::from_stream(stream)).unwrap()
}

/// Collect all files recursively under `dir_path` safely inside `root_dir`
async fn collect_files_recursively(
    root_dir: &Path,
    dir_path: &Path,
    allow_hidden: bool,
) -> Vec<(PathBuf, String)> {
    let mut result = Vec::new();
    let mut stack = vec![dir_path.to_path_buf()];

    while let Some(curr) = stack.pop() {
        let mut rd = match tokio::fs::read_dir(&curr).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !allow_hidden && fname.starts_with('.') {
                continue;
            }
            let path = entry.path();
            let canon = match std::fs::canonicalize(&path) {
                Ok(c) if c.starts_with(root_dir) => c,
                _ => continue,
            };
            let meta = match tokio::fs::metadata(&canon).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(canon);
            } else if meta.is_file() {
                if let Ok(rel) = canon.strip_prefix(dir_path) {
                    let rel_slash = rel
                        .components()
                        .filter_map(|c| match c {
                            Component::Normal(s) => Some(s.to_string_lossy().to_string()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("/");
                    if !rel_slash.is_empty() {
                        result.push((canon, rel_slash));
                    }
                }
            }
        }
    }
    result.sort_by(|a, b| a.1.cmp(&b.1));
    result
}

/// On-the-fly uncompressed (`Compression::Stored`) ZIP archive stream for zero CPU bottleneck at 10GbE
async fn stream_folder_zip(
    state: &AppState,
    client_addr: Option<SocketAddr>,
    dir_path: &Path,
    clean_rel: &str,
) -> Response {
    let archive_name = if clean_rel.is_empty() {
        state
            .root_dir
            .file_name()
            .map(|n| format!("{}.zip", n.to_string_lossy()))
            .unwrap_or_else(|| "shared_folder.zip".to_string())
    } else {
        let base = Path::new(clean_rel)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "folder".to_string());
        format!("{}.zip", base)
    };

    let files = collect_files_recursively(&state.root_dir, dir_path, state.allow_hidden).await;
    let chunk_size = state.chunk_size.max(256 * 1024);
    let guard = state
        .metrics
        .start_transfer(client_addr, format!("{} [ZIP]", archive_name), None, false);

    let (duplex_reader, duplex_writer) = tokio::io::duplex(chunk_size * 2);

    tokio::spawn(async move {
        let mut zip = ZipFileWriter::with_tokio(duplex_writer);
        let mut buf = vec![0u8; chunk_size];

        for (full_path, rel_name) in files {
            let mut file = match File::open(&full_path).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            let builder = ZipEntryBuilder::new(rel_name.into(), Compression::Stored);
            let mut entry_writer = match zip.write_entry_stream(builder).await {
                Ok(w) => w,
                Err(_) => break,
            };
            loop {
                match file.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if futures::AsyncWriteExt::write_all(&mut entry_writer, &buf[..n])
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            if entry_writer.close().await.is_err() {
                return;
            }
        }
        let _ = zip.close().await;
    });

    let reader_stream = ReaderStream::with_capacity(duplex_reader, chunk_size);
    let metered_stream = futures::stream::unfold(
        (reader_stream, guard),
        |(mut rx, guard)| async move {
            use futures::StreamExt;
            match rx.next().await {
                Some(Ok(bytes)) => {
                    guard.record_bytes(bytes.len());
                    Some((Ok::<Bytes, std::io::Error>(bytes), (rx, guard)))
                }
                Some(Err(e)) => Some((Err(e), (rx, guard))),
                None => None,
            }
        },
    );

    let content_disposition = format!(
        "attachment; filename=\"{}\"",
        archive_name.replace('"', "_")
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(header::CONTENT_DISPOSITION, content_disposition)
        .body(Body::from_stream(metered_stream))
        .unwrap()
}

/// On-the-fly streaming TAR archive for zero overhead at 10GbE
async fn stream_folder_tar(
    state: &AppState,
    client_addr: Option<SocketAddr>,
    dir_path: &Path,
    clean_rel: &str,
) -> Response {
    let archive_name = if clean_rel.is_empty() {
        state
            .root_dir
            .file_name()
            .map(|n| format!("{}.tar", n.to_string_lossy()))
            .unwrap_or_else(|| "shared_folder.tar".to_string())
    } else {
        let base = Path::new(clean_rel)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "folder".to_string());
        format!("{}.tar", base)
    };

    let files = collect_files_recursively(&state.root_dir, dir_path, state.allow_hidden).await;
    let chunk_size = state.chunk_size.max(256 * 1024);
    let guard = state
        .metrics
        .start_transfer(client_addr, format!("{} [TAR]", archive_name), None, false);

    let (duplex_reader, duplex_writer) = tokio::io::duplex(chunk_size * 2);

    tokio::spawn(async move {
        let mut tar = tokio_tar::Builder::new(duplex_writer);
        for (full_path, rel_name) in files {
            if let Ok(mut file) = File::open(&full_path).await {
                if tar.append_file(&rel_name, &mut file).await.is_err() {
                    return;
                }
            }
        }
        if let Ok(mut inner) = tar.into_inner().await {
            let _ = inner.shutdown().await;
        }
    });

    let reader_stream = ReaderStream::with_capacity(duplex_reader, chunk_size);
    let metered_stream = futures::stream::unfold(
        (reader_stream, guard),
        |(mut rx, guard)| async move {
            use futures::StreamExt;
            match rx.next().await {
                Some(Ok(bytes)) => {
                    guard.record_bytes(bytes.len());
                    Some((Ok::<Bytes, std::io::Error>(bytes), (rx, guard)))
                }
                Some(Err(e)) => Some((Err(e), (rx, guard))),
                None => None,
            }
        },
    );

    let content_disposition = format!(
        "attachment; filename=\"{}\"",
        archive_name.replace('"', "_")
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-tar")
        .header(header::CONTENT_DISPOSITION, content_disposition)
        .body(Body::from_stream(metered_stream))
        .unwrap()
}
