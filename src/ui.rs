use crate::metrics::format_bytes;

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub rel_url: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: String,
    pub modified_ts: u64,
}

#[derive(Debug, Clone, Default)]
pub struct UiContext {
    pub token: String,
    pub rel_dir: String,
    pub host_header: String,
    pub dl_ticket: Option<String>,
    pub password_enabled: bool,
    pub remaining_ttl_secs: Option<u64>,
    pub downloads_used: u64,
    pub max_downloads: Option<u64>,
    pub bytes_used: u64,
    pub max_bytes: Option<u64>,
}

fn append_ticket(url: &str, ticket: &Option<String>) -> String {
    match ticket {
        Some(t) if !t.is_empty() => {
            if url.contains('?') {
                format!("{}&key={}", url, t)
            } else {
                format!("{}?key={}", url, t)
            }
        }
        _ => url.to_string(),
    }
}

fn file_icon(name: &str, is_dir: bool) -> &'static str {
    if is_dir {
        return "📁";
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "zip" | "tar" | "gz" | "xz" | "bz2" | "7z" | "rar" | "zst" => "📦",
        "iso" | "img" | "dmg" | "vhd" | "vhdx" | "qcow2" | "vmdk" => "💿",
        "mp4" | "mkv" | "mov" | "avi" | "webm" | "m4v" => "🎬",
        "mp3" | "flac" | "wav" | "ogg" | "aac" | "m4a" => "🎵",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "bmp" | "ico" => "🖼️",
        "pdf" | "doc" | "docx" | "txt" | "md" | "rtf" => "📄",
        "rs" | "py" | "js" | "ts" | "go" | "c" | "cpp" | "h" | "json" | "toml" | "yaml" | "sh"
        | "ps1" => "💻",
        "exe" | "msi" | "deb" | "rpm" | "apk" | "bin" => "⚙️",
        _ => "📄",
    }
}

pub fn render_login_page(
    token: &str,
    redirect_path: &str,
    error_msg: Option<&str>,
    remaining_ttl_secs: Option<u64>,
) -> String {
    let error_html = match error_msg {
        Some(msg) => format!(r#"<div class="alert-error">⚠️ {}</div>"#, html_escape(msg)),
        None => String::new(),
    };

    let ttl_badge = match remaining_ttl_secs {
        Some(secs) => format!(
            r#"<div class="ttl-pill">⏱ Link expires in <span id="login-ttl" data-secs="{secs}">--:--</span></div>"#
        ),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FastShare 10G — Protected Share</title>
<style>
  :root {{
    --bg: #070a0f;
    --card: rgba(22, 27, 34, 0.85);
    --border: rgba(240, 246, 252, 0.12);
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #3b82f6;
    --accent-glow: rgba(59, 130, 246, 0.35);
    --danger: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
    background: radial-gradient(circle at 50% 0%, #111c35 0%, var(--bg) 65%);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1.5rem;
  }}
  .login-card {{
    width: 100%;
    max-width: 420px;
    background: var(--card);
    backdrop-filter: blur(16px);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 2.25rem 2rem;
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
    text-align: center;
  }}
  .lock-icon {{
    width: 56px;
    height: 56px;
    margin: 0 auto 1.1rem;
    border-radius: 14px;
    background: linear-gradient(135deg, rgba(59,130,246,0.2), rgba(16,185,129,0.2));
    border: 1px solid rgba(59,130,246,0.4);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.65rem;
  }}
  h1 {{
    font-size: 1.35rem;
    font-weight: 700;
    margin-bottom: 0.4rem;
  }}
  p.sub {{
    color: var(--muted);
    font-size: 0.9rem;
    margin-bottom: 1.5rem;
  }}
  .ttl-pill {{
    display: inline-block;
    background: rgba(210, 153, 34, 0.12);
    border: 1px solid rgba(210, 153, 34, 0.35);
    color: #e3b341;
    font-size: 0.8rem;
    padding: 0.25rem 0.7rem;
    border-radius: 999px;
    margin-bottom: 1.25rem;
  }}
  .alert-error {{
    background: rgba(248, 81, 73, 0.12);
    border: 1px solid rgba(248, 81, 73, 0.4);
    color: #ff7b72;
    padding: 0.65rem 0.9rem;
    border-radius: 8px;
    font-size: 0.86rem;
    margin-bottom: 1.1rem;
    text-align: left;
  }}
  .input-wrap {{
    position: relative;
    margin-bottom: 1.1rem;
  }}
  input[type="password"], input[type="text"] {{
    width: 100%;
    background: rgba(13, 17, 23, 0.9);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 0.75rem 2.6rem 0.75rem 0.95rem;
    border-radius: 10px;
    font-size: 0.95rem;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
  }}
  input:focus {{
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-glow);
  }}
  .toggle-pw {{
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 1rem;
    padding: 0.2rem;
  }}
  .btn-submit {{
    width: 100%;
    background: linear-gradient(135deg, #2563eb, #10b981);
    color: #fff;
    font-weight: 600;
    font-size: 0.95rem;
    padding: 0.75rem 1rem;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    transition: opacity 0.15s, transform 0.1s;
  }}
  .btn-submit:hover {{ opacity: 0.94; }}
  .btn-submit:active {{ transform: scale(0.99); }}
  .footer-note {{
    margin-top: 1.4rem;
    font-size: 0.78rem;
    color: var(--muted);
  }}
</style>
</head>
<body>
  <div class="login-card">
    <div class="lock-icon">🔒</div>
    <h1>Password Protected Share</h1>
    <p class="sub">Enter the share password to unlock 10GbE direct downloads.</p>
    {ttl_badge}
    {error_html}
    <form method="POST" action="/{token}/__auth">
      <input type="hidden" name="redirect" value="{redirect}">
      <div class="input-wrap">
        <input type="password" id="pw" name="password" placeholder="Enter password..." required autofocus autocomplete="current-password">
        <button type="button" class="toggle-pw" onclick="togglePw()" title="Show/Hide password">👁️</button>
      </div>
      <button type="submit" class="btn-submit">Unlock Folder ⚡</button>
    </form>
    <div class="footer-note">Protected by constant-time HMAC-SHA256 &amp; automatic brute-force IP ban.</div>
  </div>
<script>
function togglePw() {{
  const el = document.getElementById('pw');
  el.type = el.type === 'password' ? 'text' : 'password';
}}
const ttlEl = document.getElementById('login-ttl');
if (ttlEl) {{
  let rem = parseInt(ttlEl.getAttribute('data-secs') || '0', 10);
  const fmt = s => {{
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return h > 0 ? `${{String(h).padStart(2,'0')}}:${{String(m).padStart(2,'0')}}:${{String(sec).padStart(2,'0')}}` : `${{String(m).padStart(2,'0')}}:${{String(sec).padStart(2,'0')}}`;
  }};
  ttlEl.textContent = fmt(rem);
  setInterval(() => {{
    if (rem > 0) {{ rem--; ttlEl.textContent = fmt(rem); }}
    else {{ ttlEl.textContent = 'EXPIRED'; location.reload(); }}
  }}, 1000);
}}
</script>
</body>
</html>"#,
        token = html_escape(token),
        redirect = html_escape(redirect_path),
        error_html = error_html,
        ttl_badge = ttl_badge,
    )
}

pub fn render_status_page(title: &str, subtitle: &str, badge_icon: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FastShare 10G — {title}</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: radial-gradient(circle at 50% 0%, #1a1f2c 0%, #070a0f 70%);
    color: #e6edf3;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0;
    padding: 1.5rem;
  }}
  .box {{
    max-width: 460px;
    background: rgba(22, 27, 34, 0.85);
    border: 1px solid rgba(240, 246, 252, 0.12);
    border-radius: 16px;
    padding: 2.2rem;
    text-align: center;
    box-shadow: 0 20px 50px rgba(0,0,0,0.6);
  }}
  .icon {{ font-size: 2.4rem; margin-bottom: 0.8rem; }}
  h1 {{ font-size: 1.3rem; margin: 0 0 0.5rem; }}
  p {{ color: #8b949e; font-size: 0.92rem; line-height: 1.5; margin: 0; }}
</style>
</head>
<body>
  <div class="box">
    <div class="icon">{badge_icon}</div>
    <h1>{title}</h1>
    <p>{subtitle}</p>
  </div>
</body>
</html>"#,
        title = html_escape(title),
        subtitle = html_escape(subtitle),
        badge_icon = badge_icon
    )
}

pub fn render_directory_page(ctx: &UiContext, entries: &[FileEntry]) -> String {
    let base_prefix = format!("/{}", ctx.token);

    let mut breadcrumbs_html = format!(r#"<a href="{}/" class="crumb">🏠 Root</a>"#, base_prefix);
    if !ctx.rel_dir.is_empty() {
        let mut accum = String::new();
        for seg in ctx.rel_dir.split('/').filter(|s| !s.is_empty()) {
            if !accum.is_empty() {
                accum.push('/');
            }
            accum.push_str(seg);
            let seg_url = format!("{}/{}/", base_prefix, encode_path_segments(&accum));
            breadcrumbs_html.push_str(&format!(
                r#" <span class="crumb-sep">/</span> <a href="{}" class="crumb">{}</a>"#,
                seg_url,
                html_escape(seg)
            ));
        }
    }

    let raw_zip_url = if ctx.rel_dir.is_empty() {
        format!("{}/?archive=zip", base_prefix)
    } else {
        format!(
            "{}/{}?archive=zip",
            base_prefix,
            encode_path_segments(&ctx.rel_dir)
        )
    };
    let raw_tar_url = if ctx.rel_dir.is_empty() {
        format!("{}/?archive=tar", base_prefix)
    } else {
        format!(
            "{}/{}?archive=tar",
            base_prefix,
            encode_path_segments(&ctx.rel_dir)
        )
    };

    let zip_url = append_ticket(&raw_zip_url, &ctx.dl_ticket);
    let tar_url = append_ticket(&raw_tar_url, &ctx.dl_ticket);

    let mut total_files = 0usize;
    let mut total_dirs = 0usize;
    let mut total_bytes = 0u64;
    for e in entries {
        if e.is_dir {
            total_dirs += 1;
        } else {
            total_files += 1;
            total_bytes = total_bytes.saturating_add(e.size);
        }
    }

    let mut status_pills = String::new();
    status_pills.push_str(&format!(
        r#"<span class="pill pill-muted">📁 {} folder{} • 📄 {} file{} ({})</span>"#,
        total_dirs,
        if total_dirs == 1 { "" } else { "s" },
        total_files,
        if total_files == 1 { "" } else { "s" },
        format_bytes(total_bytes)
    ));

    if let Some(secs) = ctx.remaining_ttl_secs {
        status_pills.push_str(&format!(
            r#"<span class="pill pill-warn" title="Link automatically disables and closes UPnP when timer ends">⏱ Expires in: <strong id="ttl-timer" data-secs="{secs}">--:--</strong></span>"#
        ));
    }

    if let Some(max_dl) = ctx.max_downloads {
        let rem = max_dl.saturating_sub(ctx.downloads_used);
        status_pills.push_str(&format!(
            r#"<span class="pill pill-info" title="Remaining logical file downloads allowed">🎯 Downloads left: <strong>{} / {}</strong></span>"#,
            rem, max_dl
        ));
    }

    if let Some(max_b) = ctx.max_bytes {
        status_pills.push_str(&format!(
            r#"<span class="pill pill-info" title="Data transfer quota">📊 Data Quota: <strong>{} / {}</strong></span>"#,
            format_bytes(ctx.bytes_used),
            format_bytes(max_b)
        ));
    }

    let logout_btn = if ctx.password_enabled {
        format!(
            r#"<a href="{}/__logout" class="btn btn-ghost" title="Lock session">🔒 Lock</a>"#,
            base_prefix
        )
    } else {
        String::new()
    };

    let mut rows_html = String::new();
    let mut batch_urls_js = Vec::new();

    if !ctx.rel_dir.is_empty() {
        let parent = match ctx.rel_dir.rfind('/') {
            Some(idx) => &ctx.rel_dir[..idx],
            None => "",
        };
        let parent_url = if parent.is_empty() {
            format!("{}/", base_prefix)
        } else {
            format!("{}/{}/", base_prefix, encode_path_segments(parent))
        };
        rows_html.push_str(&format!(
            r#"<tr class="row parent-row" data-name=".." data-isdir="2" data-size="0" data-mtime="0">
                <td class="col-name"><a href="{parent_url}" class="item-link dir-link"><span class="icon">↩️</span> .. (Parent Folder)</a></td>
                <td class="col-size">—</td>
                <td class="col-date">—</td>
                <td class="col-actions"></td>
            </tr>"#
        ));
    }

    for entry in entries {
        let escaped_name = html_escape(&entry.name);
        let size_str = if entry.is_dir {
            "Folder".to_string()
        } else {
            format_bytes(entry.size)
        };
        let icon = file_icon(&entry.name, entry.is_dir);
        let ticketed_rel_url = append_ticket(&entry.rel_url, &ctx.dl_ticket);
        let full_url = format!("http://{}{}", ctx.host_header, ticketed_rel_url);
        let escaped_full_url = html_escape(&full_url);
        let escaped_rel_url = html_escape(&ticketed_rel_url);

        if !entry.is_dir {
            batch_urls_js.push((entry.name.clone(), full_url.clone()));
        }

        let actions_html = if entry.is_dir {
            let folder_zip =
                append_ticket(&format!("{}?archive=zip", entry.rel_url), &ctx.dl_ticket);
            let folder_tar =
                append_ticket(&format!("{}?archive=tar", entry.rel_url), &ctx.dl_ticket);
            format!(
                r#"<a href="{folder_zip}" class="btn btn-sm" title="Stream folder on-the-fly as uncompressed .zip">📦 .zip</a>
                   <a href="{folder_tar}" class="btn btn-sm" title="Stream folder on-the-fly as .tar">📦 .tar</a>"#
            )
        } else {
            format!(
                r#"<button class="btn btn-sm btn-turbo" onclick="startTurboDownload('{escaped_rel_url}', '{escaped_name}', {file_size})" title="In-Browser 16-Stream Concurrent 10GbE Downloader (No CLI needed!)">🚀 Turbo 16x</button>
                   <a href="{dl_url}" download class="btn btn-sm btn-primary" title="Standard single-stream browser download">⬇ Direct</a>
                   <button class="btn btn-sm btn-accent" onclick="copyAria2('{escaped_full_url}', '{escaped_name}')" title="Copy 16-connection parallel aria2c CLI command">⚡ aria2c</button>
                   <button class="btn btn-sm" onclick="copyText('{escaped_full_url}', 'Direct link copied!')" title="Copy direct URL">🔗</button>"#,
                dl_url = ticketed_rel_url,
                file_size = entry.size
            )
        };

        let browse_href = if entry.is_dir {
            &entry.rel_url
        } else {
            &ticketed_rel_url
        };

        rows_html.push_str(&format!(
            r#"<tr class="row" data-name="{lower_name}" data-isdir="{isdir}" data-size="{size}" data-mtime="{mtime}">
                <td class="col-name"><a href="{url}" class="item-link"><span class="icon">{icon}</span> <span class="fname">{escaped_name}{slash}</span></a></td>
                <td class="col-size">{size_str}</td>
                <td class="col-date">{modified}</td>
                <td class="col-actions">{actions_html}</td>
            </tr>"#,
            lower_name = html_escape(&entry.name.to_lowercase()),
            isdir = if entry.is_dir { 1 } else { 0 },
            size = entry.size,
            mtime = entry.modified_ts,
            url = browse_href,
            slash = if entry.is_dir { "/" } else { "" },
            modified = html_escape(&entry.modified),
        ));
    }

    if entries.is_empty() {
        rows_html.push_str(
            r#"<tr><td colspan="4" class="empty-cell">This folder is empty.</td></tr>"#,
        );
    }

    let batch_json = serde_json::to_string(&batch_urls_js).unwrap_or_else(|_| "[]".to_string());

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FastShare 10G — /{rel_dir}</title>
<style>
  :root {{
    --bg: #070a0f;
    --panel: rgba(22, 27, 34, 0.82);
    --panel-solid: #161b22;
    --border: rgba(240, 246, 252, 0.11);
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #3b82f6;
    --accent-hover: #60a5fa;
    --green: #10b981;
    --green-dark: #059669;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif;
    background: radial-gradient(circle at 50% -10%, #101d38 0%, var(--bg) 60%);
    color: var(--text);
    line-height: 1.5;
    padding: 1.75rem 1rem 4rem;
    min-height: 100vh;
  }}
  .container {{
    max-width: 1260px;
    margin: 0 auto;
  }}
  .top-bar {{
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    padding: 1.15rem 1.4rem;
    background: var(--panel);
    backdrop-filter: blur(14px);
    border: 1px solid var(--border);
    border-radius: 14px;
    margin-bottom: 0.9rem;
    box-shadow: 0 10px 30px rgba(0,0,0,0.35);
  }}
  .brand-area {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
  }}
  .badge-10g {{
    background: linear-gradient(135deg, #2563eb, #10b981);
    color: #fff;
    font-weight: 700;
    font-size: 0.74rem;
    padding: 0.25rem 0.65rem;
    border-radius: 999px;
    letter-spacing: 0.05em;
    box-shadow: 0 0 16px rgba(16, 185, 129, 0.25);
  }}
  .breadcrumbs {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.35rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.96rem;
  }}
  .crumb {{
    color: var(--text);
    text-decoration: none;
    padding: 0.15rem 0.45rem;
    border-radius: 6px;
    transition: background 0.15s, color 0.15s;
  }}
  .crumb:hover {{
    background: rgba(59, 130, 246, 0.16);
    color: var(--accent-hover);
  }}
  .crumb-sep {{ color: var(--muted); }}
  .toolbar {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
  }}
  .search-input {{
    background: rgba(7, 10, 15, 0.8);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 0.48rem 0.85rem;
    border-radius: 8px;
    font-size: 0.86rem;
    min-width: 210px;
    outline: none;
    transition: border-color 0.15s;
  }}
  .search-input:focus {{
    border-color: var(--accent);
  }}
  .status-strip {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.55rem;
    align-items: center;
    margin-bottom: 1rem;
  }}
  .pill {{
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 0.8rem;
    padding: 0.3rem 0.75rem;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: rgba(22, 27, 34, 0.7);
  }}
  .pill-muted {{ color: var(--muted); }}
  .pill-warn {{
    background: rgba(210, 153, 34, 0.12);
    border-color: rgba(210, 153, 34, 0.35);
    color: #e3b341;
  }}
  .pill-info {{
    background: rgba(59, 130, 246, 0.12);
    border-color: rgba(59, 130, 246, 0.35);
    color: #93c5fd;
  }}
  .btn {{
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    background: #21262d;
    color: var(--text);
    border: 1px solid var(--border);
    padding: 0.46rem 0.85rem;
    border-radius: 8px;
    text-decoration: none;
    font-size: 0.83rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s ease;
  }}
  .btn:hover {{
    background: #30363d;
    border-color: rgba(240, 246, 252, 0.28);
  }}
  .btn-primary {{
    background: var(--green-dark);
    border-color: rgba(255,255,255,0.12);
    color: #fff;
  }}
  .btn-primary:hover {{
    background: var(--green);
  }}
  .btn-turbo {{
    background: linear-gradient(135deg, #2563eb, #7c3aed);
    border-color: rgba(139, 92, 246, 0.5);
    color: #fff;
    font-weight: 600;
    box-shadow: 0 2px 10px rgba(124, 58, 237, 0.25);
  }}
  .btn-turbo:hover {{
    background: linear-gradient(135deg, #3b82f6, #8b5cf6);
    border-color: rgba(167, 139, 250, 0.8);
  }}
  .btn-accent {{
    background: rgba(37, 99, 235, 0.22);
    border-color: rgba(59, 130, 246, 0.45);
    color: #93c5fd;
  }}
  .btn-accent:hover {{
    background: rgba(37, 99, 235, 0.38);
    color: #fff;
  }}
  .btn-ghost {{
    background: transparent;
    color: var(--muted);
  }}
  .btn-sm {{
    padding: 0.28rem 0.6rem;
    font-size: 0.78rem;
    border-radius: 6px;
  }}
  .card {{
    background: var(--panel);
    backdrop-filter: blur(14px);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow-x: auto;
    box-shadow: 0 12px 36px rgba(0,0,0,0.4);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    text-align: left;
  }}
  th, td {{
    padding: 0.78rem 1.1rem;
    border-bottom: 1px solid var(--border);
  }}
  th {{
    font-size: 0.76rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    background: rgba(7, 10, 15, 0.45);
    user-select: none;
  }}
  th.sortable {{
    cursor: pointer;
    transition: color 0.15s;
  }}
  th.sortable:hover {{
    color: var(--text);
  }}
  tr.row:hover {{
    background: rgba(59, 130, 246, 0.06);
  }}
  tr:last-child td {{ border-bottom: none; }}
  .item-link {{
    color: var(--text);
    text-decoration: none;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 0.55rem;
  }}
  .item-link:hover .fname {{
    color: var(--accent-hover);
    text-decoration: underline;
  }}
  .icon {{ font-size: 1.08rem; }}
  .col-size, .col-date {{
    color: var(--muted);
    font-size: 0.85rem;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }}
  .col-actions {{
    text-align: right;
    white-space: nowrap;
    display: flex;
    justify-content: flex-end;
    gap: 0.38rem;
  }}
  .empty-cell {{
    text-align: center;
    padding: 3rem 1rem;
    color: var(--muted);
  }}
  .tip-box {{
    margin-top: 1.2rem;
    padding: 1rem 1.3rem;
    background: rgba(37, 99, 235, 0.08);
    border: 1px solid rgba(59, 130, 246, 0.25);
    border-radius: 12px;
    font-size: 0.85rem;
    color: var(--muted);
  }}
  .tip-box code {{
    color: #93c5fd;
    background: rgba(0,0,0,0.4);
    padding: 0.18rem 0.45rem;
    border-radius: 5px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }}

  /* In-Browser 16x Turbo Download HUD */
  #turbo-hud {{
    display: none;
    position: fixed;
    bottom: 22px;
    left: 50%;
    transform: translateX(-50%);
    width: 94%;
    max-width: 720px;
    background: rgba(15, 20, 28, 0.96);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(124, 58, 237, 0.55);
    border-radius: 16px;
    padding: 1.2rem 1.4rem;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.75);
    z-index: 999;
  }}
  #turbo-hud.active {{ display: block; }}
  .hud-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.65rem;
  }}
  .hud-title {{
    font-weight: 700;
    font-size: 0.95rem;
    color: #fff;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    word-break: break-all;
  }}
  .hud-mode {{
    font-size: 0.72rem;
    background: rgba(124, 58, 237, 0.25);
    border: 1px solid rgba(139, 92, 246, 0.5);
    color: #c4b5fd;
    padding: 0.15rem 0.55rem;
    border-radius: 999px;
    white-space: nowrap;
  }}
  .hud-stats {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    font-size: 0.84rem;
    color: var(--muted);
    margin-bottom: 0.45rem;
    font-variant-numeric: tabular-nums;
  }}
  .hud-speed {{
    font-size: 1.05rem;
    font-weight: 700;
    color: #34d399;
  }}
  .progress-track {{
    width: 100%;
    height: 10px;
    background: rgba(255,255,255,0.08);
    border-radius: 999px;
    overflow: hidden;
    margin-bottom: 0.65rem;
  }}
  .progress-fill {{
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, #2563eb, #8b5cf6, #10b981);
    transition: width 0.12s linear;
  }}
  .worker-grid {{
    display: grid;
    grid-template-columns: repeat(16, 1fr);
    gap: 4px;
  }}
  .worker-cell {{
    height: 6px;
    border-radius: 3px;
    background: rgba(255,255,255,0.1);
    transition: background 0.15s;
  }}
  .worker-cell.busy {{
    background: #38bdf8;
    box-shadow: 0 0 8px rgba(56, 189, 248, 0.6);
  }}

  #toast {{
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: linear-gradient(135deg, #059669, #10b981);
    color: #fff;
    font-weight: 500;
    padding: 0.7rem 1.2rem;
    border-radius: 10px;
    font-size: 0.88rem;
    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    opacity: 0;
    transform: translateY(8px);
    pointer-events: none;
    transition: opacity 0.2s ease, transform 0.2s ease;
    z-index: 1000;
  }}
  #toast.show {{
    opacity: 1;
    transform: translateY(0);
  }}
</style>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <div class="brand-area">
      <span class="badge-10g">⚡ 10GbE DIRECT</span>
      <nav class="breadcrumbs">{breadcrumbs_html}</nav>
    </div>
    <div class="toolbar">
      <input type="text" id="filter" class="search-input" placeholder="Search files... (Press /)" oninput="filterRows(this.value)">
      <a href="{zip_url}" class="btn btn-primary" title="Stream entire folder on-the-fly as uncompressed ZIP">📦 Folder (.zip)</a>
      <a href="{tar_url}" class="btn" title="Stream entire folder on-the-fly as TAR">📦 Folder (.tar)</a>
      <button class="btn btn-accent" onclick="copyBatchAria2()" title="Copy a single aria2c command to download all files in this folder at 10GbE">⚡ Batch aria2c</button>
      {logout_btn}
    </div>
  </div>

  <div class="status-strip">
    {status_pills}
  </div>

  <div class="card">
    <table>
      <thead>
        <tr>
          <th class="sortable" onclick="sortTable('name')">Name <span id="sort-name">▲</span></th>
          <th class="sortable" onclick="sortTable('size')">Size <span id="sort-size"></span></th>
          <th class="sortable" onclick="sortTable('mtime')">Modified <span id="sort-mtime"></span></th>
          <th style="text-align:right">10GbE Actions</th>
        </tr>
      </thead>
      <tbody id="file-tbody">
        {rows_html}
      </tbody>
    </table>
  </div>

  <div class="tip-box">
    <strong>🚀 In-Browser 16x Concurrent Engine (`🚀 Turbo 16x`):</strong>
    Click <strong>🚀 Turbo 16x</strong> on any file to launch up to <strong>16 parallel HTTP Range TCP streams</strong> directly inside your browser (striping across wildcard DNS shards when available to bypass browser per-host connection caps) — or use <strong>⚡ aria2c</strong> for massive multi-tens-of-GB archives.
  </div>
</div>

<!-- In-Browser 16x Turbo Download HUD -->
<div id="turbo-hud">
  <div class="hud-header">
    <div class="hud-title">
      <span>🚀</span>
      <span id="hud-filename">Downloading...</span>
      <span id="hud-mode" class="hud-mode">16x Parallel Streams</span>
    </div>
    <button class="btn btn-sm" onclick="cancelTurboDownload()" style="border-color: rgba(248,81,73,0.5); color: #ff7b72;">✖ Cancel</button>
  </div>
  <div class="hud-stats">
    <span id="hud-progress-txt">0.0% (0 B / 0 B)</span>
    <span id="hud-speed" class="hud-speed">0.0 Mbps (0.0 MiB/s)</span>
  </div>
  <div class="progress-track">
    <div id="hud-bar" class="progress-fill"></div>
  </div>
  <div class="worker-grid" id="hud-workers">
    <div class="worker-cell"></div><div class="worker-cell"></div><div class="worker-cell"></div><div class="worker-cell"></div>
    <div class="worker-cell"></div><div class="worker-cell"></div><div class="worker-cell"></div><div class="worker-cell"></div>
    <div class="worker-cell"></div><div class="worker-cell"></div><div class="worker-cell"></div><div class="worker-cell"></div>
    <div class="worker-cell"></div><div class="worker-cell"></div><div class="worker-cell"></div><div class="worker-cell"></div>
  </div>
</div>

<div id="toast">Copied to clipboard!</div>

<script>
const BATCH_FILES = {batch_json};
let sortState = {{ col: 'name', asc: true }};
let activeTurboAbort = null;

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}}

function copyText(txt, msg) {{
  navigator.clipboard.writeText(txt).then(() => showToast(msg || 'Copied to clipboard!'));
}}

function copyAria2(url, name) {{
  const safeName = name.replace(/"/g, '\\"');
  const cmd = `aria2c -x 16 -s 16 -k 4M --file-allocation=none -o "${{safeName}}" "${{url}}"`;
  copyText(cmd, `Copied 16x aria2c command for ${{name}}!`);
}}

function copyBatchAria2() {{
  if (!BATCH_FILES.length) {{
    showToast('No files in current directory to batch download.');
    return;
  }}
  const cmds = BATCH_FILES.map(([name, url]) => {{
    const safeName = name.replace(/"/g, '\\"');
    return `aria2c -x 16 -s 16 -k 4M --file-allocation=none -o "${{safeName}}" "${{url}}"`;
  }}).join(' && ');
  copyText(cmds, `Copied batch aria2c command for ${{BATCH_FILES.length}} file(s)!`);
}}

function formatBytesJs(b) {{
  if (b >= 1099511627776) return (b / 1099511627776).toFixed(2) + ' TiB';
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GiB';
  if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MiB';
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KiB';
  return b + ' B';
}}

function formatSpeedJs(bps) {{
  const bits = bps * 8;
  const mib = bps / 1048576;
  if (bits >= 1e9) return `${{(bits / 1e9).toFixed(2)}} Gbps (${{mib.toFixed(0)}} MiB/s)`;
  return `${{(bits / 1e6).toFixed(1)}} Mbps (${{mib.toFixed(1)}} MiB/s)`;
}}

// Discover whether we can stripe across 4 wildcard DNS origins (s1..s4.<ip-dashed>.sslip.io)
// to bypass the browser's 6-TCP-connections-per-host limit and open 16 real TCP connections!
async function resolveTurboOrigins(relUrl, signal) {{
  const host = window.location.hostname;
  const port = window.location.port ? `:${{window.location.port}}` : '';
  const proto = window.location.protocol;
  const ipv4Regex = /^(\d{{1,3}}\.){{3}}\d{{1,3}}$/;

  if (ipv4Regex.test(host) && host !== '127.0.0.1') {{
    const dashed = host.replace(/\./g, '-');
    const testOrigin = `${{proto}}//s1.${{dashed}}.sslip.io${{port}}`;
    try {{
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 1100);
      const res = await fetch(testOrigin + relUrl, {{
        method: 'HEAD',
        mode: 'cors',
        signal: ctrl.signal
      }});
      clearTimeout(timer);
      if (res.ok || res.status === 206) {{
        return [
          `${{proto}}//s1.${{dashed}}.sslip.io${{port}}`,
          `${{proto}}//s2.${{dashed}}.sslip.io${{port}}`,
          `${{proto}}//s3.${{dashed}}.sslip.io${{port}}`,
          `${{proto}}//s4.${{dashed}}.sslip.io${{port}}`
        ];
      }}
    }} catch (_) {{}}
  }}
  return [window.location.origin];
}}

function cancelTurboDownload() {{
  if (activeTurboAbort) {{
    activeTurboAbort.abort();
    activeTurboAbort = null;
  }}
  document.getElementById('turbo-hud').classList.remove('active');
  showToast('Turbo download cancelled.');
}}

async function startTurboDownload(relUrl, fileName, totalSize) {{
  if (activeTurboAbort) {{
    showToast('A Turbo download is already in progress!');
    return;
  }}
  if (totalSize === 0) {{
    window.location.href = relUrl;
    return;
  }}

  // Try Native FileSystemAccess API (showSaveFilePicker) first for zero-RAM direct disk streaming
  let fileWritable = null;
  if (typeof window.showSaveFilePicker === 'function') {{
    try {{
      const handle = await window.showSaveFilePicker({{ suggestedName: fileName }});
      fileWritable = await handle.createWritable();
    }} catch (err) {{
      if (err && err.name === 'AbortError') return;
      fileWritable = null;
    }}
  }}

  const abortCtrl = new AbortController();
  activeTurboAbort = abortCtrl;

  const hud = document.getElementById('turbo-hud');
  const hudTitle = document.getElementById('hud-filename');
  const hudMode = document.getElementById('hud-mode');
  const hudProgTxt = document.getElementById('hud-progress-txt');
  const hudSpeed = document.getElementById('hud-speed');
  const hudBar = document.getElementById('hud-bar');
  const workerCells = document.querySelectorAll('#hud-workers .worker-cell');

  hudTitle.textContent = fileName;
  hudBar.style.width = '0%';
  hud.classList.add('active');

  const origins = await resolveTurboOrigins(relUrl, abortCtrl.signal);
  const numWorkers = origins.length > 1 ? 16 : 6;
  hudMode.textContent = origins.length > 1
    ? `16x Multi-Origin TCP${{fileWritable ? ' -> Disk' : ''}}`
    : `6x Parallel TCP${{fileWritable ? ' -> Disk' : ''}}`;

  // 8 MiB chunk size for large files, 2 MiB for medium files
  const chunkSize = totalSize >= 64 * 1048576 ? 8 * 1048576 : 2 * 1048576;
  const numChunks = Math.ceil(totalSize / chunkSize);

  const completedChunks = new Array(numChunks);
  let nextChunkToAssign = 0;
  let nextChunkToWrite = 0;
  let isWritingToDisk = false;
  let bytesReceived = 0;
  const startTime = performance.now();
  let lastTickTime = startTime;
  let lastTickBytes = 0;

  const speedTimer = setInterval(() => {{
    const now = performance.now();
    const dt = (now - lastTickTime) / 1000;
    if (dt >= 0.25) {{
      const db = bytesReceived - lastTickBytes;
      const bps = db / dt;
      lastTickTime = now;
      lastTickBytes = bytesReceived;
      hudSpeed.textContent = formatSpeedJs(bps);
    }}
    const pct = Math.min(100, (bytesReceived / totalSize) * 100);
    hudBar.style.width = pct.toFixed(1) + '%';
    hudProgTxt.textContent = `${{pct.toFixed(1)}}% (${{formatBytesJs(bytesReceived)}} / ${{formatBytesJs(totalSize)}})`;
  }}, 200);

  async function flushDiskQueue() {{
    if (!fileWritable || isWritingToDisk) return;
    isWritingToDisk = true;
    try {{
      while (nextChunkToWrite < numChunks && completedChunks[nextChunkToWrite]) {{
        const data = completedChunks[nextChunkToWrite];
        completedChunks[nextChunkToWrite] = null; // Free RAM immediately!
        await fileWritable.write(data);
        nextChunkToWrite++;
      }}
    }} finally {{
      isWritingToDisk = false;
    }}
  }}

  async function runWorker(workerIdx) {{
    const cell = workerCells[workerIdx % workerCells.length];
    while (!abortCtrl.signal.aborted) {{
      // If streaming directly to disk, bound lookahead to 24 chunks to cap RAM usage
      if (fileWritable && (nextChunkToAssign - nextChunkToWrite) >= 24) {{
        await new Promise(r => setTimeout(r, 40));
        continue;
      }}
      const chunkIdx = nextChunkToAssign++;
      if (chunkIdx >= numChunks) break;

      const startByte = chunkIdx * chunkSize;
      const endByte = Math.min(totalSize - 1, startByte + chunkSize - 1);
      const origin = origins[chunkIdx % origins.length];

      if (cell) cell.classList.add('busy');
      try {{
        const resp = await fetch(origin + relUrl, {{
          method: 'GET',
          mode: 'cors',
          headers: {{ 'Range': `bytes=${{startByte}}-${{endByte}}` }},
          signal: abortCtrl.signal
        }});
        if (!resp.ok && resp.status !== 206) {{
          throw new Error(`HTTP ${{resp.status}}`);
        }}

        const reader = resp.body.getReader();
        const expectedLen = endByte - startByte + 1;
        const chunkBuf = new Uint8Array(expectedLen);
        let offset = 0;

        while (true) {{
          const {{ done, value }} = await reader.read();
          if (done) break;
          chunkBuf.set(value, offset);
          offset += value.byteLength;
          bytesReceived += value.byteLength;
        }}

        completedChunks[chunkIdx] = offset === expectedLen ? chunkBuf : chunkBuf.subarray(0, offset);
        if (fileWritable) {{
          await flushDiskQueue();
        }}
      }} finally {{
        if (cell) cell.classList.remove('busy');
      }}
    }}
  }}

  try {{
    const workers = [];
    for (let i = 0; i < Math.min(numWorkers, numChunks); i++) {{
      workers.push(runWorker(i));
    }}
    await Promise.all(workers);

    if (fileWritable) {{
      await flushDiskQueue();
      await fileWritable.close();
    }} else {{
      const blob = new Blob(completedChunks, {{ type: 'application/octet-stream' }});
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
    }}

    const elapsedSec = Math.max(0.01, (performance.now() - startTime) / 1000);
    const avgBps = totalSize / elapsedSec;
    showToast(`Completed in ${{elapsedSec.toFixed(1)}}s @ ${{formatSpeedJs(avgBps)}}!`);
  }} catch (err) {{
    if (!abortCtrl.signal.aborted) {{
      showToast('Turbo download error: ' + (err.message || err));
    }}
    if (fileWritable) {{
      try {{ await fileWritable.abort(); }} catch (_) {{}}
    }}
  }} finally {{
    clearInterval(speedTimer);
    activeTurboAbort = null;
    setTimeout(() => hud.classList.remove('active'), 1800);
  }}
}}

function filterRows(q) {{
  const needle = q.toLowerCase();
  document.querySelectorAll('#file-tbody tr.row').forEach(tr => {{
    if (tr.classList.contains('parent-row')) return;
    const name = tr.getAttribute('data-name') || '';
    tr.style.display = name.includes(needle) ? '' : 'none';
  }});
}}

function sortTable(col) {{
  if (sortState.col === col) {{
    sortState.asc = !sortState.asc;
  }} else {{
    sortState.col = col;
    sortState.asc = col === 'name';
  }}
  ['name', 'size', 'mtime'].forEach(c => {{
    const el = document.getElementById('sort-' + c);
    if (el) el.textContent = sortState.col === c ? (sortState.asc ? '▲' : '▼') : '';
  }});

  const tbody = document.getElementById('file-tbody');
  const rows = Array.from(tbody.querySelectorAll('tr.row'));
  rows.sort((a, b) => {{
    const dirA = parseInt(a.getAttribute('data-isdir') || '0', 10);
    const dirB = parseInt(b.getAttribute('data-isdir') || '0', 10);
    if (dirA !== dirB) return dirB - dirA;

    let cmp = 0;
    if (col === 'name') {{
      cmp = (a.getAttribute('data-name') || '').localeCompare(b.getAttribute('data-name') || '');
    }} else if (col === 'size') {{
      cmp = parseInt(a.getAttribute('data-size') || '0', 10) - parseInt(b.getAttribute('data-size') || '0', 10);
    }} else if (col === 'mtime') {{
      cmp = parseInt(a.getAttribute('data-mtime') || '0', 10) - parseInt(b.getAttribute('data-mtime') || '0', 10);
    }}
    return sortState.asc ? cmp : -cmp;
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

window.addEventListener('keydown', e => {{
  if (e.key === '/' && document.activeElement !== document.getElementById('filter')) {{
    e.preventDefault();
    document.getElementById('filter').focus();
  }}
}});

const ttlEl = document.getElementById('ttl-timer');
if (ttlEl) {{
  let rem = parseInt(ttlEl.getAttribute('data-secs') || '0', 10);
  const fmt = s => {{
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return h > 0 ? `${{String(h).padStart(2,'0')}}:${{String(m).padStart(2,'0')}}:${{String(sec).padStart(2,'0')}}` : `${{String(m).padStart(2,'0')}}:${{String(sec).padStart(2,'0')}}`;
  }};
  ttlEl.textContent = fmt(rem);
  setInterval(() => {{
    if (rem > 0) {{ rem--; ttlEl.textContent = fmt(rem); }}
    else {{ ttlEl.textContent = 'EXPIRED'; }}
  }}, 1000);
}}
</script>
</body>
</html>"#,
        rel_dir = html_escape(&ctx.rel_dir),
        breadcrumbs_html = breadcrumbs_html,
        zip_url = zip_url,
        tar_url = tar_url,
        logout_btn = logout_btn,
        status_pills = status_pills,
        rows_html = rows_html,
        batch_json = batch_json,
    )
}

pub fn encode_path_segments(rel_path: &str) -> String {
    rel_path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            percent_encoding::utf8_percent_encode(seg, percent_encoding::NON_ALPHANUMERIC)
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
