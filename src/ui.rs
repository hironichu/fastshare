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

fn file_type_label(name: &str, is_dir: bool) -> String {
    if is_dir {
        return "DIR".to_string();
    }
    match name.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() && ext.len() <= 8 => ext.to_ascii_uppercase(),
        _ => "FILE".to_string(),
    }
}

pub fn render_login_page(
    token: &str,
    redirect_path: &str,
    error_msg: Option<&str>,
    remaining_ttl_secs: Option<u64>,
) -> String {
    let error_html = match error_msg {
        Some(msg) => format!(r#"<div class="alert-error">{}</div>"#, html_escape(msg)),
        None => String::new(),
    };

    let ttl_html = match remaining_ttl_secs {
        Some(secs) => format!(
            r#"<div class="meta-row"><span>SESSION TTL</span><span id="login-ttl" data-secs="{secs}">--:--</span></div>"#
        ),
        None => String::new(),
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FastShare — Authentication Required</title>
<style>
  :root {{
    --bg: #0a0a0c;
    --panel: #111114;
    --border: #242429;
    --text: #ededf0;
    --muted: #84848e;
    --accent: #2563eb;
    --danger: #ef4444;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1.5rem;
  }}
  .auth-panel {{
    width: 100%;
    max-width: 380px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2rem;
  }}
  .brand {{
    font-family: var(--mono);
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 0.5rem;
  }}
  h1 {{
    font-size: 1.15rem;
    font-weight: 600;
    margin-bottom: 0.35rem;
  }}
  p.desc {{
    color: var(--muted);
    font-size: 0.85rem;
    margin-bottom: 1.25rem;
  }}
  .meta-row {{
    display: flex;
    justify-content: space-between;
    font-family: var(--mono);
    font-size: 0.76rem;
    color: var(--muted);
    padding: 0.5rem 0.65rem;
    background: #0d0d10;
    border: 1px solid var(--border);
    border-radius: 3px;
    margin-bottom: 1rem;
  }}
  .alert-error {{
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.35);
    color: #f87171;
    padding: 0.6rem 0.75rem;
    border-radius: 3px;
    font-size: 0.82rem;
    margin-bottom: 1rem;
  }}
  label {{
    display: block;
    font-family: var(--mono);
    font-size: 0.74rem;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 0.4rem;
  }}
  input[type="password"] {{
    width: 100%;
    background: #0a0a0c;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 0.6rem 0.75rem;
    border-radius: 3px;
    font-size: 0.9rem;
    font-family: var(--mono);
    outline: none;
    margin-bottom: 1rem;
  }}
  input[type="password"]:focus {{
    border-color: var(--accent);
  }}
  .btn-submit {{
    width: 100%;
    background: var(--text);
    color: var(--bg);
    font-weight: 600;
    font-size: 0.85rem;
    padding: 0.65rem 1rem;
    border: 1px solid var(--text);
    border-radius: 3px;
    cursor: pointer;
  }}
  .btn-submit:hover {{
    opacity: 0.9;
  }}
</style>
</head>
<body>
  <div class="auth-panel">
    <div class="brand">FastShare</div>
    <h1>Authentication Required</h1>
    <p class="desc">Enter the access password for this directory.</p>
    {ttl_html}
    {error_html}
    <form method="POST" action="/{token}/__auth">
      <input type="hidden" name="redirect" value="{redirect}">
      <label for="pw">Password</label>
      <input type="password" id="pw" name="password" required autofocus autocomplete="current-password">
      <button type="submit" class="btn-submit">Authenticate</button>
    </form>
  </div>
<script>
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
        ttl_html = ttl_html,
    )
}

pub fn render_status_page(title: &str, subtitle: &str, code_label: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FastShare — {title}</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
    background: #0a0a0c;
    color: #ededf0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0;
    padding: 1.5rem;
  }}
  .box {{
    max-width: 420px;
    width: 100%;
    background: #111114;
    border: 1px solid #242429;
    border-radius: 4px;
    padding: 1.75rem;
  }}
  .code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.76rem;
    color: #84848e;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 0.4rem;
  }}
  h1 {{ font-size: 1.1rem; font-weight: 600; margin: 0 0 0.45rem; }}
  p {{ color: #84848e; font-size: 0.86rem; line-height: 1.5; margin: 0; }}
</style>
</head>
<body>
  <div class="box">
    <div class="code">FastShare // {code_label}</div>
    <h1>{title}</h1>
    <p>{subtitle}</p>
  </div>
</body>
</html>"#,
        title = html_escape(title),
        subtitle = html_escape(subtitle),
        code_label = html_escape(code_label)
    )
}

pub fn render_directory_page(ctx: &UiContext, entries: &[FileEntry]) -> String {
    let base_prefix = format!("/{}", ctx.token);

    let mut breadcrumbs_html = format!(r#"<a href="{}/" class="crumb">root</a>"#, base_prefix);
    if !ctx.rel_dir.is_empty() {
        let mut accum = String::new();
        for seg in ctx.rel_dir.split('/').filter(|s| !s.is_empty()) {
            if !accum.is_empty() {
                accum.push('/');
            }
            accum.push_str(seg);
            let seg_url = format!("{}/{}/", base_prefix, encode_path_segments(&accum));
            breadcrumbs_html.push_str(&format!(
                r#"<span class="crumb-sep">/</span><a href="{}" class="crumb">{}</a>"#,
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

    let mut telemetry_items = Vec::new();
    telemetry_items.push(format!(
        r#"<div class="stat-item"><span class="stat-label">ITEMS</span><span class="stat-val">{} dir, {} file ({})</span></div>"#,
        total_dirs,
        total_files,
        format_bytes(total_bytes)
    ));

    if let Some(secs) = ctx.remaining_ttl_secs {
        telemetry_items.push(format!(
            r#"<div class="stat-item"><span class="stat-label">TTL</span><span class="stat-val" id="ttl-timer" data-secs="{secs}">--:--</span></div>"#
        ));
    }

    if let Some(max_dl) = ctx.max_downloads {
        let rem = max_dl.saturating_sub(ctx.downloads_used);
        telemetry_items.push(format!(
            r#"<div class="stat-item"><span class="stat-label">DOWNLOAD QUOTA</span><span class="stat-val">{} / {} remaining</span></div>"#,
            rem, max_dl
        ));
    }

    if let Some(max_b) = ctx.max_bytes {
        telemetry_items.push(format!(
            r#"<div class="stat-item"><span class="stat-label">TRANSFER CAP</span><span class="stat-val">{} / {}</span></div>"#,
            format_bytes(ctx.bytes_used),
            format_bytes(max_b)
        ));
    }

    let telemetry_html = telemetry_items.join("");

    let logout_btn = if ctx.password_enabled {
        format!(
            r#"<a href="{}/__logout" class="btn">Logout</a>"#,
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
                <td class="col-name"><a href="{parent_url}" class="item-link">..</a></td>
                <td class="col-type"><span class="type-tag">UP</span></td>
                <td class="col-size">-</td>
                <td class="col-date">-</td>
                <td class="col-actions"></td>
            </tr>"#
        ));
    }

    for entry in entries {
        let escaped_name = html_escape(&entry.name);
        let size_str = if entry.is_dir {
            "-".to_string()
        } else {
            format_bytes(entry.size)
        };
        let type_label = html_escape(&file_type_label(&entry.name, entry.is_dir));
        let ticketed_rel_url = append_ticket(&entry.rel_url, &ctx.dl_ticket);
        let escaped_rel_url = html_escape(&ticketed_rel_url);

        if !entry.is_dir {
            batch_urls_js.push((entry.name.clone(), ticketed_rel_url.clone()));
        }

        let actions_html = if entry.is_dir {
            let folder_zip =
                append_ticket(&format!("{}?archive=zip", entry.rel_url), &ctx.dl_ticket);
            let folder_tar =
                append_ticket(&format!("{}?archive=tar", entry.rel_url), &ctx.dl_ticket);
            format!(
                r#"<a href="{folder_zip}" class="btn btn-sm">.zip</a>
                   <a href="{folder_tar}" class="btn btn-sm">.tar</a>"#
            )
        } else {
            format!(
                r#"<a href="{dl_url}" download class="btn btn-sm btn-primary">Download</a>
                   <button type="button" class="btn btn-sm" data-rel="{escaped_rel_url}" data-name="{escaped_name}" data-size="{file_size}" onclick="handleParallelBtn(this)" title="Concurrent multi-stream browser range transfer">Parallel</button>
                   <button type="button" class="btn btn-sm" data-rel="{escaped_rel_url}" data-name="{escaped_name}" onclick="handleAria2Btn(this, event)" title="Launch in aria2c (via RPC / URI handler) and copy CLI command">aria2c</button>
                   <button type="button" class="btn btn-sm" data-rel="{escaped_rel_url}" onclick="handleCopyLinkBtn(this)" title="Copy direct URL">Copy URL</button>"#,
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
                <td class="col-name"><a href="{url}" class="item-link"><span class="fname">{escaped_name}{slash}</span></a></td>
                <td class="col-type"><span class="type-tag">{type_label}</span></td>
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
            r#"<tr><td colspan="5" class="empty-cell">Directory is empty.</td></tr>"#,
        );
    }

    let batch_json = serde_json::to_string(&batch_urls_js).unwrap_or_else(|_| "[]".to_string());

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FastShare — /{rel_dir}</title>
<style>
  :root {{
    --bg: #0a0a0c;
    --panel: #111114;
    --panel-alt: #16161a;
    --border: #242429;
    --text: #ededf0;
    --muted: #84848e;
    --accent: #2563eb;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.45;
    padding: 1.5rem 1.25rem 4rem;
    min-height: 100vh;
  }}
  .container {{
    max-width: 1280px;
    margin: 0 auto;
  }}
  .header-bar {{
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    padding: 0.9rem 1.15rem;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 0.75rem;
  }}
  .nav-group {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
  }}
  .wordmark {{
    font-family: var(--mono);
    font-weight: 700;
    font-size: 0.85rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text);
    padding-right: 0.75rem;
    border-right: 1px solid var(--border);
  }}
  .breadcrumbs {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.3rem;
    font-family: var(--mono);
    font-size: 0.85rem;
  }}
  .crumb {{
    color: var(--text);
    text-decoration: none;
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
  }}
  .crumb:hover {{
    background: var(--panel-alt);
    text-decoration: underline;
  }}
  .crumb-sep {{ color: var(--muted); }}
  .toolbar {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    align-items: center;
  }}
  .search-input {{
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 0.38rem 0.7rem;
    border-radius: 3px;
    font-size: 0.82rem;
    font-family: var(--mono);
    min-width: 200px;
    outline: none;
  }}
  .search-input:focus {{
    border-color: var(--muted);
  }}
  .telemetry-bar {{
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    padding: 0.55rem 1.15rem;
    background: #0d0d10;
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 0.75rem;
    font-family: var(--mono);
    font-size: 0.76rem;
  }}
  .stat-item {{
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .stat-label {{
    color: var(--muted);
  }}
  .stat-val {{
    color: var(--text);
    font-weight: 500;
  }}
  .btn {{
    display: inline-flex;
    align-items: center;
    background: var(--panel-alt);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 0.38rem 0.7rem;
    border-radius: 3px;
    text-decoration: none;
    font-size: 0.78rem;
    font-family: var(--mono);
    cursor: pointer;
    transition: border-color 0.12s, background 0.12s;
  }}
  .btn:hover {{
    background: #1f1f25;
    border-color: #3f3f48;
  }}
  .btn-primary {{
    background: var(--text);
    color: var(--bg);
    border-color: var(--text);
    font-weight: 600;
  }}
  .btn-primary:hover {{
    background: #d4d4d8;
    border-color: #d4d4d8;
    color: var(--bg);
  }}
  .btn-sm {{
    padding: 0.22rem 0.5rem;
    font-size: 0.74rem;
  }}
  .table-wrap {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    text-align: left;
  }}
  th, td {{
    padding: 0.62rem 1rem;
    border-bottom: 1px solid var(--border);
  }}
  th {{
    font-family: var(--mono);
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    background: #0d0d10;
    user-select: none;
  }}
  th.sortable {{
    cursor: pointer;
  }}
  th.sortable:hover {{
    color: var(--text);
  }}
  tr.row:hover {{
    background: #151519;
  }}
  tr:last-child td {{ border-bottom: none; }}
  .item-link {{
    color: var(--text);
    text-decoration: none;
    font-size: 0.88rem;
  }}
  .item-link:hover .fname {{
    text-decoration: underline;
  }}
  .col-type {{
    width: 90px;
  }}
  .type-tag {{
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--muted);
    background: #0a0a0c;
    border: 1px solid var(--border);
    padding: 0.1rem 0.38rem;
    border-radius: 2px;
  }}
  .col-size, .col-date {{
    font-family: var(--mono);
    color: var(--muted);
    font-size: 0.8rem;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }}
  .col-actions {{
    text-align: right;
    white-space: nowrap;
    display: flex;
    justify-content: flex-end;
    gap: 0.35rem;
  }}
  .empty-cell {{
    text-align: center;
    padding: 2.5rem 1rem;
    font-family: var(--mono);
    font-size: 0.82rem;
    color: var(--muted);
  }}

  /* Parallel Transfer Panel */
  #transfer-hud {{
    display: none;
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    width: 94%;
    max-width: 680px;
    background: var(--panel);
    border: 1px solid #3f3f48;
    border-radius: 4px;
    padding: 1rem 1.2rem;
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.7);
    z-index: 999;
    font-family: var(--mono);
  }}
  #transfer-hud.active {{ display: block; }}
  .hud-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 0.55rem;
  }}
  .hud-title {{
    font-weight: 600;
    font-size: 0.82rem;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 0.6rem;
    word-break: break-all;
  }}
  .hud-mode {{
    font-size: 0.7rem;
    background: #0a0a0c;
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 0.1rem 0.45rem;
    border-radius: 2px;
  }}
  .hud-stats {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    font-size: 0.78rem;
    color: var(--muted);
    margin-bottom: 0.45rem;
    font-variant-numeric: tabular-nums;
  }}
  .hud-speed {{
    font-weight: 600;
    color: var(--text);
  }}
  .progress-track {{
    width: 100%;
    height: 6px;
    background: #0a0a0c;
    border: 1px solid var(--border);
    overflow: hidden;
    margin-bottom: 0.55rem;
  }}
  .progress-fill {{
    height: 100%;
    width: 0%;
    background: var(--text);
    transition: width 0.1s linear;
  }}
  .worker-grid {{
    display: grid;
    grid-template-columns: repeat(16, 1fr);
    gap: 3px;
  }}
  .worker-cell {{
    height: 4px;
    background: #1c1c21;
  }}
  .worker-cell.busy {{
    background: var(--accent);
  }}

  #toast {{
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: var(--panel-alt);
    color: var(--text);
    border: 1px solid #3f3f48;
    font-family: var(--mono);
    padding: 0.55rem 0.95rem;
    border-radius: 3px;
    font-size: 0.78rem;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.15s ease;
    z-index: 1000;
  }}
  #toast.show {{ opacity: 1; }}
</style>
</head>
<body>
<div class="container">
  <div class="header-bar">
    <div class="nav-group">
      <span class="wordmark">FastShare</span>
      <nav class="breadcrumbs">{breadcrumbs_html}</nav>
    </div>
    <div class="toolbar">
      <input type="text" id="filter" class="search-input" placeholder="Filter... (/)" oninput="filterRows(this.value)">
      <a href="{zip_url}" class="btn">Archive (.zip)</a>
      <a href="{tar_url}" class="btn">Archive (.tar)</a>
      <button type="button" class="btn" onclick="copyBatchAria2()">Batch aria2c</button>
      {logout_btn}
    </div>
  </div>

  <div class="telemetry-bar">
    {telemetry_html}
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th class="sortable" onclick="sortTable('name')">Name <span id="sort-name">▲</span></th>
          <th>Type</th>
          <th class="sortable" onclick="sortTable('size')">Size <span id="sort-size"></span></th>
          <th class="sortable" onclick="sortTable('mtime')">Modified <span id="sort-mtime"></span></th>
          <th style="text-align:right">Actions</th>
        </tr>
      </thead>
      <tbody id="file-tbody">
        {rows_html}
      </tbody>
    </table>
  </div>
</div>

<div id="transfer-hud">
  <div class="hud-header">
    <div class="hud-title">
      <span id="hud-filename">Transferring...</span>
      <span id="hud-mode" class="hud-mode">Parallel Range</span>
    </div>
    <button type="button" class="btn btn-sm" onclick="cancelParallelDownload()">Abort</button>
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

<iframe id="proto-loader" style="display:none;"></iframe>
<div id="toast">Copied to clipboard</div>

<script>
const BATCH_FILES = {batch_json};
let sortState = {{ col: 'name', asc: true }};
let activeTransferAbort = null;

function showToast(msg) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2400);
}}

function copyText(txt, msg) {{
  if (navigator.clipboard && window.isSecureContext) {{
    navigator.clipboard.writeText(txt)
      .then(() => showToast(msg || 'Copied to clipboard'))
      .catch(() => fallbackCopy(txt, msg));
  }} else {{
    fallbackCopy(txt, msg);
  }}
}}

function fallbackCopy(txt, msg) {{
  const ta = document.createElement('textarea');
  ta.value = txt;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  ta.style.top = '0';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {{
    const ok = document.execCommand('copy');
    if (ok) {{
      showToast(msg || 'Copied to clipboard');
    }} else {{
      window.prompt('Copy command (Ctrl+C):', txt);
    }}
  }} catch (_) {{
    window.prompt('Copy command (Ctrl+C):', txt);
  }}
  ta.remove();
}}

function handleParallelBtn(btn) {{
  const relUrl = btn.getAttribute('data-rel') || '';
  const name = btn.getAttribute('data-name') || 'download.bin';
  const size = parseInt(btn.getAttribute('data-size') || '0', 10);
  startParallelDownload(relUrl, name, size);
}}

// Triggers aria2c via local JSON-RPC (if running on 127.0.0.1:6800), invokes the registered
// `fastshare://` URI scheme (which executes `aria2c -x 16 -s 16` directly), and copies the
// CLI command to the clipboard as an immediate fallback.
async function handleAria2Btn(btn, evt) {{
  const relUrl = btn.getAttribute('data-rel') || '';
  const name = btn.getAttribute('data-name') || 'download.bin';
  const fullUrl = window.location.origin + relUrl;
  const safeName = name.replace(/"/g, '\\"');
  const cmd = `aria2c -x 16 -s 16 -k 4M --file-allocation=none -o "${{safeName}}" "${{fullUrl}}"`;

  copyText(cmd, `aria2c command copied (${{name}})`);

  // 1. Try local aria2c JSON-RPC daemon (port 6800 or 16800)
  for (const rpcPort of [6800, 16800]) {{
    try {{
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 450);
      const res = await fetch(`http://127.0.0.1:${{rpcPort}}/jsonrpc`, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          jsonrpc: '2.0',
          id: 'fastshare',
          method: 'aria2.addUri',
          params: [[fullUrl], {{ out: name, split: '16', 'max-connection-per-server': '16', 'min-split-size': '4M', 'file-allocation': 'none' }}]
        }}),
        signal: ctrl.signal
      }});
      clearTimeout(timer);
      if (res.ok) {{
        showToast(`Dispatched ${{name}} to local aria2c RPC (:${{rpcPort}})`);
        return;
      }}
    }} catch (_) {{}}
  }}

  // 2. Trigger `fastshare://host:port/path` URI handler (spawns aria2c directly if registered)
  const hostAndPath = window.location.host + relUrl;
  const iframe = document.getElementById('proto-loader');
  if (iframe) {{
    iframe.src = `fastshare://${{hostAndPath}}`;
  }}
}}

function handleCopyLinkBtn(btn) {{
  const relUrl = btn.getAttribute('data-rel') || '';
  const fullUrl = window.location.origin + relUrl;
  copyText(fullUrl, 'URL copied to clipboard');
}}

function copyBatchAria2() {{
  if (!BATCH_FILES.length) {{
    showToast('No files in directory');
    return;
  }}
  const cmds = BATCH_FILES.map(([name, relUrl]) => {{
    const safeName = name.replace(/"/g, '\\"');
    const url = window.location.origin + relUrl;
    return `aria2c -x 16 -s 16 -k 4M --file-allocation=none -o "${{safeName}}" "${{url}}"`;
  }}).join(' && ');
  copyText(cmds, `Batch aria2c command copied (${{BATCH_FILES.length}} files)`);
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

async function resolveShardedOrigins(relUrl) {{
  const host = window.location.hostname;
  const port = window.location.port ? `:${{window.location.port}}` : '';
  const proto = window.location.protocol;
  const ipv4Regex = /^(\d{{1,3}}\.){{3}}\d{{1,3}}$/;

  if (ipv4Regex.test(host) && host !== '127.0.0.1') {{
    const dashed = host.replace(/\./g, '-');
    const testOrigin = `${{proto}}//s1.${{dashed}}.sslip.io${{port}}`;
    try {{
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 1000);
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

function cancelParallelDownload() {{
  if (activeTransferAbort) {{
    activeTransferAbort.abort();
    activeTransferAbort = null;
  }}
  document.getElementById('transfer-hud').classList.remove('active');
  showToast('Transfer aborted');
}}

async function startParallelDownload(relUrl, fileName, totalSize) {{
  if (activeTransferAbort) {{
    showToast('Transfer already in progress');
    return;
  }}
  if (totalSize === 0) {{
    window.location.href = relUrl;
    return;
  }}

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
  activeTransferAbort = abortCtrl;

  const hud = document.getElementById('transfer-hud');
  const hudTitle = document.getElementById('hud-filename');
  const hudMode = document.getElementById('hud-mode');
  const hudProgTxt = document.getElementById('hud-progress-txt');
  const hudSpeed = document.getElementById('hud-speed');
  const hudBar = document.getElementById('hud-bar');
  const workerCells = document.querySelectorAll('#hud-workers .worker-cell');

  hudTitle.textContent = fileName;
  hudBar.style.width = '0%';
  hud.classList.add('active');

  const origins = await resolveShardedOrigins(relUrl);
  const numWorkers = origins.length > 1 ? 16 : 6;
  hudMode.textContent = `${{numWorkers}}x Range Streams`;

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
        completedChunks[nextChunkToWrite] = null;
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
    showToast(`Completed in ${{elapsedSec.toFixed(1)}}s (${{formatSpeedJs(avgBps)}})`);
  }} catch (err) {{
    if (!abortCtrl.signal.aborted) {{
      showToast('Transfer error: ' + (err.message || err));
    }}
    if (fileWritable) {{
      try {{ await fileWritable.abort(); }} catch (_) {{}}
    }}
  }} finally {{
    clearInterval(speedTimer);
    activeTransferAbort = null;
    setTimeout(() => hud.classList.remove('active'), 1500);
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
        telemetry_html = telemetry_html,
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
