use crate::metrics::{format_bytes, format_duration, format_speed_bps, Metrics};
use crate::security::IpRule;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table};
use ratatui::Terminal;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

#[derive(PartialEq, Eq)]
enum InputMode {
    Normal,
    BanIp,
    UnbanIp,
}

pub async fn run_tui(
    metrics: Arc<Metrics>,
    shutdown_tx: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = tui_loop(&mut terminal, &metrics, &shutdown_tx, &mut shutdown_rx).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

async fn tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    metrics: &Arc<Metrics>,
    shutdown_tx: &watch::Sender<bool>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    let tick_rate = Duration::from_millis(200);
    let mut input_mode = InputMode::Normal;
    let mut input_buf = String::new();

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        metrics.tick();

        // Check if TTL timer or download/bytes quota is exhausted
        let active_cnt = metrics.active_count();
        let total_sent = metrics.total_bytes_sent.load(Ordering::Relaxed);
        if let Some(reason) = metrics
            .security
            .check_quota_exhausted(active_cnt, total_sent)
        {
            metrics.log(format!("Auto-closing server & UPnP port: {}", reason));
            let _ = shutdown_tx.send(true);
            break;
        }

        terminal.draw(|f| draw_dashboard(f, metrics, &input_mode, &input_buf))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match input_mode {
                        InputMode::Normal => match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                let _ = shutdown_tx.send(true);
                                break;
                            }
                            KeyCode::Char('c')
                                if key.modifiers.contains(KeyModifiers::CONTROL) =>
                            {
                                let _ = shutdown_tx.send(true);
                                break;
                            }
                            KeyCode::Char('b') => {
                                input_mode = InputMode::BanIp;
                                input_buf.clear();
                            }
                            KeyCode::Char('u') => {
                                input_mode = InputMode::UnbanIp;
                                input_buf.clear();
                            }
                            _ => {}
                        },
                        InputMode::BanIp | InputMode::UnbanIp => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                input_buf.clear();
                            }
                            KeyCode::Enter => {
                                let trimmed = input_buf.trim().to_string();
                                if !trimmed.is_empty() {
                                    if input_mode == InputMode::BanIp {
                                        if let Some(rule) = IpRule::parse(&trimmed) {
                                            let label = rule.display_str();
                                            metrics.security.add_blacklist_rule(rule);
                                            metrics.log(format!(
                                                "Blacklist: Added IP/CIDR rule [{}]",
                                                label
                                            ));
                                        } else {
                                            metrics.log(format!(
                                                "Blacklist error: Invalid IP or CIDR '{}'",
                                                trimmed
                                            ));
                                        }
                                    } else if metrics.security.remove_blacklist_str(&trimmed) {
                                        metrics.log(format!(
                                            "Blacklist: Removed IP/CIDR rule [{}]",
                                            trimmed
                                        ));
                                    } else {
                                        metrics.log(format!(
                                            "Blacklist: Rule '{}' not found",
                                            trimmed
                                        ));
                                    }
                                }
                                input_mode = InputMode::Normal;
                                input_buf.clear();
                            }
                            KeyCode::Backspace => {
                                input_buf.pop();
                            }
                            KeyCode::Char(c) => {
                                input_buf.push(c);
                            }
                            _ => {}
                        },
                    }
                }
            }
        }
    }
    Ok(())
}

fn draw_dashboard(
    f: &mut ratatui::Frame,
    metrics: &Arc<Metrics>,
    input_mode: &InputMode,
    input_buf: &str,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(8), // Share URLs, Security, TTL & UPnP Info
            Constraint::Length(7), // Live Bandwidth + Quotas + Sparkline
            Constraint::Min(7),    // Active Downloads Table
            Constraint::Length(8), // Recent Event Logs / Input Prompt
        ])
        .split(f.area());

    draw_info_panel(f, chunks[0], metrics);
    draw_bandwidth_panel(f, chunks[1], metrics);
    draw_transfers_table(f, chunks[2], metrics);
    draw_logs_panel(f, chunks[3], metrics, input_mode, input_buf);
}

fn draw_info_panel(f: &mut ratatui::Frame, area: Rect, metrics: &Arc<Metrics>) {
    let info = metrics.net_info.read().unwrap().clone();
    let lan_url = format!("http://{}:{}/{}/", info.local_ip, info.port, info.token);
    let wan_url = match &info.public_ip {
        Some(pub_ip) => format!("http://{}:{}/{}/", pub_ip, info.port, info.token),
        None => "Detecting public IP... (or use your WAN IP)".to_string(),
    };

    let sec = &metrics.security;
    let auth_str = if sec.requires_password() {
        "Password + 24-char Token (HMAC-SHA256)"
    } else {
        "24-char Secret Token URL"
    };

    let ttl_str = match sec.remaining_ttl() {
        Some(rem) => format_duration(rem),
        None => "Unlimited".to_string(),
    };

    let bl_list = sec.list_blacklist();
    let bl_summary = if bl_list.is_empty() {
        "0 banned".to_string()
    } else if bl_list.len() <= 3 {
        format!("{} ({})", bl_list.len(), bl_list.join(", "))
    } else {
        format!("{} rules active", bl_list.len())
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" Folder    : ", Style::default().fg(Color::DarkGray)),
            Span::styled(info.shared_dir, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(
                " Public URL: ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                wan_url,
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(" LAN URL   : ", Style::default().fg(Color::Cyan)),
            Span::styled(lan_url, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(" Security  : ", Style::default().fg(Color::DarkGray)),
            Span::styled(auth_str, Style::default().fg(Color::LightMagenta)),
            Span::raw("  |  "),
            Span::styled("TTL: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                ttl_str,
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  "),
            Span::styled("Blacklist: ", Style::default().fg(Color::DarkGray)),
            Span::styled(bl_summary, Style::default().fg(Color::LightRed)),
        ]),
        Line::from(vec![
            Span::styled(" UPnP / NAT: ", Style::default().fg(Color::DarkGray)),
            Span::styled(info.upnp_status, Style::default().fg(Color::Yellow)),
            Span::raw("  |  Keys: "),
            Span::styled(
                "[b]",
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Ban IP  "),
            Span::styled(
                "[u]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Unban  "),
            Span::styled(
                "[q]",
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Quit & Close UPnP"),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            " FastShare — HTTP/2 File Server ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

fn draw_bandwidth_panel(f: &mut ratatui::Frame, area: Rect, metrics: &Arc<Metrics>) {
    let cur_bps = *metrics.current_total_bps.read().unwrap();
    let peak_bps = *metrics.peak_total_bps.read().unwrap();
    let total_sent = metrics.total_bytes_sent.load(Ordering::Relaxed);
    let history: Vec<u64> = metrics
        .speed_history_mbps
        .read()
        .unwrap()
        .iter()
        .copied()
        .collect();

    let sec = &metrics.security;
    let dl_used = sec.downloads_used.load(Ordering::Relaxed);
    let dl_quota_str = match sec.max_downloads {
        Some(max_dl) => format!("{} / {}", dl_used, max_dl),
        None => format!("{} (Unlimited)", dl_used),
    };
    let sent_quota_str = match sec.max_bytes {
        Some(max_b) => format!("{} / {}", format_bytes(total_sent), format_bytes(max_b)),
        None => format_bytes(total_sent),
    };

    let inner_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(48), Constraint::Min(20)])
        .split(area);

    let stats_lines = vec![
        Line::from(vec![
            Span::styled(" Current   : ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_speed_bps(cur_bps),
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Peak      : ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_speed_bps(peak_bps),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Sent      : ", Style::default().fg(Color::DarkGray)),
            Span::styled(sent_quota_str, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(" Downloads : ", Style::default().fg(Color::DarkGray)),
            Span::styled(dl_quota_str, Style::default().fg(Color::LightCyan)),
        ]),
    ];

    let stats_block = Block::default()
        .borders(Borders::ALL)
        .title(" Bandwidth & Quotas ");
    f.render_widget(
        Paragraph::new(stats_lines).block(stats_block),
        inner_chunks[0],
    );

    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Throughput History (Mbps) "),
        )
        .data(&history)
        .style(Style::default().fg(Color::Green));
    f.render_widget(sparkline, inner_chunks[1]);
}

fn draw_transfers_table(f: &mut ratatui::Frame, area: Rect, metrics: &Arc<Metrics>) {
    let transfers = metrics.snapshot_transfers();

    let header = Row::new(vec![
        Cell::from("Client IP"),
        Cell::from("File / Archive"),
        Cell::from("Mode"),
        Cell::from("Progress"),
        Cell::from("Speed"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = transfers
        .into_iter()
        .map(|t| {
            let mode = if t.is_range { "Range" } else { "Stream" };
            let progress = match t.total_size {
                Some(total) if total > 0 => {
                    let pct = ((t.bytes_sent as f64 / total as f64) * 100.0).min(100.0);
                    format!(
                        "{:.1}% ({}/{})",
                        pct,
                        format_bytes(t.bytes_sent),
                        format_bytes(total)
                    )
                }
                _ => format_bytes(t.bytes_sent),
            };
            Row::new(vec![
                Cell::from(t.client_ip),
                Cell::from(t.file_path),
                Cell::from(mode),
                Cell::from(progress),
                Cell::from(format_speed_bps(t.current_bps)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Percentage(42),
        Constraint::Length(8),
        Constraint::Length(26),
        Constraint::Length(24),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default().borders(Borders::ALL).title(format!(
            " Active Connections ({}/{}) ",
            metrics.active_count(),
            metrics.security.max_concurrent
        )),
    );

    f.render_widget(table, area);
}

fn draw_logs_panel(
    f: &mut ratatui::Frame,
    area: Rect,
    metrics: &Arc<Metrics>,
    input_mode: &InputMode,
    input_buf: &str,
) {
    if *input_mode != InputMode::Normal {
        let title = if *input_mode == InputMode::BanIp {
            " Ban IP or CIDR (Enter to confirm, Esc to cancel) "
        } else {
            " Unban IP or CIDR (Enter to confirm, Esc to cancel) "
        };
        let prompt = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    " Target IP / CIDR > ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}_", input_buf),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                " Examples: 203.0.113.42   or   198.51.100.0/24",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::LightRed)),
        );
        f.render_widget(prompt, area);
        return;
    }

    let logs = metrics.logs.read().unwrap();
    let max_lines = area.height.saturating_sub(2) as usize;
    let lines: Vec<Line> = logs
        .iter()
        .rev()
        .take(max_lines)
        .rev()
        .map(|entry| {
            Line::from(vec![
                Span::styled(
                    format!("[{}] ", entry.timestamp),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(entry.message.clone()),
            ])
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Security & Activity Log ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}
