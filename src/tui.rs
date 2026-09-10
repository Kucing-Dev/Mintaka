use crate::live::scan_live_processes;
use crate::types::LiveProcessReport;
use crate::virustotal::VtClient;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Paragraph, Row, Table, TableState, Wrap,
    },
    Terminal,
};
use std::io::stdout;
use std::time::{Duration, Instant};

pub struct TuiApp {
    pub processes: Vec<LiveProcessReport>,
    pub table_state: TableState,
    pub filter: String,
    pub is_filtering: bool,
    pub selected_tab: usize, // 0 = Overview/Processes, 1 = Process Details
    pub last_refresh: Instant,
    pub refresh_interval: Duration,
}

impl TuiApp {
    pub fn new(interval_secs: u64) -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Self {
            processes: Vec::new(),
            table_state,
            filter: String::new(),
            is_filtering: false,
            selected_tab: 0,
            last_refresh: Instant::now() - Duration::from_secs(100), // Force immediate scan
            refresh_interval: Duration::from_secs(interval_secs),
        }
    }

    pub fn refresh_data(&mut self, vt_client: Option<&VtClient>) -> Result<()> {
        let raw_processes = scan_live_processes(None, None, vt_client)?;
        if self.filter.is_empty() {
            self.processes = raw_processes;
        } else {
            let query = self.filter.to_lowercase();
            self.processes = raw_processes
                .into_iter()
                .filter(|p| {
                    p.name.to_lowercase().contains(&query)
                        || p.pid.to_string().contains(&query)
                        || p.exe_path
                            .as_ref()
                            .map(|path| path.to_lowercase().contains(&query))
                            .unwrap_or(false)
                })
                .collect();
        }

        if self.processes.is_empty() {
            self.table_state.select(None);
        } else if self.table_state.selected().is_none()
            || self.table_state.selected().unwrap() >= self.processes.len()
        {
            self.table_state.select(Some(0));
        }

        self.last_refresh = Instant::now();
        Ok(())
    }

    pub fn next(&mut self) {
        if self.processes.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.processes.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn previous(&mut self) {
        if self.processes.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.processes.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }
}

pub fn run_interactive_tui(vt_key: Option<String>, refresh_interval: u64) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let vt_client = vt_key.as_ref().map(|k| VtClient::new(k.clone()));
    let mut app = TuiApp::new(refresh_interval);
    app.refresh_data(vt_client.as_ref())?;

    let res = main_loop(&mut terminal, &mut app, vt_client.as_ref());

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn main_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
    vt_client: Option<&VtClient>,
) -> Result<()> {
    loop {
        if app.last_refresh.elapsed() >= app.refresh_interval {
            let _ = app.refresh_data(vt_client);
        }

        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if app.is_filtering {
                    match key.code {
                        KeyCode::Enter => {
                            app.is_filtering = false;
                            let _ = app.refresh_data(vt_client);
                        }
                        KeyCode::Esc => {
                            app.is_filtering = false;
                            app.filter.clear();
                            let _ = app.refresh_data(vt_client);
                        }
                        KeyCode::Backspace => {
                            app.filter.pop();
                            let _ = app.refresh_data(vt_client);
                        }
                        KeyCode::Char(c) => {
                            app.filter.push(c);
                            let _ = app.refresh_data(vt_client);
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Char('c') => {
                            if key.modifiers.contains(KeyModifiers::CONTROL) {
                                return Ok(());
                            } else {
                                app.filter.clear();
                                let _ = app.refresh_data(vt_client);
                            }
                        }
                        KeyCode::Char('/') => {
                            app.is_filtering = true;
                        }
                        KeyCode::Char('r') => {
                            let _ = app.refresh_data(vt_client);
                        }
                        KeyCode::Down | KeyCode::Char('j') => app.next(),
                        KeyCode::Up | KeyCode::Char('k') => app.previous(),
                        KeyCode::Tab => {
                            app.selected_tab = (app.selected_tab + 1) % 2;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &mut TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title Header
            Constraint::Min(10),  // Main Content (Table + Detail)
            Constraint::Length(3), // Footer Help Bar
        ])
        .split(f.size());

    // 1. Draw Title Header
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for p in &app.processes {
        match p.risk_level.as_str() {
            "HIGH RISK" => high_count += 1,
            "NEEDS REVIEW" => medium_count += 1,
            _ => low_count += 1,
        }
    }

    let header_spans = vec![
        Span::styled(
            " MINTAKA v0.9 ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Interactive Triage Dashboard  │ Total: "),
        Span::styled(
            app.processes.len().to_string(),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ HIGH: "),
        Span::styled(
            high_count.to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ REVIEW: "),
        Span::styled(
            medium_count.to_string(),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ LOW: "),
        Span::styled(
            low_count.to_string(),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
    ];

    let header = Paragraph::new(Line::from(header_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Live Process & Network Triage "),
    );
    f.render_widget(header, chunks[0]);

    // 2. Draw Main Area (Split into Left Table & Right Details)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[1]);

    // Draw Process Table
    let rows: Vec<Row> = app
        .processes
        .iter()
        .map(|p| {
            let (risk_color, risk_text) = match p.risk_level.as_str() {
                "HIGH RISK" => (Color::Red, "HIGH"),
                "NEEDS REVIEW" => (Color::Yellow, "REVIEW"),
                _ => (Color::Green, "LOW"),
            };

            let vt_str = p
                .vt_report
                .as_ref()
                .map(|vt| format!("{}/{}", vt.exe_positives, vt.exe_total))
                .unwrap_or_else(|| "-".to_string());

            let exe = p.exe_path.as_deref().unwrap_or("-");

            Row::new(vec![
                p.pid.to_string(),
                p.name.clone(),
                format!("{:>3}", p.risk_score),
                risk_text.to_string(),
                p.network_connections.len().to_string(),
                p.loaded_dlls.len().to_string(),
                vt_str,
                exe.to_string(),
            ])
            .style(Style::default().fg(risk_color))
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),  // PID
            Constraint::Length(18), // Name
            Constraint::Length(6),  // Score
            Constraint::Length(7),  // Risk Level
            Constraint::Length(6),  // Conns
            Constraint::Length(6),  // DLLs
            Constraint::Length(8),  // VT
            Constraint::Min(20),    // Exe Path
        ],
    )
    .header(
        Row::new(vec![
            "PID", "Name", "Score", "Risk", "Conns", "DLLs", "VT", "Path",
        ])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(format!(" Processes ({}) ", app.processes.len())),
    )
    .highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    f.render_stateful_widget(table, main_chunks[0], &mut app.table_state);

    // Draw Selected Process Details View
    let selected_proc = app
        .table_state
        .selected()
        .and_then(|i| app.processes.get(i));

    let detail_lines = if let Some(p) = selected_proc {
        let mut lines = Vec::new();

        lines.push(Line::from(vec![
            Span::styled("Process: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(&p.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" (PID: {})", p.pid), Style::default().fg(Color::Yellow)),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Path: ", Style::default().fg(Color::Cyan)),
            Span::raw(p.exe_path.as_deref().unwrap_or("-")),
        ]));

        if let Some(ref parent) = p.parent_name {
            lines.push(Line::from(vec![
                Span::styled("Parent: ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{} (PID: {:?})", parent, p.parent_pid.unwrap_or(0))),
            ]));
        }

        lines.push(Line::from(vec![
            Span::styled("Cmdline: ", Style::default().fg(Color::Cyan)),
            Span::raw(p.cmdline.join(" ")),
        ]));

        if let Some(ref st) = p.static_report {
            let sig_span = if st.is_signed {
                Span::styled(
                    format!("Signed ({})", st.signature_publisher.as_deref().unwrap_or("Valid")),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("Un-signed / No Digital Signature", Style::default().fg(Color::DarkGray))
            };
            lines.push(Line::from(vec![
                Span::styled("Signature: ", Style::default().fg(Color::Cyan)),
                sig_span,
            ]));
        }

        lines.push(Line::from(vec![
            Span::styled("Risk Score: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{}/100 [{}]", p.risk_score, p.risk_level),
                match p.risk_level.as_str() {
                    "HIGH RISK" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    "NEEDS REVIEW" => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    _ => Style::default().fg(Color::Green),
                },
            ),
        ]));

        lines.push(Line::from(""));

        // Indicators
        lines.push(Line::from(Span::styled(
            "── Risk Indicators ──",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )));

        if p.indicators.is_empty() {
            lines.push(Line::from(Span::raw("  (No suspicious indicators detected)")));
        } else {
            for ind in &p.indicators {
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(Color::Red)),
                    Span::raw(ind),
                ]));
            }
        }

        lines.push(Line::from(""));

        // Network Connections with IP Intelligence & Reverse DNS
        lines.push(Line::from(Span::styled(
            "── Active Network Sockets & IP Intelligence ──",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));

        if p.network_connections.is_empty() {
            lines.push(Line::from(Span::raw("  (No active network sockets)")));
        } else {
            for conn in &p.network_connections {
                let mut conn_spans = vec![
                    Span::styled("  • ", Style::default().fg(Color::Cyan)),
                    Span::styled(format!("[{}] ", conn.protocol), Style::default().fg(Color::Yellow)),
                    Span::raw(format!("{} ──> {}:{}", conn.local_addr, conn.remote_ip, conn.remote_port)),
                ];

                if let Some(ref host) = conn.remote_hostname {
                    conn_spans.push(Span::styled(format!(" ({})", host), Style::default().fg(Color::Green)));
                }

                if let Some(ref rep) = conn.vt_reputation {
                    if let Some(ref country) = rep.country {
                        conn_spans.push(Span::styled(format!(" [{}]", country), Style::default().fg(Color::Magenta)));
                    }
                    if let Some(ref owner) = rep.owner {
                        conn_spans.push(Span::styled(format!(" ({})", owner), Style::default().fg(Color::DarkGray)));
                    }
                    if rep.malicious_votes > 0 {
                        conn_spans.push(Span::styled(
                            format!(" [VT: {} FLAGGED]", rep.malicious_votes),
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ));
                    }
                }

                lines.push(Line::from(conn_spans));
            }
        }

        lines.push(Line::from(""));

        // Loaded Modules / DLL Tree View
        lines.push(Line::from(Span::styled(
            "── Loaded Modules / DLL Tree Hierarchy ──",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));

        if p.loaded_dlls.is_empty() {
            lines.push(Line::from(Span::raw("  (No extra loaded modules detected)")));
        } else {
            // Group modules by parent directory
            let mut grouped: std::collections::BTreeMap<String, Vec<&crate::types::LoadedModule>> = std::collections::BTreeMap::new();
            for dll in &p.loaded_dlls {
                let dir = std::path::Path::new(&dll.path)
                    .parent()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "/".to_string());
                grouped.entry(dir).or_default().push(dll);
            }

            for (dir, modules) in grouped.iter().take(6) {
                let is_susp_dir = modules.iter().any(|m| m.is_suspicious_location);
                let dir_style = if is_susp_dir {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Yellow)
                };

                let dir_flag = if is_susp_dir { " ⚠️ [SUSPICIOUS LOCATION]" } else { "" };
                lines.push(Line::from(vec![
                    Span::styled(format!(" 📁 {}/{}", dir, dir_flag), dir_style),
                    Span::styled(format!(" ({} modules)", modules.len()), Style::default().fg(Color::DarkGray)),
                ]));

                for (idx, mod_item) in modules.iter().enumerate() {
                    let is_last = idx == modules.len() - 1;
                    let tree_prefix = if is_last { "    └── " } else { "    ├── " };

                    let hash_str = mod_item.sha256.as_deref().map(|h| format!(" [{}]", &h[..12])).unwrap_or_default();

                    let sig_flag = if mod_item.is_unsigned_in_system_dir {
                        Span::styled(" [UNSIGNED SYSTEM DLL]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                    } else if mod_item.is_signed {
                        Span::styled(format!(" [{}]", mod_item.signature_publisher.as_deref().unwrap_or("Signed")), Style::default().fg(Color::Green))
                    } else {
                        Span::raw("")
                    };

                    lines.push(Line::from(vec![
                        Span::styled(tree_prefix, Style::default().fg(Color::DarkGray)),
                        Span::styled(&mod_item.name, Style::default().fg(Color::White)),
                        Span::styled(hash_str, Style::default().fg(Color::DarkGray)),
                        sig_flag,
                    ]));
                }
            }
        }

        lines
    } else {
        vec![Line::from("Select a process to view details")]
    };

    let detail_paragraph = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Process Inspector "),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(detail_paragraph, main_chunks[1]);

    // 3. Draw Footer Help Bar / Filter Input
    let footer_text = if app.is_filtering {
        vec![
            Span::styled(" FILTER SEARCH: ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" {}_", app.filter), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("  (Press Enter to submit, Esc to cancel)", Style::default().fg(Color::DarkGray)),
        ]
    } else {
        vec![
            Span::styled(" [q/Esc] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Quit  "),
            Span::styled(" [↑/↓/j/k] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Navigate  "),
            Span::styled(" [/] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(if app.filter.is_empty() { "Filter  " } else { "Change Filter  " }),
            Span::styled(" [c] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Clear Filter  "),
            Span::styled(" [r] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Refresh  "),
            if !app.filter.is_empty() {
                Span::styled(format!("│ Active Filter: \"{}\"", app.filter), Style::default().fg(Color::Yellow))
            } else {
                Span::raw("")
            },
        ]
    };

    let footer = Paragraph::new(Line::from(footer_text)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if app.is_filtering { Color::Yellow } else { Color::DarkGray })),
    );

    f.render_widget(footer, chunks[2]);
}
