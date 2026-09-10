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
    pub raw_processes: Vec<LiveProcessReport>,
    pub processes: Vec<LiveProcessReport>,
    pub table_state: TableState,
    pub filter: String,
    pub is_filtering: bool,
    pub show_tree_view: bool,
    pub active_panel: usize, // 0 = Process List Table, 1 = Process Inspector Panel
    pub detail_scroll: u16,
    pub last_refresh: Instant,
    pub refresh_interval: Duration,
}

impl TuiApp {
    pub fn new(interval_secs: u64) -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Self {
            raw_processes: Vec::new(),
            processes: Vec::new(),
            table_state,
            filter: String::new(),
            is_filtering: false,
            show_tree_view: false,
            active_panel: 0,
            detail_scroll: 0,
            last_refresh: Instant::now() - Duration::from_secs(100), // Force immediate scan on startup
            refresh_interval: Duration::from_secs(interval_secs),
        }
    }

    pub fn fetch_system_processes(&mut self, vt_client: Option<&VtClient>) -> Result<()> {
        self.raw_processes = scan_live_processes(None, None, vt_client)?;
        self.apply_filter_and_sort();
        self.last_refresh = Instant::now();
        Ok(())
    }

    pub fn apply_filter_and_sort(&mut self) {
        let mut filtered: Vec<LiveProcessReport> = if self.filter.is_empty() {
            self.raw_processes.clone()
        } else {
            let query = self.filter.to_lowercase();
            self.raw_processes
                .iter()
                .filter(|p| {
                    p.name.to_lowercase().contains(&query)
                        || p.pid.to_string().contains(&query)
                        || p.exe_path
                            .as_ref()
                            .map(|path| path.to_lowercase().contains(&query))
                            .unwrap_or(false)
                })
                .cloned()
                .collect()
        };

        if !self.show_tree_view {
            // Sort by Risk Score descending in Flat mode
            filtered.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
        }

        self.processes = filtered;

        if self.processes.is_empty() {
            self.table_state.select(None);
        } else if self.table_state.selected().is_none()
            || self.table_state.selected().unwrap() >= self.processes.len()
        {
            self.table_state.select(Some(0));
        }
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
        self.detail_scroll = 0;
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
        self.detail_scroll = 0;
    }

    pub fn scroll_detail_down(&mut self, amount: u16) {
        self.detail_scroll = self.detail_scroll.saturating_add(amount);
    }

    pub fn scroll_detail_up(&mut self, amount: u16) {
        self.detail_scroll = self.detail_scroll.saturating_sub(amount);
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
    app.fetch_system_processes(vt_client.as_ref())?;

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
            let _ = app.fetch_system_processes(vt_client);
        }

        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if app.is_filtering {
                    match key.code {
                        KeyCode::Enter => {
                            app.is_filtering = false;
                        }
                        KeyCode::Esc => {
                            app.is_filtering = false;
                            app.filter.clear();
                            app.apply_filter_and_sort();
                        }
                        KeyCode::Backspace => {
                            app.filter.pop();
                            app.apply_filter_and_sort();
                        }
                        KeyCode::Char(c) => {
                            app.filter.push(c);
                            app.apply_filter_and_sort();
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
                                app.apply_filter_and_sort();
                            }
                        }
                        KeyCode::Char('/') => {
                            app.is_filtering = true;
                        }
                        KeyCode::Char('r') => {
                            let _ = app.fetch_system_processes(vt_client);
                        }
                        KeyCode::Char('t') => {
                            app.show_tree_view = !app.show_tree_view;
                            app.apply_filter_and_sort();
                        }
                        KeyCode::Tab => {
                            app.active_panel = (app.active_panel + 1) % 2;
                        }
                        KeyCode::PageDown | KeyCode::Char('d') => app.scroll_detail_down(5),
                        KeyCode::PageUp | KeyCode::Char('u') => app.scroll_detail_up(5),
                        KeyCode::Down | KeyCode::Char('j') => {
                            if app.active_panel == 1 {
                                app.scroll_detail_down(2);
                            } else {
                                app.next();
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.active_panel == 1 {
                                app.scroll_detail_up(2);
                            } else {
                                app.previous();
                            }
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

    let mode_label = if app.show_tree_view { "PSTree View" } else { "Risk-Sorted View" };

    let header_spans = vec![
        Span::styled(
            " MINTAKA v0.9 ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" Mode: [{}] ", mode_label),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ Total: "),
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
            .title(" Live Process Triage & Parent-Child Execution Tree "),
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

            let display_name = if app.show_tree_view {
                format!("{}{}", p.tree_prefix, p.name)
            } else {
                p.name.clone()
            };

            let exe = p.exe_path.as_deref().unwrap_or("-");

            Row::new(vec![
                p.pid.to_string(),
                display_name,
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

    let title_mode = if app.show_tree_view {
        format!(" Process Execution Tree ({}) ", app.processes.len())
    } else {
        format!(" Processes sorted by Risk ({}) ", app.processes.len())
    };

    let table_border_style = if app.active_panel == 0 {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Cyan)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),  // PID
            Constraint::Length(22), // Name / Tree
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
            "PID", "Process Tree / Name", "Score", "Risk", "Conns", "DLLs", "VT", "Path",
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
            .border_style(table_border_style)
            .title(title_mode),
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

        // Risk Indicators
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

    let inspector_border_style = if app.active_panel == 1 {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Cyan)
    };

    let inspector_title = if app.detail_scroll > 0 {
        format!(" Process Inspector (Line {}) [Tab to switch focus] ", app.detail_scroll + 1)
    } else {
        " Process Inspector [Tab to switch focus] ".to_string()
    };

    let detail_paragraph = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(inspector_border_style)
                .title(inspector_title),
        )
        .scroll((app.detail_scroll, 0))
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
        let focus_label = if app.active_panel == 0 { "Table (Scroll Proc)" } else { "Inspector (Scroll Info)" };
        vec![
            Span::styled(" [q/Esc] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Quit  "),
            Span::styled(" [Tab] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(format!("Focus: {}  ", focus_label), Style::default().fg(Color::Yellow)),
            Span::styled(" [↑/↓/j/k] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Scroll  "),
            Span::styled(" [PgUp/PgDn] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Scroll Detail  "),
            Span::styled(" [t] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(if app.show_tree_view { "Flat View  " } else { "Tree View  " }),
            Span::styled(" [/] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(if app.filter.is_empty() { "Filter  " } else { "Change Filter  " }),
            Span::styled(" [c] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Clear  "),
            Span::styled(" [r] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Refresh  "),
        ]
    };

    let footer = Paragraph::new(Line::from(footer_text)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if app.is_filtering { Color::Yellow } else { Color::DarkGray })),
    );

    f.render_widget(footer, chunks[2]);
}
