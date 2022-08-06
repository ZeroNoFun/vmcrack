use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    error::Error,
    io,
    time::{Duration, Instant},
};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};

use crate::emu::{EmuReport, RegState};
//use unicorn_engine::RegisterX86;

use std::stringify;

struct StatefulList<T> {
    state: ListState,
    items: Vec<T>,
}

impl<T> StatefulList<T> {
    fn with_items(items: Vec<T>) -> StatefulList<T> {
        StatefulList {
            state: ListState::default(),
            items,
        }
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn unselect(&mut self) {
        self.state.select(None);
    }

    fn get_selected(&self) -> usize {
        self.state.selected().unwrap_or(0) as usize
    }
}

/// This struct holds the current state of the app. In particular, it has the `items` field which is a wrapper
/// around `ListState`. Keeping track of the items state let us render the associated widget with its state
/// and have access to features such as natural scrolling.
///
/// Check the event handling at the bottom to see how to change the state on incoming events.
/// Check the drawing logic for items on how to specify the highlighting style for selected items.
pub struct EmuReportApp {
    items: StatefulList<(u32, String, String, RegState)>,
}

impl EmuReportApp {
    pub fn new(emu_report: &EmuReport) -> EmuReportApp {
        EmuReportApp {
            items: StatefulList::with_items(emu_report.report.clone()),
        }
    }

    /// Rotate through the event list.
    /// This only exists to simulate some kind of "progress"
    fn on_tick(&mut self) {}
}

pub fn emu_report(emu_report: EmuReport) -> Result<(), Box<dyn Error>> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let tick_rate = Duration::from_millis(250);
    let app = EmuReportApp::new(&emu_report);
    let res = run_app(&mut terminal, app, tick_rate);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    mut app: EmuReportApp,
    tick_rate: Duration,
) -> io::Result<()> {
    let mut last_tick = Instant::now();
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Left => app.items.unselect(),
                    KeyCode::Down => app.items.next(),
                    KeyCode::Up => app.items.previous(),
                    _ => {}
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut EmuReportApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(f.size());

    let vm_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(25), 
                     Constraint::Percentage(25),
                     Constraint::Percentage(50)].as_ref())
        .split(Rect {
            x: (f.size().width as f32 * 0.35) as u16,
            y: f.size().y,
            width: (f.size().width as f32 * 0.15) as u16,
            height: f.size().height,
        });

    let items: Vec<ListItem> = app
        .items
        .items
        .iter()
        .map(|i| {
            let line = format!("0x{:X} {} {}", i.0, i.1, i.2);
            ListItem::new(line).style(Style::default().fg(Color::White).bg(Color::Black))
        })
        .collect();

    let items = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Instructions"))
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 30, 30))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(items, chunks[0], &mut app.items.state);

    let register_block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black).fg(Color::White))
        .title(Span::styled(
            "Register state",
            Style::default().bg(Color::Black).fg(Color::White),
        ));

    let register_state = app.items.items.get(app.items.get_selected()).unwrap().3.reg;

    use unicorn_engine::RegisterX86::*;
    macro_rules! write_reg_span {
        ($r:expr) => {{
            Spans::from(format!(
                "{}: 0x{:X} ({})",
                stringify!($r),
                register_state[$r as usize],
                register_state[$r as usize]
            ))
        }};
    }

    let register_text = vec![
        write_reg_span!(EAX),
        write_reg_span!(EBX),
        write_reg_span!(ECX),
        write_reg_span!(EDX),
        write_reg_span!(EBP),
        write_reg_span!(ESP),
        write_reg_span!(ESI),
        write_reg_span!(EDI),
        write_reg_span!(EIP),
    ];

    let register_paragraph = Paragraph::new(register_text)
        .style(Style::default().bg(Color::Black).fg(Color::White))
        .block(register_block)
        .alignment(Alignment::Left);

    f.render_widget(register_paragraph, vm_chunks[0]);

    let flag_block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black).fg(Color::White))
        .title(Span::styled(
            "EFLAGS",
            Style::default().bg(Color::Black).fg(Color::White),
        ));

    let flags = register_state[EFLAGS as usize];
    #[allow(non_snake_case)]
    let (ZF, PF, AF, 
         OF, SF, DF,
         CF, TF, IF) = 
        (((flags >> 6) & 1), ((flags >> 2) & 1), ((flags >> 4) & 1),
        ((flags >> 11) & 1), ((flags >> 7) & 1), ((flags >> 10) & 1),
        ((flags >> 0) & 1), ((flags >> 8) & 1), ((flags >> 9) & 1));

    macro_rules! write_flag_span {
            ($f:expr) => {{
                Spans::from(format!(
                    "{}: 0x{:X}",
                    stringify!($f),
                    $f,
                ))
            }};
        }

    let flags_text = vec![
        write_reg_span!(EFLAGS),
        write_flag_span!(ZF),
        write_flag_span!(PF),
        write_flag_span!(AF),
        write_flag_span!(OF),
        write_flag_span!(SF),
        write_flag_span!(DF),
        write_flag_span!(CF),
        write_flag_span!(TF),
        write_flag_span!(IF),
    ];

    let flags_paragraph = Paragraph::new(flags_text)
        .style(Style::default().bg(Color::Black).fg(Color::White))
        .block(flag_block)
        .alignment(Alignment::Left);

    f.render_widget(flags_paragraph, vm_chunks[1]);
}
