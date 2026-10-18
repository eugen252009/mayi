//! Presentation only. Never resolves executables or changes broker data.
use super::*;

fn preview(text: &str) -> String {
    let escaped = render_console_arg(text);
    if escaped.len() > 100 {
        format!("{} ... [more in details]", &escaped[..100])
    } else {
        escaped
    }
}

fn program(path: &str) -> String {
    // Do not normalize trailing separators or pretend an invalid path is a program.
    if !path.starts_with('/') || path.ends_with('/') {
        return format!("[invalid executable path] {}", preview(path));
    }
    let name = path.rsplit('/').next().unwrap_or("");
    if name == "." || name == ".." || name.is_empty() {
        return "[invalid executable path]".into();
    }
    preview(name)
}

pub(super) fn dimensions() -> (usize, usize) {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0
        && size.ws_col > 0
        && size.ws_row > 0
    {
        (
            (size.ws_col as usize).clamp(12, 120),
            (size.ws_row as usize).clamp(8, 100),
        )
    } else {
        (80, 24)
    }
}

pub(super) fn render(
    rows: &[Value],
    component: &[usize],
    details: bool,
    page: usize,
    width: usize,
    height: usize,
) -> (String, usize) {
    render_with_notice(rows, component, details, page, width, height, false)
}

fn render_with_notice(
    rows: &[Value],
    component: &[usize],
    details: bool,
    page: usize,
    width: usize,
    height: usize,
    notice: bool,
) -> (String, usize) {
    let width = width.clamp(12, 120) - 1;
    let height = height.clamp(8, 100);
    let compact = width < 59 || height < 18;
    let mut body = String::new();
    // Presentation only. Keep the original component index on every row:
    // numeric decisions still bind to the unchanged broker snapshot.
    let mut display: Vec<_> = component.iter().enumerate().collect();
    display.sort_by_key(|(_, i)| rows[**i]["queue_state"] != "PENDING_APPROVAL");
    let pending = component
        .iter()
        .filter(|i| rows[**i]["queue_state"] == "PENDING_APPROVAL")
        .count();
    if component.len() > 1 {
        body.push_str(&format!(
            "{pending} need approval; {} context\n",
            component.len() - pending
        ));
    }
    for (index, row_index) in display {
        let row = &rows[*row_index];
        let op = &row["operations"][0];
        let path = op["executable"].as_str().unwrap_or("");
        if component.len() > 1 {
            body.push_str(&format!("[{index}] "));
        }
        body.push_str(&program(path));
        let basename = path.rsplit('/').next().unwrap_or("");
        let wrapper = [
            "sh", "bash", "dash", "zsh", "fish", "env", "sudo", "su", "busybox", "xargs", "find",
            "perl", "ruby", "node", "php", "lua", "exec",
        ]
        .contains(&basename)
            || basename.starts_with("python");
        let mut custom_argv0 = false;
        if let Some(args) = op["argv"].as_array() {
            let arguments = args
                .iter()
                .skip(1)
                .map(|arg| render_console_arg(arg.as_str().unwrap_or("<invalid>")))
                .collect::<Vec<_>>()
                .join(" ");
            let limit = width.saturating_sub(5).min(68);
            if arguments.len() > limit {
                body.push_str(&format!(" {} ... [more in details]", &arguments[..limit]));
            } else if !arguments.is_empty() {
                body.push_str(&format!(" {arguments}"));
            }
            let argv0 = args.first().and_then(Value::as_str).unwrap_or("");
            custom_argv0 = argv0 != path && argv0 != basename;
        }
        body.push('\n');
        if wrapper {
            body.push_str("Interprets commands or runs other programs\n");
        }
        if custom_argv0 {
            body.push_str("Custom argv[0] -- inspect details\n");
        }
        body.push_str(&format!(
            "Requested by UID {} | One use\n",
            row["requester_uid"]
        ));
        if let Some(expires) = row["expires_at"].as_i64() {
            let seconds = expires.saturating_sub(now()).max(0);
            body.push_str(&format!(
                "Time left at display: {:02}:{:02}\n",
                seconds / 60,
                seconds % 60
            ));
        }
        if row["queue_state"] == "RUNNING" {
            body.push_str("Context: dispatched; start unconfirmed here\n");
        } else if row["queue_state"] != "PENDING_APPROVAL" {
            body.push_str(&format!(
                "Context state: {}\n",
                render_console_arg(row["queue_state"].as_str().unwrap_or("UNKNOWN"))
            ));
        }
        if details {
            body.push_str("More information: exact broker fields (JSON notation)\n");
            body.push_str(&terminal_safe(&serde_json::to_string_pretty(row).unwrap()));
            body.push('\n');
        }
        body.push('\n');
    }
    let wrap = |text: &str| -> Vec<String> {
        text.lines()
            .flat_map(|line| {
                if line.is_empty() {
                    return vec![String::new()];
                }
                line.as_bytes()
                    .chunks(width)
                    .map(|s| String::from_utf8(s.to_vec()).unwrap())
                    .collect()
            })
            .collect()
    };
    let mut header = if compact {
        "MAYI | Exec UID 0 GID 23012".to_owned()
    } else {
        format!(
            "MAYI  /  Permission requested{}\nExecutor: UID 0 / GID 23012",
            if component.len() > 1 {
                format!(" ({})", component.len())
            } else {
                String::new()
            }
        )
    };
    if notice {
        header.push_str("\nQueue changed; s:next set");
    }
    let footer = |current: usize, pages: usize| {
        let mut lines = Vec::new();
        lines.push(
            if compact {
                if details {
                    "Space:less"
                } else {
                    "Space:info"
                }
            } else if details {
                "[Space] Less information"
            } else {
                "[Space] More information"
            }
            .to_owned(),
        );
        if pages > 1 {
            lines.push(format!("Page {}/{}  [ / ]", current + 1, pages));
        }
        if details {
            lines.push(
                if compact {
                    "f:ask s:skip 0-9:subset"
                } else {
                    "[f] Follow-up  [s] Skip  [0-9] Subset"
                }
                .to_owned(),
            );
        }
        lines.push(
            if compact {
                if component.len() == 1 {
                    "a:approve d:deny q:quit"
                } else {
                    "a:ALL pending d:deny q:quit"
                }
            } else if component.len() == 1 {
                "[d] Deny   [a] Approve   [q] Quit"
            } else {
                "[d] Deny   [a] Approve ALL pending   [q] Quit"
            }
            .to_owned(),
        );
        lines.push("Action + Enter: ".to_owned());
        wrap(&lines.join("\n"))
    };
    let lines = wrap(&body);
    let head = wrap(&header);
    // Reserve the fully wrapped chrome INCLUDING worst-case page-number width.
    // Page count cannot exceed the body line count. No content byte is dropped.
    let maximum = lines.len().max(2);
    let count = height
        .saturating_sub(head.len() + footer(maximum - 1, maximum).len())
        .max(1);
    let pages = lines.len().div_ceil(count).max(1);
    let page = page.min(pages - 1);
    let mut output = head;
    output.extend(lines.into_iter().skip(page * count).take(count));
    output.extend(footer(page, pages));
    (output.join("\n"), pages)
}

pub(super) struct View {
    pub details: bool,
    pub page: usize,
    pub notice: bool,
}
impl View {
    pub fn draw(&mut self, rows: &[Value], component: &[usize], key: Option<u8>) {
        match key {
            Some(b' ') => {
                self.details = !self.details;
                self.page = 0;
            }
            Some(b'[') => self.page = self.page.saturating_sub(1),
            Some(b']') => self.page = self.page.saturating_add(1),
            _ => {}
        }
        let (width, height) = dimensions();
        let (text, pages) = if self.notice {
            render_with_notice(
                rows,
                component,
                self.details,
                self.page,
                width,
                height,
                true,
            )
        } else {
            render(rows, component, self.details, self.page, width, height)
        };
        self.page = self.page.min(pages - 1);
        if visible_screen_clear_supported() {
            let _ = io::stdout().write_all(CLEAR_VISIBLE_SCREEN);
        }
        print!("{text}");
        let _ = io::stdout().flush();
    }
}

pub(super) fn waiting(tick: u64, elapsed: u64) -> String {
    let width = dimensions().0.saturating_sub(1);
    let spin = ["|", "/", "-", "\\"][(tick % 4) as usize];
    let text = if width < 60 {
        format!("{spin} Action + Enter ({elapsed}s): ")
    } else {
        format!("{spin} Your decision? ({elapsed}s)  Action + Enter: ")
    };
    text.chars().take(width).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_chrome_and_every_page_fit_supported_terminals() {
        let rows = vec![
            json!({"requester_uid":1000,"queue_state":"PENDING_APPROVAL","expires_at":now()+300,"challenge_id":"a".repeat(48),"request_digest":"b".repeat(64),"operations":[{"type":"exec","executable":"/usr/bin/bash","argv":["bash","-c","x".repeat(1024)+"END\n\u{1b}\u{202e}"]}]}),
        ];
        let original = rows.clone();
        for (width, height) in [(120, 40), (100, 30), (80, 24), (60, 20), (40, 12), (30, 8)] {
            for details in [false, true] {
                let (_, pages) = render(&rows, &[0], details, 0, width, height);
                let mut all = String::new();
                for page in 0..pages {
                    let (text, actual) = render(&rows, &[0], details, page, width, height);
                    assert_eq!(pages, actual);
                    assert!(
                        text.lines().count() <= height,
                        "{width}x{height} page{page}: {text}"
                    );
                    assert!(text.lines().all(|line| line.len() < width));
                    assert!(text.contains("UID 0") && text.contains("23012"));
                    assert!(
                        text.contains("Action + Enter:")
                            && (text.contains("a:approve") || text.contains("[a] Approve"))
                    );
                    assert!(!text.contains('\u{1b}') && text.is_ascii());
                    all.push_str(&text);
                    all.push('\n');
                }
                if details {
                    assert!(
                        all.contains("request_digest")
                            && all.contains("executable")
                            && all.contains("END")
                    );
                }
            }
        }
        assert_eq!(rows, original);
    }
    #[test]
    fn actionable_rows_first_keep_original_component_indices() {
        let mut parent = json!({"requester_uid":1000,"queue_state":"SUCCEEDED","operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]});
        let mut child = parent.clone();
        child["queue_state"] = json!("PENDING_APPROVAL");
        child["operations"][0]["executable"] = json!("/usr/bin/bash");
        child["operations"][0]["argv"] = json!(["bash", "-c", "echo child"]);
        parent["request_id"] = json!("parent");
        let rows = vec![parent, child];
        let before = rows.clone();
        let component = vec![0, 1];
        let text = render(&rows, &component, false, 0, 100, 100).0;
        assert!(text.find("[1] bash").unwrap() < text.find("[0] true").unwrap());
        assert!(
            text.contains("1 need approval; 1 context")
                && text.contains("Context state: SUCCEEDED")
        );
        assert_eq!(component, vec![0, 1]);
        assert_eq!(rows, before);
    }
    #[test]
    fn queue_notice_is_bounded_without_switching_set_or_inventing_start() {
        let rows = vec![
            json!({"requester_uid":1000,"queue_state":"PENDING_APPROVAL","operations":[{"type":"exec","executable":"/usr/bin/bash","argv":["bash","-c","echo hello"]}]}),
            json!({"requester_uid":1000,"queue_state":"RUNNING","operations":[{"type":"exec","executable":"/usr/bin/true","argv":["true"]}]}),
        ];
        let original = rows.clone();
        for (width, height) in [(120, 40), (100, 30), (80, 24), (60, 20), (40, 12), (30, 8)] {
            for details in [false, true] {
                let (_, pages) =
                    render_with_notice(&rows, &[0, 1], details, 0, width, height, true);
                let mut all = String::new();
                for p in 0..pages {
                    let text =
                        render_with_notice(&rows, &[0, 1], details, p, width, height, true).0;
                    assert!(
                        text.lines().count() <= height && text.lines().all(|l| l.len() < width),
                        "{text}"
                    );
                    assert!(
                        text.contains("Queue changed")
                            && text.contains("s:next set")
                            && text.contains("UID 0")
                    );
                    all.push_str(&text);
                    all.push('\n');
                }
                if width >= 80 && height >= 24 {
                    assert!(all.contains("start unconfirmed"));
                }
            }
        }
        assert_eq!(rows, original);
    }
    #[test]
    fn basename_and_escaping() {
        assert_eq!(program("/usr/bin/bash"), "bash");
        assert!(program("/tmp/\x1b[2J\n\u{202e}").is_ascii());
        assert!(!program("/tmp/\x1b[2J\n").contains('\x1b'));
        assert!(!program("/tmp/\x1b[2J\n").contains('\n'));
        assert!(program("/tmp/").contains("invalid"));
        assert!(program("relative").contains("invalid"));
    }
    #[test]
    fn pages_preserve_complete_arguments() {
        let arg = "x".repeat(10000) + "END\n\x1b";
        let rows = vec![
            json!({"requester_uid":1001,"queue_state":"PENDING_APPROVAL","operations":[{"type":"exec","executable":"/usr/bin/bash","argv":["bash","-c",arg]}]}),
        ];
        let (compact, _) = render(&rows, &[0], false, 0, 80, 100);
        assert!(compact.contains("Interprets commands"));
        assert!(!compact.contains("/usr/bin/bash"));
        assert!(compact.contains("more in details"));
        let (_, pages) = render(&rows, &[0], true, 0, 20, 12);
        let all: String = (0..pages)
            .map(|p| render(&rows, &[0], true, p, 20, 12).0)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(all.contains("executable"));
        assert!(!all.contains('\x1b'));
        assert!(all.contains("END"));
        assert!(all.lines().all(|line| line.len() <= 19));
        assert!(pages > 100);
    }
    #[test]
    fn ordinary_request_is_one_short_screen() {
        let rows = vec![json!({
            "requester_uid":1001, "queue_state":"PENDING_APPROVAL",
            "expires_at":now()+300, "request_digest":"a".repeat(64),
            "operations":[{"type":"exec","executable":"/usr/bin/bash",
                "argv":["bash","-c","echo hello"]}]
        })];
        let (text, pages) = render(&rows, &[0], false, 0, 80, 24);
        assert_eq!(pages, 1);
        assert!(text.lines().count() <= 15, "{text}");
        assert!(text.contains("bash -c 'echo hello'"));
        assert!(!text.contains("-> root"));
        assert!(text.contains("-c 'echo hello'"));
        assert!(text.contains("Interprets commands"));
        for noise in [
            "argv[",
            "PENDING_APPROVAL",
            "request_digest",
            "Unix",
            "Page 1/1",
            "/usr/bin/bash",
            "Follow-up",
            "Subset",
            "broker",
        ] {
            assert!(!text.contains(noise), "{noise}: {text}");
        }
        let (expanded, _) = render(&rows, &[0], true, 0, 100, 100);
        assert!(expanded.contains("/usr/bin/bash"));
        assert!(expanded.contains("request_digest"));
    }

    #[test]
    fn simple_command_is_one_line_and_executor_is_always_visible() {
        let rows = vec![
            json!({"requester_uid":1000,"queue_state":"PENDING_APPROVAL",
            "operations":[{"type":"exec","executable":"/usr/bin/echo","argv":["echo","hallo"]}]}),
        ];
        let (compact, _) = render(&rows, &[0], false, 0, 80, 24);
        assert!(compact.lines().any(|line| line == "echo hallo"));
        assert!(!compact.contains("-> root"));
        assert!(compact.contains("Executor: UID 0 / GID 23012"));
        let (details, _) = render(&rows, &[0], true, 0, 100, 100);
        assert!(details.contains("Executor: UID 0 / GID 23012"));
        assert!(details.contains("/usr/bin/echo"));
    }

    #[test]
    fn non_utf8_is_rejected_by_existing_json_representation() {
        assert!(serde_json::from_slice::<Value>(b"{\"path\":\"\xff\"}").is_err());
    }

    #[test]
    fn spinner_is_clock_driven() {
        assert_ne!(waiting(0, 0), waiting(1, 0));
        assert_eq!(waiting(0, 0), waiting(4, 0));
    }
}
