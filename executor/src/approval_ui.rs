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
            (size.ws_col as usize).clamp(12, 100),
            (size.ws_row as usize).clamp(12, 100),
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
    let mut body = String::new();
    for (index, row_index) in component.iter().enumerate() {
        let row = &rows[*row_index];
        let op = &row["operations"][0];
        let path = op["executable"].as_str().unwrap_or("");
        let label = if component.len() == 1 {
            String::new()
        } else {
            format!("[{index}] ")
        };
        body.push_str(&format!("{label}{}", program(path)));
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
            let limit = width.clamp(12, 100).saturating_sub(5).min(68);
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
        if row["queue_state"] != "PENDING_APPROVAL" {
            body.push_str(&format!(
                "State: {}\n",
                render_console_arg(row["queue_state"].as_str().unwrap_or("UNKNOWN"))
            ));
        }
        if details {
            body.push_str("Executor: UID 0 / GID 23012\n");
            body.push_str("More information: exact broker fields (JSON notation)\n");
            // Includes complete path, argv[0], dependencies, IDs, digest and deadlines.
            // JSON escapes newlines; terminal_safe additionally escapes non-ASCII/bidi.
            body.push_str(&terminal_safe(&serde_json::to_string_pretty(row).unwrap()));
            body.push('\n');
        }
        body.push('\n');
    }
    let width = width.clamp(12, 100) - 1;
    let lines: Vec<String> = body
        .lines()
        .flat_map(|line| {
            if line.is_empty() {
                return vec![String::new()];
            }
            // All input is ASCII escaped. Wrap without dropping any byte.
            line.as_bytes()
                .chunks(width)
                .map(|s| String::from_utf8(s.to_vec()).unwrap())
                .collect()
        })
        .collect();
    let count = height.clamp(12, 100).saturating_sub(8).max(1);
    let pages = lines.len().div_ceil(count).max(1);
    let page = page.min(pages - 1);
    let mut output = format!(
        "\nMAYI  /  Permission requested{}\n\n",
        if component.len() > 1 {
            format!(" ({})", component.len())
        } else {
            String::new()
        }
    );
    for line in lines.iter().skip(page * count).take(count) {
        output.push_str(line);
        output.push('\n');
    }
    output.push_str(if details {
        "[Space] Less information\n"
    } else {
        "[Space] More information\n"
    });
    if pages > 1 {
        output.push_str(&format!("Page {}/{}  [ / ] Browse\n", page + 1, pages));
    }
    if details {
        output.push_str("[f] Follow-up  [s] Skip  [0-9] Subset\n");
    }
    output.push_str(if component.len() == 1 {
        "\n[d] Deny   [a] Approve   [q] Quit\nAction + Enter: "
    } else {
        "\n[d] Deny   [a] Approve ALL pending   [q] Quit\nAction + Enter: "
    });
    // Wrap chrome as well as data on narrow terminals. No bytes are hidden.
    output = output
        .lines()
        .flat_map(|line| {
            if line.is_empty() {
                return vec![String::new()];
            }
            line.as_bytes()
                .chunks(width)
                .map(|s| String::from_utf8(s.to_vec()).unwrap())
                .collect()
        })
        .collect::<Vec<_>>()
        .join("\n");
    (output, pages)
}

pub(super) struct View {
    pub details: bool,
    pub page: usize,
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
        let (text, pages) = render(rows, component, self.details, self.page, width, height);
        self.page = self.page.min(pages - 1);
        if visible_screen_clear_supported() {
            let _ = io::stdout().write_all(CLEAR_VISIBLE_SCREEN);
        }
        print!("{text}");
        let _ = io::stdout().flush();
    }
}

pub(super) fn waiting(tick: u64, elapsed: u64) -> String {
    format!(
        "{} Your decision? ({}s)  Action + Enter: ",
        ["|", "/", "-", "\\"][(tick % 4) as usize],
        elapsed
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
            .collect();
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
    fn simple_command_is_one_line_and_executor_stays_in_details() {
        let rows = vec![
            json!({"requester_uid":1000,"queue_state":"PENDING_APPROVAL",
            "operations":[{"type":"exec","executable":"/usr/bin/echo","argv":["echo","hallo"]}]}),
        ];
        let (compact, _) = render(&rows, &[0], false, 0, 80, 24);
        assert!(compact.lines().any(|line| line == "echo hallo"));
        assert!(!compact.contains("-> root"));
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
