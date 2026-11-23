//! Terminal presentation only; JSON and completion streams are never styled.
//!
//! Colours are the Ragbaz design-system roles: ochre (`ink.link` / `edge.focus`)
//! and "Cyrillic blue" (`ink.code` / `status.info`). Night values are used for
//! dark terminals and `RBQ_THEME=ragbaz` selects the printed-object palette.
use clap::builder::styling::{Color, RgbColor, Style};
use serde_json::json;
use std::{
    env,
    io::{self, IsTerminal, Write},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

static COLOR: AtomicBool = AtomicBool::new(false);
static NIGHT: AtomicBool = AtomicBool::new(true);
static VERBOSE: AtomicU8 = AtomicU8::new(0);
static JSON: AtomicBool = AtomicBool::new(false);

const OCHRE_NIGHT: RgbColor = RgbColor(217, 160, 74);
const BLUE_NIGHT: RgbColor = RgbColor(143, 184, 212);
const OCHRE_DAY: RgbColor = RgbColor(122, 75, 18);
const BLUE_DAY: RgbColor = RgbColor(35, 74, 99);
const GOOD_NIGHT: RgbColor = RgbColor(143, 188, 106);
const GOOD_DAY: RgbColor = RgbColor(63, 107, 47);
const WARN_NIGHT: RgbColor = RgbColor(217, 180, 74);
const WARN_DAY: RgbColor = RgbColor(138, 100, 18);

#[derive(Clone, Copy, clap::ValueEnum, Debug, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

/// Read presentation-adjacent flags before Clap parses, so `--help`,
/// `--version` and error output use the same colours and pager as the command.
pub fn prepare(args: &[String]) {
    let mut mode = match env::var("RBQ_COLOR").as_deref() {
        Ok("always") => ColorMode::Always,
        Ok("never") => ColorMode::Never,
        _ => ColorMode::Auto,
    };
    let mut json = false;
    let mut verbose = 0_u8;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--color" => {
                if let Some(value) = iter.next() {
                    mode = parse_color(value).unwrap_or(mode);
                }
            }
            "-v" | "--verbose" => verbose = verbose.saturating_add(1),
            _ if arg.starts_with("--color=") => {
                mode = parse_color(&arg["--color=".len()..]).unwrap_or(mode);
            }
            _ if arg.starts_with('-')
                && arg.len() > 1
                && arg[1..].bytes().all(|byte| byte == b'v') =>
            {
                verbose = verbose.saturating_add((arg.len() - 1) as u8);
            }
            _ => {}
        }
    }
    configure(mode, json, json, verbose);
}

fn parse_color(value: &str) -> Option<ColorMode> {
    match value.to_ascii_lowercase().as_str() {
        "auto" => Some(ColorMode::Auto),
        "always" => Some(ColorMode::Always),
        "never" => Some(ColorMode::Never),
        _ => None,
    }
}

/// `plain` turns colour off (JSON and completion scripts); `json` selects
/// machine-readable help, version and error output.
pub fn configure(mode: ColorMode, plain: bool, json: bool, verbose: u8) {
    let forced = env::var_os("CLICOLOR_FORCE").is_some_and(|value| value != "0");
    let disabled = env::var_os("NO_COLOR").is_some()
        || env::var("CLICOLOR").ok().as_deref() == Some("0")
        || env::var("TERM").ok().as_deref() == Some("dumb");
    let enabled = !plain
        && match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => forced || (io::stdout().is_terminal() && !disabled),
        };
    COLOR.store(enabled, Ordering::Relaxed);
    NIGHT.store(night_theme(), Ordering::Relaxed);
    VERBOSE.store(verbose, Ordering::Relaxed);
    JSON.store(json, Ordering::Relaxed);
}

pub fn json_mode() -> bool {
    JSON.load(Ordering::Relaxed)
}

pub fn verbose_level() -> u8 {
    VERBOSE.load(Ordering::Relaxed)
}

/// Trace goes to stderr and never shares a stream with JSON or completion code.
pub fn trace(level: u8, message: impl AsRef<str>) {
    if verbose_level() >= level {
        eprintln!("{} {}", dim("rbq / trace"), message.as_ref());
    }
}

fn night_theme() -> bool {
    match env::var("RBQ_THEME").as_deref() {
        Ok("ragbaz" | "sepia" | "light") => return false,
        Ok("ragbaz-night" | "night" | "dark") => return true,
        _ => {}
    }
    // COLORFGBG is the one widely available hint: foreground;background.
    if let Ok(value) = env::var("COLORFGBG")
        && let Some(background) = value
            .rsplit(';')
            .next()
            .and_then(|part| part.parse::<u8>().ok())
    {
        return background < 8;
    }
    true
}

fn palette() -> (RgbColor, RgbColor) {
    if NIGHT.load(Ordering::Relaxed) {
        (OCHRE_NIGHT, BLUE_NIGHT)
    } else {
        (OCHRE_DAY, BLUE_DAY)
    }
}

pub fn styles() -> clap::builder::styling::Styles {
    if !COLOR.load(Ordering::Relaxed) {
        return clap::builder::styling::Styles::plain();
    }
    let (ochre, blue) = palette();
    let (good, warn) = if NIGHT.load(Ordering::Relaxed) {
        (GOOD_NIGHT, WARN_NIGHT)
    } else {
        (GOOD_DAY, WARN_DAY)
    };
    let style = |color: RgbColor| Style::new().fg_color(Some(Color::Rgb(color)));
    clap::builder::styling::Styles::styled()
        .header(style(blue).bold())
        .usage(style(ochre).bold())
        .literal(style(ochre).bold())
        .placeholder(style(blue))
        .error(style(RgbColor(224, 112, 95)).bold())
        .valid(style(good))
        .invalid(style(warn))
        .context(style(blue))
}

fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect()
}

fn paint(text: &str, code: &str) -> String {
    let safe = sanitize(text);
    if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[{code}m{safe}\x1b[0m")
    } else {
        safe
    }
}

fn paint_rgb(text: &str, color: RgbColor) -> String {
    let safe = sanitize(text);
    if COLOR.load(Ordering::Relaxed) && !safe.is_empty() {
        format!(
            "\x1b[38;2;{};{};{}m{safe}\x1b[0m",
            color.0, color.1, color.2
        )
    } else {
        safe
    }
}

pub fn blue(text: &str) -> String {
    paint_rgb(text, palette().1)
}
pub fn heading(text: &str) -> String {
    paint_rgb(text, palette().1)
}
pub fn good(text: &str) -> String {
    let color = if NIGHT.load(Ordering::Relaxed) {
        GOOD_NIGHT
    } else {
        GOOD_DAY
    };
    paint_rgb(text, color)
}
pub fn warning(text: &str) -> String {
    let color = if NIGHT.load(Ordering::Relaxed) {
        WARN_NIGHT
    } else {
        WARN_DAY
    };
    paint_rgb(text, color)
}
pub fn dim(text: &str) -> String {
    paint(text, "2")
}

/// A larger RBQ logotype in the Ragbaz roles: R and Q in ochre, B in blue.
/// The glyphs are stable box-drawing characters, not a patched font.
pub fn banner() -> String {
    const LINES: [(&str, &str, &str); 6] = [
        (" ██████╗ ", "██████╗ ", "██████╗ "),
        (" ██╔══██╗", "██╔══██╗", "██╔══██╗"),
        (" ██████╔╝", "██████╔╝", "██║  ██║"),
        (" ██╔══██╗", "██╔══██╗", "██║  ██║"),
        (" ██║  ██║", "██║  ██║", "╚██████╔╝"),
        (" ╚═╝  ╚═╝", "╚═════╝ ", " ╚═════╝ "),
    ];
    let (ochre, blue) = palette();
    let mut lines = Vec::with_capacity(LINES.len() + 1);
    for (r, b, q) in LINES {
        lines.push(format!(
            "{}{}{}",
            paint_rgb(r, ochre),
            paint_rgb(b, blue),
            paint_rgb(q, ochre)
        ));
    }
    lines.push(dim("   preserve · verify · restore"));
    lines.join("\n")
}

pub fn version_text() -> String {
    let features = [
        ("storage", cfg!(feature = "storage")),
        ("peer", cfg!(feature = "peer")),
        ("serve", cfg!(feature = "serve")),
    ]
    .into_iter()
    .filter(|(_, enabled)| *enabled)
    .map(|(name, _)| name)
    .collect::<Vec<_>>()
    .join(", ");
    let target = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
    format!(
        "{}\n\n{}  {}\n{} {}\n{} {}",
        banner(),
        blue("RBQ"),
        env!("CARGO_PKG_VERSION"),
        dim("features:"),
        if features.is_empty() {
            "none"
        } else {
            features.as_str()
        },
        dim("target:"),
        target
    )
}

pub fn print_help(rendered: &str) {
    let text = format!("{}\n\n{}", banner(), rendered.trim_end());
    if json_mode() {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "rbq.cli.help.v1",
                "version": env!("CARGO_PKG_VERSION"),
                "help": rendered,
            }))
            .unwrap_or_default()
        );
        return;
    }
    print_paged(&text);
}

pub fn print_version() {
    let text = version_text();
    if json_mode() {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "rbq.cli.version.v1",
                "name": "rbq",
                "version": env!("CARGO_PKG_VERSION"),
            }))
            .unwrap_or_default()
        );
        return;
    }
    println!("{text}");
}

pub fn print_error(message: &str) {
    if json_mode() {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"status":"error","error":message}))
                .unwrap_or_default()
        );
    } else {
        eprintln!("{} {}", warning("rbq:"), sanitize(message));
    }
}

/// Spawn `$RBQ_PAGER`, then `$PAGER`, then `less -FRX`. Arguments are split
/// without a shell; LESS/LESSCHARSET and friends remain inherited.
pub fn print_paged(text: &str) {
    if !io::stdout().is_terminal() {
        print!("{text}");
        return;
    }
    let pager = env::var("RBQ_PAGER")
        .ok()
        .or_else(|| env::var("PAGER").ok())
        .unwrap_or_else(|| "less -FRX".into());
    let mut parts = split_command(&pager);
    if parts.is_empty() {
        print!("{text}");
        return;
    }
    let program = parts.remove(0);
    match Command::new(program)
        .args(parts)
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
        Err(_) => print!("{text}"),
    }
}

fn split_command(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in value.chars() {
        match (quote, character) {
            (_, '\'' | '"') if quote.is_none() => quote = Some(character),
            (Some(active), closing) if active == closing => quote = None,
            (None, whitespace) if whitespace.is_whitespace() => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

#[cfg(feature = "peer")]
pub fn peer_report(value: &serde_json::Value, code: i32) {
    println!(
        "{}  {}",
        heading("RBQ / PEER"),
        if code == 0 {
            good("OK")
        } else {
            warning("ATTENTION")
        }
    );
    if let Some(layers) = value["layers"].as_object() {
        println!(
            "  {:<12} {:>12} {:>12} {:>14}",
            "LAYER", "SNAPSHOTS", "OBJECTS", "BYTES"
        );
        for (name, layer) in layers {
            println!(
                "  {:<12} {:>12} {:>12} {:>14}",
                name, layer["snapshots"], layer["objects"], layer["bytes"]
            );
        }
    } else if let Some(direction) = value["direction"].as_str() {
        println!(
            "  {} · {} objects · {} bytes",
            heading(direction),
            value["transferred"],
            value["transferred_bytes"]
        );
        println!(
            "  {} already present · {} snapshots verified",
            value["already_present"],
            value["verified"].as_array().map_or(0, Vec::len)
        );
        for field in ["conflicts", "rejected", "verification_failed"] {
            if let Some(items) = value[field].as_array() {
                for item in items {
                    println!(
                        "  {} {}",
                        warning(field),
                        paint(item.as_str().unwrap_or("unknown"), "33")
                    );
                }
            }
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        );
    }
    println!(
        "{}",
        dim(
            "Additive exchange only · no deletion propagation · physical device identity not inferred"
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_controls_in_peer_labels_are_removed() {
        // Do not allow untrusted terminal escape sequences to change titles.
        assert!(!paint("peer\x1b]title\x07", "36").contains('\x07'));
    }

    #[test]
    fn command_splitting_respects_quotes_without_a_shell() {
        assert_eq!(
            split_command("less -FRX -- \"two words\""),
            ["less", "-FRX", "--", "two words"]
        );
    }

    #[test]
    fn banner_uses_both_ragbaz_roles() {
        COLOR.store(true, Ordering::Relaxed);
        NIGHT.store(true, Ordering::Relaxed);
        let banner = banner();
        assert!(banner.contains("\x1b[38;2;217;160;74m"));
        assert!(banner.contains("\x1b[38;2;143;184;212m"));
        COLOR.store(false, Ordering::Relaxed);
    }
}
