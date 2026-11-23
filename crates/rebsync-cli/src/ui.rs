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

// Used by the storage-only binaries report.
#[cfg_attr(not(feature = "storage"), allow(dead_code))]
pub fn ochre(text: &str) -> String {
    paint_rgb(text, palette().0)
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

/// Short reports print directly; long ones go through the user's pager.
#[cfg_attr(not(feature = "storage"), allow(dead_code))]
pub fn print_maybe_paged(text: &str) {
    if text.lines().count() > 24 {
        print_paged(text);
    } else {
        print!("{text}");
    }
}

/// Clear between `--watch` frames without polluting redirected output.
#[cfg_attr(not(feature = "storage"), allow(dead_code))]
pub fn clear_screen() -> &'static str {
    if io::stdout().is_terminal() {
        "\x1b[2J\x1b[H"
    } else {
        "\n--- rbq status ---\n"
    }
}

#[cfg_attr(not(feature = "storage"), allow(dead_code))]
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg_attr(not(feature = "storage"), allow(dead_code))]
fn progress_bar(percent: f64, width: usize) -> String {
    let filled = ((percent.clamp(0.0, 100.0) / 100.0) * width as f64).round() as usize;
    format!(
        "{}{}",
        ochre(&"█".repeat(filled)),
        dim(&"░".repeat(width.saturating_sub(filled)))
    )
}

#[cfg_attr(not(feature = "storage"), allow(dead_code))]
fn padded(text: &str, width: usize) -> String {
    format!("{:<width$}", sanitize(text))
}

#[cfg_attr(not(feature = "storage"), allow(dead_code))]
fn state_text(state: &str) -> String {
    match state {
        "synced" => good(state),
        "attention" | "incomplete" | "unavailable" | "mirror-pending" | "out-of-sync" => {
            warning(state)
        }
        "empty" | "local-only" | "unshared" | "unknown" => ochre(state),
        "disabled" => dim(state),
        _ => sanitize(state),
    }
}

/// Stable, coloured status table. The layout is intentionally deterministic so
/// it reads well both once through a pager and under `watch`/`--watch`.
#[cfg_attr(not(feature = "storage"), allow(dead_code))]
pub fn render_status(value: &serde_json::Value, detail: u8) -> String {
    let overall = &value["overall"];
    let state = overall["state"].as_str().unwrap_or("unknown");
    let pending = overall["pending_bytes"].as_u64().unwrap_or(0);
    let progress = overall["progress"].as_f64().unwrap_or(100.0);
    let mut lines = Vec::new();

    lines.push(format!(
        "{}  {}",
        heading("RBQ / STATUS"),
        state_text(state)
    ));
    lines.push(format!(
        "  {} {:>5.1}%   {} {}   {} {}",
        progress_bar(progress, 20),
        progress,
        dim("occupied"),
        human_bytes(overall["occupied_bytes"].as_u64().unwrap_or(0)),
        dim("pending"),
        human_bytes(pending)
    ));
    lines.push(format!(
        "  {} {}  ·  {} {}  ·  {} {}",
        dim("logical"),
        human_bytes(overall["logical_bytes"].as_u64().unwrap_or(0)),
        dim("synced"),
        overall["synced"],
        dim("attention"),
        overall["attention"]
    ));
    lines.push(String::new());
    lines.push(format!(
        "  {} {} {} {} {} {} {}",
        padded("LAYER", 11),
        padded("STATE", 15),
        padded("MIRROR", 15),
        padded("SNAPSHOTS", 9),
        padded("STORED", 11),
        padded("PENDING", 11),
        "PROGRESS"
    ));

    if let Some(layers) = value["layers"].as_array() {
        for layer in layers {
            let stats = &layer["stats"];
            let snapshots = stats["snapshots"].as_u64().map(|n| n.to_string());
            let stored = stats["stored_bytes"]
                .as_u64()
                .map(human_bytes)
                .unwrap_or_else(|| "-".into());
            let missing = stats["missing_bytes"]
                .as_u64()
                .map(human_bytes)
                .unwrap_or_else(|| "-".into());
            let layer_progress = layer["progress"].as_f64().unwrap_or(100.0);
            let name = layer["layer"].as_str().unwrap_or("?");
            let state = layer["state"].as_str().unwrap_or("unknown");
            let mirror = layer["mirror"].as_str().unwrap_or("not-configured");
            lines.push(format!(
                "  {} {} {} {} {} {} {} {:.0}%",
                ochre(&padded(name, 11)),
                state_text(&padded(state, 15)),
                blue(&padded(mirror, 15)),
                padded(snapshots.as_deref().unwrap_or("-"), 9),
                padded(&stored, 11),
                padded(&missing, 11),
                progress_bar(layer_progress, 10),
                layer_progress
            ));
            if detail >= 1 {
                if let Some(reason) = layer["reason"].as_str()
                    && !reason.is_empty()
                {
                    lines.push(format!("      {}", dim(reason)));
                }
                if let Some(latest) = stats["latest"].as_str() {
                    lines.push(format!("      {} {}", dim("latest"), latest));
                }
            }
            if detail >= 2 {
                if let Some(evidence) = layer["mirror_evidence"].as_object() {
                    lines.push(format!(
                        "      {} {} · {}",
                        dim("mirror evidence"),
                        evidence["at"].as_str().unwrap_or("?"),
                        evidence["run_id"].as_str().unwrap_or("?")
                    ));
                }
                if let Some(orphans) = stats["orphan_chunks"].as_u64()
                    && orphans > 0
                {
                    lines.push(format!(
                        "      {} {} chunks · {} reclaimable",
                        dim("orphans"),
                        orphans,
                        human_bytes(stats["orphan_bytes"].as_u64().unwrap_or(0))
                    ));
                }
            }
        }
    }

    let repositories = value["repositories"].as_array().map_or(0, Vec::len);
    lines.push(String::new());
    lines.push(format!(
        "{} {}  {} {}",
        heading("REPOSITORIES"),
        repositories,
        dim("synced"),
        value["repositories"].as_array().map_or(0, |items| items
            .iter()
            .filter(|repo| repo["state"].as_str() == Some("synced"))
            .count())
    ));
    if let Some(items) = value["repositories"].as_array() {
        for repo in items.iter().take(if detail >= 1 { usize::MAX } else { 8 }) {
            let path = repo["path"].as_str().unwrap_or("?");
            let branch = repo["branch"].as_str().unwrap_or("-");
            let ahead = repo["ahead"]
                .as_u64()
                .map(|n| n.to_string())
                .unwrap_or_default();
            let behind = repo["behind"]
                .as_u64()
                .map(|n| n.to_string())
                .unwrap_or_default();
            let state = repo["state"].as_str().unwrap_or("unknown");
            lines.push(format!(
                "  {} {} {} {} {} {}",
                blue(&padded(path, 42)),
                ochre(&padded(branch, 16)),
                padded(&format!("{ahead}↑"), 6),
                padded(&format!("{behind}↓"), 6),
                state_text(state),
                repo["reason"].as_str().map(dim).unwrap_or_default()
            ));
            if detail >= 1 {
                for item in repo["warnings"].as_array().into_iter().flatten() {
                    if let Some(text) = item.as_str() {
                        lines.push(format!("      {} {}", warning("!"), dim(text)));
                    }
                }
            }
        }
        if items.len() > 8 && detail == 0 {
            lines.push(format!(
                "  {}",
                dim(&format!("… {} more with -v", items.len() - 8))
            ));
        }
    }

    if let Some(issues) = value["issues"].as_array() {
        for issue in issues.iter().filter_map(|item| item.as_str()) {
            lines.push(format!("  {} {}", warning("!"), warning(issue)));
        }
    }
    if detail >= 1 {
        lines.push(String::new());
        lines.push(dim(&format!(
            "generated {} · {}",
            value["generated_at"].as_str().unwrap_or("?"),
            value["note"].as_str().unwrap_or("")
        )));
    }
    format!("{}\n", lines.join("\n"))
}

#[cfg_attr(not(feature = "storage"), allow(dead_code))]
pub fn print_status(value: &serde_json::Value, detail: u8) {
    print_maybe_paged(&render_status(value, detail));
}

/// Compact human view of a binaries-layer result. JSON callers bypass this.
#[cfg_attr(not(feature = "storage"), allow(dead_code))]
pub fn print_binary_report(value: &serde_json::Value) {
    let mut lines = Vec::new();
    if let Some(snapshots) = value["snapshots"].as_array() {
        lines.push(heading("RBQ / BINARIES"));
        for snapshot in snapshots {
            lines.push(format!(
                "  {} {} · {} bytes",
                ochre(snapshot["id"].as_str().unwrap_or("?")),
                dim(snapshot["created_at"].as_str().unwrap_or("")),
                snapshot["bytes"]
            ));
            if let Some(tools) = snapshot["tools"].as_array() {
                for tool in tools {
                    lines.push(format!(
                        "    {} {} {}",
                        good(tool["tool"].as_str().unwrap_or("?")),
                        dim(tool["version"].as_str().unwrap_or("")),
                        dim(&tool["sha256"]
                            .as_str()
                            .unwrap_or("")
                            .chars()
                            .take(12)
                            .collect::<String>())
                    ));
                }
            }
        }
    } else if let Some(id) = value["id"].as_str() {
        lines.push(format!("{}  {}", heading("RBQ / BINARIES"), ochre(id)));
        if let Some(tool) = value["tool"].as_str() {
            lines.push(format!(
                "  {} {}",
                good(tool),
                dim(value["version"].as_str().unwrap_or(""))
            ));
        }
        if let Some(path) = value["restored_to"].as_str() {
            lines.push(format!("  restored to {path}"));
        }
        if let Some(bytes) = value["bytes"].as_u64() {
            lines.push(format!("  {bytes} bytes"));
        }
        if let Some(note) = value["note"].as_str() {
            lines.push(format!("  {}", dim(note)));
        }
    } else {
        lines.push(serde_json::to_string_pretty(value).unwrap_or_default());
    }
    print_maybe_paged(&format!("{}\n", lines.join("\n")));
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

    #[test]
    fn status_bytes_are_human_readable() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2.0 MiB");
    }

    #[test]
    fn status_render_includes_space_and_layer_states() {
        let value = json!({
            "schema": "rbq.status.v1",
            "generated_at": "2026-01-01T00:00:00Z",
            "overall": {
                "state": "attention",
                "synced": 1,
                "attention": 1,
                "occupied_bytes": 1536,
                "pending_bytes": 512,
                "logical_bytes": 2048,
                "progress": 75.0
            },
            "layers": [{
                "layer": "binaries", "state": "incomplete", "mirror": "verified",
                "progress": 50.0,
                "stats": {"snapshots": 1, "stored_bytes": 1024, "missing_bytes": 512,
                    "latest": "2026-01-01T00:00:00Z", "orphan_chunks": 0}
            }],
            "repositories": [],
            "issues": [],
            "note": "test"
        });
        let text = render_status(&value, 2);
        assert!(text.contains("RBQ / STATUS"));
        assert!(text.contains("1.5 KiB"));
        assert!(text.contains("512 B"));
        assert!(text.contains("incomplete"));
        assert!(text.contains("binaries"));
    }
}
