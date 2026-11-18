//! Terminal presentation only; JSON and completion streams are never styled.
use std::{
    io::IsTerminal,
    sync::atomic::{AtomicBool, Ordering},
};

static COLOR: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

pub fn configure(mode: ColorMode, machine: bool) {
    let enabled = !machine
        && match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => {
                std::io::stdout().is_terminal()
                    && std::env::var_os("NO_COLOR").is_none()
                    && std::env::var("TERM").is_ok_and(|term| term != "dumb")
            }
        };
    COLOR.store(enabled, Ordering::Relaxed);
}

pub fn styles() -> clap::builder::styling::Styles {
    use clap::builder::styling::AnsiColor;
    clap::builder::styling::Styles::styled()
        .header(AnsiColor::Cyan.on_default().bold())
        .usage(AnsiColor::Cyan.on_default().bold())
        .literal(AnsiColor::Green.on_default().bold())
        .placeholder(AnsiColor::Cyan.on_default())
        .error(AnsiColor::Red.on_default().bold())
}

fn paint(text: &str, code: &str) -> String {
    let safe: String = text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[{code}m{safe}\x1b[0m")
    } else {
        safe
    }
}
pub fn heading(text: &str) -> String {
    paint(text, "1;36")
}
pub fn good(text: &str) -> String {
    paint(text, "1;32")
}
pub fn warning(text: &str) -> String {
    paint(text, "1;33")
}
pub fn dim(text: &str) -> String {
    paint(text, "2")
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
    #[test]
    fn terminal_controls_in_peer_labels_are_removed() {
        // Do not allow untrusted terminal escape sequences to change titles.
        assert!(!super::paint("peer\x1b]title\x07", "36").contains('\x07'));
    }
}
