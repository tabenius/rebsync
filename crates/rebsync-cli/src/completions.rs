//! Shell completion installation; scripts are generated without configuration
//! and no private artifact names ever enter them.
use anyhow::{Context, Result, bail};
use clap::{CommandFactory, ValueEnum};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

use crate::Cli;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum InstallShell {
    Bash,
    Fish,
    All,
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub shell: InstallShell,
    pub dry_run: bool,
    pub force: bool,
    pub system: bool,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub shell: &'static str,
    pub path: PathBuf,
    pub action: &'static str,
    pub next: String,
}

fn data_home(home: &Path, xdg: Option<PathBuf>) -> PathBuf {
    xdg.unwrap_or_else(|| home.join(".local/share"))
}

fn config_home(home: &Path, xdg: Option<PathBuf>) -> PathBuf {
    xdg.unwrap_or_else(|| home.join(".config"))
}

/// Explicit XDG values keep destination resolution testable without mutating
/// the process environment (which is shared between parallel tests).
fn user_destination_with(
    shell: InstallShell,
    home: &Path,
    xdg_data: Option<PathBuf>,
    xdg_config: Option<PathBuf>,
) -> PathBuf {
    match shell {
        InstallShell::Bash => data_home(home, xdg_data)
            .join("bash-completion/completions")
            .join("rbq"),
        InstallShell::Fish => config_home(home, xdg_config).join("fish/completions/rbq.fish"),
        InstallShell::All => unreachable!("All is expanded before path selection"),
    }
}

pub fn user_destination(shell: InstallShell, home: &Path) -> PathBuf {
    user_destination_with(
        shell,
        home,
        env::var_os("XDG_DATA_HOME").map(PathBuf::from),
        env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
    )
}

pub fn system_destination(shell: InstallShell) -> PathBuf {
    match shell {
        InstallShell::Bash => PathBuf::from("/etc/bash_completion.d/rbq"),
        InstallShell::Fish => PathBuf::from("/usr/local/share/fish/vendor_completions.d/rbq.fish"),
        InstallShell::All => unreachable!("All is expanded before path selection"),
    }
}

fn to_clap_shell(shell: InstallShell) -> clap_complete::Shell {
    match shell {
        InstallShell::Bash => clap_complete::Shell::Bash,
        InstallShell::Fish => clap_complete::Shell::Fish,
        InstallShell::All => unreachable!("All is expanded before generation"),
    }
}

fn generate(shell: InstallShell) -> Vec<u8> {
    let mut script = Vec::new();
    let mut command = Cli::command();
    clap_complete::generate(to_clap_shell(shell), &mut command, "rbq", &mut script);
    script
}

fn shell_name(shell: InstallShell) -> &'static str {
    match shell {
        InstallShell::Bash => "bash",
        InstallShell::Fish => "fish",
        InstallShell::All => unreachable!("All is expanded before reporting"),
    }
}

fn next_step(shell: InstallShell, path: &Path) -> String {
    match shell {
        InstallShell::Bash => format!("source {} or start a new bash shell", path.display()),
        InstallShell::Fish => {
            format!(
                "open a new fish shell; {} is loaded automatically",
                path.display()
            )
        }
        InstallShell::All => unreachable!("All is expanded before reporting"),
    }
}

/// Install scripts with create-or-update semantics. Existing, different files
/// are left alone unless `--force` is given.
pub fn install(options: Options) -> Result<Vec<Report>> {
    let selected: Vec<InstallShell> = match options.shell {
        InstallShell::All => vec![InstallShell::Bash, InstallShell::Fish],
        shell => vec![shell],
    };
    let home = if options.system {
        None
    } else {
        Some(PathBuf::from(
            env::var_os("HOME").context("HOME is not set; use --system or set HOME")?,
        ))
    };
    let mut reports = Vec::new();
    for shell in selected {
        let path = match &home {
            Some(home) => user_destination(shell, home),
            None => system_destination(shell),
        };
        let script = generate(shell);
        if script.is_empty() {
            bail!("generated completion script is empty");
        }
        let action = if options.dry_run {
            match fs::read(&path) {
                Ok(existing) if existing == script => "unchanged",
                Ok(_) => "would replace",
                Err(_) => "would install",
            }
        } else {
            let existing = fs::read(&path).ok();
            if existing.as_deref() == Some(script.as_slice()) {
                "current"
            } else {
                if existing.is_some() && !options.force {
                    bail!(
                        "{} already exists with different completions; use --force to replace",
                        path.display()
                    );
                }
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("create completion directory {}", parent.display())
                    })?;
                }
                fs::write(&path, &script)
                    .with_context(|| format!("write completion script {}", path.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
                }
                "installed"
            }
        };
        let next = next_step(shell, &path);
        reports.push(Report {
            shell: shell_name(shell),
            path,
            action,
            next,
        });
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_destinations_follow_xdg_defaults() {
        let home = Path::new("/home/example");
        assert_eq!(
            user_destination_with(InstallShell::Bash, home, None, None),
            Path::new("/home/example/.local/share/bash-completion/completions/rbq")
        );
        assert_eq!(
            user_destination_with(InstallShell::Fish, home, None, None),
            Path::new("/home/example/.config/fish/completions/rbq.fish")
        );
        assert_eq!(
            user_destination_with(
                InstallShell::Fish,
                home,
                None,
                Some(PathBuf::from("/xdg/config"))
            ),
            Path::new("/xdg/config/fish/completions/rbq.fish")
        );
    }
}
