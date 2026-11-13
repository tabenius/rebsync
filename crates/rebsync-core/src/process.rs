//! Bounded subprocess execution with no shell interpolation.
use anyhow::{Context, Result, bail};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use wait_timeout::ChildExt;

const LIMIT: usize = 16 * 1024 * 1024;
#[derive(Debug)]
pub struct Output {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
}
pub fn command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "never")
        .env(
            "GIT_SSH_COMMAND",
            "ssh -oBatchMode=yes -oConnectTimeout=10 -oStrictHostKeyChecking=yes",
        )
        .env("GIT_CONFIG_NOSYSTEM", "1");
    cmd
}
pub fn git(repo: &Path) -> Command {
    let mut cmd = command("git");
    cmd.current_dir(repo).args([
        "--no-optional-locks",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "protocol.ssh.allow=always",
        "-c",
        "protocol.file.allow=always",
    ]);
    cmd
}
fn drain(mut reader: impl Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut kept = vec![];
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let remaining = LIMIT.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..n.min(remaining)]);
        truncated |= n > remaining;
    }
    Ok((kept, truncated))
}
pub fn run(cmd: &mut Command, timeout: u64, input: Option<&[u8]>) -> Result<Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    // A separate process group lets timeouts terminate SSH/helpers as well.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().context("launch subprocess")?;
    let stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || drain(stdout));
    let writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().unwrap();
        let owned = bytes.to_vec();
        thread::spawn(move || stdin.write_all(&owned))
    });
    let status = match child.wait_timeout(Duration::from_secs(timeout))? {
        Some(status) => status,
        None => {
            #[cfg(unix)]
            {
                // kill(1), not a shell; a negative PID addresses the process group.
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{}", child.id())])
                    .status();
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            if let Some(w) = writer {
                let _ = w.join();
            }
            bail!("subprocess timed out after {timeout}s");
        }
    };
    if let Some(w) = writer {
        w.join()
            .map_err(|_| anyhow::anyhow!("subprocess input thread failed"))??;
    }
    let (stdout, truncated) = reader
        .join()
        .map_err(|_| anyhow::anyhow!("subprocess output thread failed"))??;
    if truncated {
        bail!("subprocess output exceeded 16 MiB; refusing truncated inventory");
    }
    Ok(Output {
        success: status.success(),
        code: status.code(),
        stdout,
    })
}
pub fn checked(cmd: &mut Command, timeout: u64) -> Result<Vec<u8>> {
    let out = run(cmd, timeout, None)?;
    if !out.success {
        bail!(
            "subprocess failed (exit {:?}); diagnostic output suppressed to avoid leaking secrets",
            out.code
        );
    }
    Ok(out.stdout)
}
pub fn text(cmd: &mut Command, timeout: u64) -> Result<String> {
    Ok(String::from_utf8(checked(cmd, timeout)?)
        .context("non-UTF-8 Git metadata")?
        .trim_end()
        .into())
}
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file: File = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subprocess_timeout_is_bounded() {
        let start = std::time::Instant::now();
        let result = run(command("sleep").arg("30"), 1, None);
        assert!(result.is_err());
        assert!(start.elapsed().as_secs() < 10);
    }
}
