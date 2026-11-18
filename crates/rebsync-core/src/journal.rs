use crate::process::write_private;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub struct Journal {
    file: File,
    pub path: PathBuf,
    pub run_id: String,
    sequence: u64,
}
impl Journal {
    pub fn open(home: &Path) -> Result<Self> {
        let now = Utc::now();
        let run_id = format!(
            "{}-{}",
            now.format("%Y%m%dT%H%M%S%.9fZ"),
            std::process::id()
        );
        let base = format!("rbq_{}", now.format("%Y-%m-%d_%H%M%S"));
        let mut path = home.join(format!("{base}.jsonl"));
        if path.exists() {
            path = home.join(format!("{base}_{}.jsonl", run_id));
        }
        write_private(&path, b"")?;
        let file = OpenOptions::new().append(true).open(&path)?;
        Ok(Self {
            file,
            path,
            run_id,
            sequence: 0,
        })
    }
    pub fn event(&mut self, kind: &str, subject: impl Serialize, detail: Value) -> Result<()> {
        self.sequence += 1;
        let event = json!({"schema":"rbq.event.v1", "run_id":self.run_id, "sequence":self.sequence, "at":Utc::now().to_rfc3339(), "kind":kind, "subject":subject, "detail":detail});
        serde_json::to_writer(&mut self.file, &event)?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journals_are_collision_safe_and_parseable() -> Result<()> {
        let home = tempfile::tempdir()?;
        let mut first = Journal::open(home.path())?;
        let mut second = Journal::open(home.path())?;
        assert_ne!(first.path, second.path);
        first.event("test", "one", json!({"success":true}))?;
        second.event("test", "two", json!({"success":false}))?;
        for path in [&first.path, &second.path] {
            for line in std::fs::read_to_string(path)?.lines() {
                let value: Value = serde_json::from_str(line)?;
                assert_eq!(value["schema"], "rbq.event.v1");
            }
        }
        Ok(())
    }
}
