use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub rebekah_home: PathBuf,
    pub scan: Scan,
    pub git: Git,
    pub backup: Backup,
    pub storage: StorageConfig,
    pub mneme: MnemeConfig,
    pub frog: crate::frog::FrogConfig,
    pub agenda: crate::agenda::AgendaConfig,
    pub git_layer: crate::gitlayer::GitLayerConfig,
    pub reconcile: Reconcile,
    pub fleet: Fleet,
    pub command_timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scan {
    pub roots: Vec<PathBuf>,
    pub exclude: Vec<String>,
    pub max_depth: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Git {
    pub remote_prefixes: Vec<String>,
    pub fetch: bool,
    pub push: bool,
    pub fast_forward: bool,
    pub backup_required: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub repository: Option<String>,
    pub password_file: Option<PathBuf>,
    pub datasets: Vec<Dataset>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dataset {
    pub name: String,
    pub path: PathBuf,
    /// "directory" for quiescent data, "agenda" for whole editions.
    pub kind: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Root of Rebsync-managed objects. Relative paths resolve against
    /// rebekah_home. This is not a source checkout or a restic repository.
    pub root: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from(".rebsync/objects"),
        }
    }
}
/// The Mneme layer: an owner-produced, owner-validated session-history index
/// snapshot, published as content-addressed chunks into Rebsync object storage.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MnemeConfig {
    /// Publish a Mneme snapshot during `--apply` runs.
    pub enabled: bool,
    /// Mneme executable; a bare name is looked up on PATH.
    pub binary: PathBuf,
    /// Index path passed as `--db`; unset means Mneme's own default/MNEME_DB.
    pub db: Option<PathBuf>,
    /// Names this history store in object keys; one object-key segment.
    pub label: String,
    /// Fixed chunk size for content addressing: a multiple of 4 KiB, 4 KiB..=64 MiB.
    /// Mneme exports whole SQLite pages, so page-aligned chunks survive inserts.
    pub chunk_bytes: u64,
    /// Also back up the verified snapshot through the encrypted restic repository.
    pub restic: bool,
    /// Bound for each Mneme subprocess (snapshot creation can be slow).
    pub timeout_seconds: u64,
}

impl Default for MnemeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            binary: PathBuf::from("mneme"),
            db: None,
            label: "local".into(),
            chunk_bytes: 64 * 1024,
            restic: true,
            timeout_seconds: 900,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reconcile {
    pub write_instructions: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fleet {
    pub host: String,
    pub root: String,
}

impl Config {
    pub fn defaults(home: PathBuf) -> Self {
        Self {
            version: 1,
            rebekah_home: home,
            scan: Scan {
                roots: vec![],
                max_depth: 14,
                exclude: [
                    ".git",
                    ".rebekah",
                    ".rebsync",
                    ".cache",
                    ".cargo",
                    ".rustup",
                    ".npm",
                    ".local",
                    ".ssh",
                    ".config",
                    ".android",
                    ".gradle",
                    ".ollama",
                    "node_modules",
                    "target",
                    "vendor",
                    ".venv",
                    "venv",
                ]
                .map(String::from)
                .to_vec(),
            },
            git: Git {
                remote_prefixes: vec!["github.com/tabenius".into(), "github.com/RAGBAZ".into()],
                fetch: true,
                push: true,
                fast_forward: true,
                backup_required: true,
            },
            backup: Backup {
                repository: None,
                password_file: None,
                datasets: vec![],
            },
            storage: StorageConfig::default(),
            mneme: MnemeConfig::default(),
            frog: Default::default(),
            agenda: Default::default(),
            git_layer: Default::default(),
            reconcile: Reconcile {
                write_instructions: true,
            },
            fleet: Fleet {
                host: "kali-1".into(),
                root: "/srv/ragbaz/src/vendors/ragbaz/head".into(),
            },
            command_timeout_seconds: 120,
        }
    }
    pub fn roots(&self) -> Vec<PathBuf> {
        if self.scan.roots.is_empty() {
            vec![self.rebekah_home.clone()]
        } else {
            self.scan.roots.clone()
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported configuration version {}", self.version);
        }
        if self.command_timeout_seconds == 0 {
            bail!("command timeout must be positive");
        }
        if self.storage.root.as_os_str().is_empty() {
            bail!("storage root cannot be empty");
        }
        if !(4096..=64 * 1024 * 1024).contains(&self.mneme.chunk_bytes)
            || !self.mneme.chunk_bytes.is_multiple_of(4096)
        {
            bail!("mneme.chunk_bytes must be a multiple of 4096 between 4 KiB and 64 MiB");
        }
        if self.mneme.timeout_seconds == 0 {
            bail!("mneme.timeout_seconds must be positive");
        }
        if self.mneme.binary.as_os_str().is_empty() {
            bail!("mneme.binary cannot be empty");
        }
        crate::mneme::validate_label(&self.mneme.label)?;
        for (name, label, chunk) in [
            ("frog", &self.frog.label, self.frog.chunk_bytes),
            ("agenda", &self.agenda.label, self.agenda.chunk_bytes),
            ("git_layer", &"repo".to_string(), self.git_layer.chunk_bytes),
        ] {
            crate::layer::validate_label(label).map_err(|e| anyhow::anyhow!("{name}.{e}"))?;
            if !(4096..=64 * 1024 * 1024).contains(&chunk) || !chunk.is_multiple_of(4096) {
                bail!("{name}.chunk_bytes must be a multiple of 4096 between 4 KiB and 64 MiB");
            }
        }
        if self.frog.timeout_seconds == 0 {
            bail!("frog.timeout_seconds must be positive");
        }
        for prefix in &self.git.remote_prefixes {
            let owner = prefix.strip_prefix("github.com/").unwrap_or("");
            if owner.is_empty()
                || owner.contains('/')
                || !owner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                bail!("remote prefix must be github.com/OWNER: {prefix}");
            }
        }
        for dataset in &self.backup.datasets {
            if !["directory", "agenda"].contains(&dataset.kind.as_str()) {
                bail!(
                    "dataset {}: supported kinds are directory and agenda; SQLite must be exported consistently by its owner first (use the [mneme] or [frog] layer)",
                    dataset.name
                );
            }
            if dataset.name.is_empty() {
                bail!("dataset name cannot be empty");
            }
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct ConfigOverrides {
    pub rebekah_home: Option<PathBuf>,
    pub config: Option<PathBuf>,
    pub roots: Option<Vec<PathBuf>>,
    pub fetch: Option<bool>,
    pub push: Option<bool>,
    pub fast_forward: Option<bool>,
    pub backup_repository: Option<String>,
    pub password_file: Option<PathBuf>,
    pub storage_root: Option<PathBuf>,
    pub mneme_db: Option<PathBuf>,
}
#[derive(Debug, Serialize)]
pub struct EffectiveConfig {
    pub config: Config,
    pub origins: BTreeMap<String, String>,
    pub files: Vec<PathBuf>,
}

fn mark(value: &Value, path: &str, source: &str, origins: &mut BTreeMap<String, String>) {
    if let Some(object) = value.as_object() {
        for (key, v) in object {
            mark(
                v,
                &if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                },
                source,
                origins,
            );
        }
    } else {
        origins.insert(path.into(), source.into());
    }
}
fn merge(
    target: &mut Value,
    patch: Value,
    path: &str,
    source: &str,
    origins: &mut BTreeMap<String, String>,
) {
    if let (Some(t), Some(p)) = (target.as_object_mut(), patch.as_object()) {
        for (key, value) in p {
            let child = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            merge(
                t.entry(key.clone()).or_insert(Value::Null),
                value.clone(),
                &child,
                source,
                origins,
            );
        }
    } else {
        mark(&patch, path, source, origins);
        *target = patch;
    }
}
fn select(dir: &Path, stem: &str) -> Result<Option<PathBuf>> {
    let candidates: Vec<_> = ["toml", "yaml", "yml"]
        .iter()
        .map(|ext| dir.join(format!("{stem}.{ext}")))
        .filter(|p| p.exists())
        .collect();
    if candidates.len() > 1 {
        bail!("ambiguous configuration files in {}", dir.display());
    }
    Ok(candidates.into_iter().next())
}
fn parse(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read configuration {}", path.display()))?;
    let value = match path.extension().and_then(|x| x.to_str()) {
        Some("toml") => serde_json::to_value(toml::from_str::<toml::Value>(&text)?)?,
        Some("yaml" | "yml") => serde_saphyr::from_str::<Value>(&text)?,
        _ => bail!("configuration must be TOML or YAML"),
    };
    if !value.is_object() {
        bail!("configuration must be a mapping");
    }
    Ok(value)
}
fn absolute(path: PathBuf, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

pub fn load_config(overrides: ConfigOverrides) -> Result<EffectiveConfig> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")?;
    let config_home = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    load_config_at(home, config_home, overrides)
}

/// Explicit locations make configuration resolution independently testable.
pub fn load_config_at(
    home: PathBuf,
    config_home: PathBuf,
    overrides: ConfigOverrides,
) -> Result<EffectiveConfig> {
    let cwd = env::current_dir()?;
    let mut value = serde_json::to_value(Config::defaults(home.clone()))?;
    let mut origins = BTreeMap::new();
    mark(&value, "", "default", &mut origins);
    let mut files = vec![];
    if let Some(path) = select(&config_home.join("rebsync"), "config")? {
        merge(
            &mut value,
            parse(&path)?,
            "",
            &path.display().to_string(),
            &mut origins,
        );
        files.push(path);
    }
    let explicit = overrides.config.as_ref().map(|p| parse(p)).transpose()?;
    let selected_home = overrides
        .rebekah_home
        .clone()
        .or_else(|| {
            explicit
                .as_ref()
                .and_then(|v| v.get("rebekah_home"))
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .or_else(|| {
            value
                .get("rebekah_home")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .unwrap_or(home);
    let selected_home = absolute(selected_home, &cwd);
    if let Some(path) = select(&selected_home, "rebsync")? {
        let patch = parse(&path)?;
        if patch.get("rebekah_home").is_some() {
            bail!(
                "home-local configuration cannot redirect rebekah_home; use user config, --config or the positional argument"
            );
        }
        merge(
            &mut value,
            patch,
            "",
            &path.display().to_string(),
            &mut origins,
        );
        files.push(path);
    }
    if let Some(patch) = explicit {
        let path = overrides.config.as_ref().unwrap();
        merge(
            &mut value,
            patch,
            "",
            &path.display().to_string(),
            &mut origins,
        );
        files.push(path.clone());
    }
    let mut cli = serde_json::json!({});
    if let Some(path) = overrides.rebekah_home {
        cli["rebekah_home"] = serde_json::to_value(path)?;
    }
    if let Some(roots) = overrides.roots {
        cli["scan"]["roots"] = serde_json::to_value(roots)?;
    }
    if let Some(fetch) = overrides.fetch {
        cli["git"]["fetch"] = fetch.into();
    }
    if let Some(push) = overrides.push {
        cli["git"]["push"] = push.into();
    }
    if let Some(ff) = overrides.fast_forward {
        cli["git"]["fast_forward"] = ff.into();
    }
    if let Some(repo) = overrides.backup_repository {
        cli["backup"]["repository"] = repo.into();
    }
    if let Some(path) = overrides.password_file {
        cli["backup"]["password_file"] = serde_json::to_value(path)?;
    }
    if let Some(root) = overrides.storage_root {
        cli["storage"]["root"] = serde_json::to_value(root)?;
    }
    if let Some(path) = overrides.mneme_db {
        cli["mneme"]["db"] = serde_json::to_value(path)?;
    }
    merge(&mut value, cli, "", "CLI", &mut origins);
    let mut config: Config = serde_json::from_value(value).context("invalid configuration")?;
    config.rebekah_home = absolute(config.rebekah_home, &cwd);
    config.storage.root = absolute(config.storage.root, &config.rebekah_home);
    config.scan.roots = config
        .scan
        .roots
        .into_iter()
        .map(|p| absolute(p, &config.rebekah_home))
        .collect();
    if let Some(path) = config.backup.password_file.take() {
        config.backup.password_file = Some(absolute(path, &config.rebekah_home));
    }
    if let Some(path) = config.mneme.db.take() {
        config.mneme.db = Some(absolute(path, &config.rebekah_home));
    }
    // A bare program name stays a PATH lookup; anything with a separator is a path.
    if config.mneme.binary.components().count() > 1 {
        config.mneme.binary = absolute(config.mneme.binary.clone(), &config.rebekah_home);
    }
    if let Some(path) = config.frog.db.take() {
        config.frog.db = Some(absolute(path, &config.rebekah_home));
    }
    for program in [&mut config.frog.binary, &mut config.frog.python] {
        if program.components().count() > 1 {
            *program = absolute(program.clone(), &config.rebekah_home);
        }
    }
    config.agenda.path = absolute(config.agenda.path.clone(), &config.rebekah_home);
    for dataset in &mut config.backup.datasets {
        dataset.path = absolute(dataset.path.clone(), &config.rebekah_home);
    }
    config.validate()?;
    Ok(EffectiveConfig {
        config,
        origins,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layers_and_explicit_false() -> Result<()> {
        let t = tempfile::tempdir()?;
        let home = t.path().join("home");
        let xdg = t.path().join("xdg");
        fs::create_dir_all(&home)?;
        fs::create_dir_all(xdg.join("rebsync"))?;
        fs::write(xdg.join("rebsync/config.toml"), "[git]\npush = false\n")?;
        fs::write(
            home.join("rebsync.yaml"),
            "git:\n  push: true\nscan:\n  roots: [src]\n",
        )?;
        let explicit = t.path().join("explicit.toml");
        fs::write(&explicit, "[git]\npush = true\n[scan]\nroots = ['other']\n")?;
        let e = load_config_at(
            home.clone(),
            xdg,
            ConfigOverrides {
                config: Some(explicit),
                push: Some(false),
                ..Default::default()
            },
        )?;
        assert!(!e.config.git.push);
        assert_eq!(e.origins["git.push"], "CLI");
        assert_eq!(e.config.scan.roots, vec![home.join("other")]);
        Ok(())
    }
    #[test]
    fn mneme_chunks_must_be_page_aligned() {
        let mut config = Config::defaults("/home/test".into());
        assert_eq!(config.mneme.chunk_bytes, 64 * 1024);
        assert!(config.validate().is_ok());
        for bad in [0, 1000, 4095, 65_537, 128 * 1024 * 1024] {
            config.mneme.chunk_bytes = bad;
            assert!(config.validate().is_err(), "accepted {bad}");
        }
        config.mneme.chunk_bytes = 4096;
        assert!(config.validate().is_ok());
    }
    #[test]
    fn rejects_unknown_keys_and_ambiguous_formats() -> Result<()> {
        let t = tempfile::tempdir()?;
        fs::write(t.path().join("rebsync.toml"), "[git]\nforce_push = true\n")?;
        assert!(load_config_at(t.path().into(), t.path().join("xdg"), Default::default()).is_err());
        fs::write(t.path().join("rebsync.yaml"), "version: 1\n")?;
        assert!(load_config_at(t.path().into(), t.path().join("xdg"), Default::default()).is_err());
        Ok(())
    }
}
