//! Owner-controlled migration signals. Rebeqah never migrates a live database.
use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Serialize)]
pub struct MigrationBlocked {
    pub layer: String,
    pub status: String,
    pub report: Value,
}

impl std::fmt::Display for MigrationBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} migration {}: {}; use the owner tooling; rbq does not migrate live data",
            self.layer, self.status, self.report
        )
    }
}

impl std::error::Error for MigrationBlocked {}

/// Optional owner extension: migration.status is current, required, unavailable
/// or unknown. Absence is legacy/unknown, never an assertion of compatibility.
/// Frog's existing schema-drift response is also understood without an extension.
pub fn check_report(layer: &str, report: &Value) -> Result<()> {
    let drift = report.get("behind").and_then(Value::as_array);
    let ahead = report.get("ahead").and_then(Value::as_array);
    let status = if ahead.is_some_and(|items| !items.is_empty()) {
        Some("unavailable")
    } else if drift.is_some_and(|items| !items.is_empty()) {
        Some("required")
    } else if let Some(migration) = report.get("migration") {
        match migration.get("status").and_then(Value::as_str) {
            Some("current") => None,
            Some("required") => Some("required"),
            Some("unavailable") => Some("unavailable"),
            _ => Some("unknown"),
        }
    } else {
        None
    };
    if let Some(status) = status {
        bail!(MigrationBlocked {
            layer: layer.into(),
            status: status.into(),
            report: report.clone(),
        });
    }
    Ok(())
}

pub fn require_schema(layer: &str, report: &Value, expected: &str) -> Result<()> {
    check_report(layer, report)?;
    if report.get("schema").and_then(Value::as_str) != Some(expected) {
        bail!(MigrationBlocked {
            layer: layer.into(),
            status: "unavailable".into(),
            report: json!({"expected_schema": expected, "observed_schema": report.get("schema"),
                "reason": "No supported conversion for this owner export schema; upgrade compatible owner/rbq tooling."}),
        });
    }
    Ok(())
}

pub fn failure(layer: &str, error: &anyhow::Error) -> Value {
    if let Some(migration) = error.downcast_ref::<MigrationBlocked>() {
        json!({"name": layer, "kind": layer, "status": "blocked",
            "error": format!("{error:#}"), "migration": migration})
    } else {
        json!({"name": layer, "kind": layer, "status": "failed", "error": format!("{error:#}")})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_migration_states_are_not_silently_accepted() {
        for status in ["required", "unavailable", "unknown", "future-status"] {
            let error =
                check_report("frog", &json!({"migration": {"status": status}})).unwrap_err();
            let report = failure("frog", &error);
            assert_eq!(report["status"], "blocked");
            assert!(report["migration"].is_object());
        }
        assert!(check_report("frog", &json!({"migration": {"status": "current"}})).is_ok());
        assert!(check_report("frog", &json!({})).is_ok());
        assert!(check_report("frog", &json!({"behind": ["016_repo_dep_kind.sql"]})).is_err());
        assert!(check_report("frog", &json!({"ahead": ["999_future.sql"]})).is_err());
    }
}
