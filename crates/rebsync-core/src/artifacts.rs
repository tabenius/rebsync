//! Read-only, source-scoped navigation through Dash's private MCP endpoint.
//! No fallback to filesystem paths, rendered HTML, arbitrary tools or URLs.
use crate::private_http::{PrivateHttp, bounded, read_token};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const PROTOCOL: &str = "2025-03-26";
const TOOLS: &[&str] = &[
    "artifacts_list_sources",
    "artifacts_list",
    "artifacts_get",
    "artifacts_get_provenance",
    "artifacts_read_piece",
    "artifacts_read_frog",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub source_id: String,
    pub id: String,
}

impl SourceRef {
    pub fn new(source_id: String, id: String) -> Result<Self> {
        let reference = Self { source_id, id };
        reference.validate()?;
        Ok(reference)
    }
    fn validate(&self) -> Result<()> {
        for part in [&self.source_id, &self.id] {
            ensure!(
                !part.is_empty()
                    && part.chars().count() <= 512
                    && !part.chars().any(char::is_control),
                "artifact references require nonempty source_id and id, at most 512 characters each"
            );
        }
        Ok(())
    }
}

pub struct Artifacts {
    http: PrivateHttp,
    next_id: u64,
    protocol: String,
}

impl Artifacts {
    pub fn from_token_file(endpoint: &str, path: &Path) -> Result<Self> {
        Self::connect(endpoint, &read_token(path)?)
    }

    pub fn connect(endpoint: &str, token: &str) -> Result<Self> {
        let mut client = Self {
            http: PrivateHttp::connect(endpoint, "/mcp/", token)?,
            next_id: 0,
            protocol: PROTOCOL.into(),
        };
        let initialized = client.rpc("initialize", json!({ "protocolVersion": PROTOCOL,
            "capabilities": {}, "clientInfo": { "name": "rbq", "version": env!("CARGO_PKG_VERSION") } }))?;
        let version = initialized["protocolVersion"]
            .as_str()
            .context("MCP server omitted protocol version")?;
        ensure!(
            ["2025-03-26", "2025-06-18", "2025-11-25"].contains(&version),
            "unsupported MCP protocol version"
        );
        ensure!(
            initialized["capabilities"]["tools"].is_object(),
            "MCP server does not support tools"
        );
        client.protocol = version.into();
        // Dash uses stateless requests: session IDs and SSE are deliberately not
        // accepted. Initialization never creates a server-side session to close.
        client.notify_initialized()?;
        Ok(client)
    }

    fn notify_initialized(&self) -> Result<()> {
        let response = PrivateHttp::response(
            self.http
                .request("POST", "")
                .set("Accept", "application/json, text/event-stream")
                .set("MCP-Protocol-Version", &self.protocol)
                .send_json(json!({"jsonrpc":"2.0", "method":"notifications/initialized"})),
        )?;
        ensure!(
            response.status() == 202,
            "MCP initialization notification was not accepted"
        );
        Ok(())
    }

    fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let response = PrivateHttp::response(
            self.http
                .request("POST", "")
                .set("Accept", "application/json, text/event-stream")
                .set("MCP-Protocol-Version", &self.protocol)
                .send_json(
                    json!({"jsonrpc":"2.0", "id":self.next_id, "method":method, "params":params}),
                ),
        )?;
        ensure!(
            response.header("mcp-session-id").is_none(),
            "stateful MCP endpoints are not supported by this Dash client"
        );
        ensure!(
            response.header("content-type").is_some_and(|value| value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))),
            "MCP endpoint must return bounded JSON, not an event stream"
        );
        let bytes = bounded(response.into_reader(), MAX_RESPONSE)?;
        let value: Value = serde_json::from_slice(&bytes).context("invalid MCP JSON response")?;
        ensure!(
            value["jsonrpc"] == "2.0" && value["id"].as_u64() == Some(self.next_id),
            "MCP response identity mismatch"
        );
        if value.get("error").is_some() {
            bail!("MCP request refused; check deployed tool support and credential opt-ins");
        }
        ensure!(value["result"].is_object(), "MCP response omitted result");
        Ok(value["result"].clone())
    }

    fn call(&mut self, name: &str, arguments: Value) -> Result<Value> {
        ensure!(TOOLS.contains(&name), "unsupported artifact tool");
        let result = self.rpc("tools/call", json!({"name":name, "arguments":arguments}))?;
        if result["isError"] == true {
            // Only a short machine code may enter stderr; never echo authored
            // contents, server exception messages or credential-bearing URLs.
            let code = result["structuredContent"]["error"]
                .as_str()
                .filter(|code| {
                    !code.is_empty()
                        && code.len() <= 80
                        && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                });
            bail!(
                "artifact request refused ({})",
                code.unwrap_or("tool_error")
            );
        }
        let mut data = result["structuredContent"]
            .as_object()
            .context("MCP tool omitted structured content")?
            .clone();
        // Even a legitimate server returns authored text and source assertions,
        // not instructions or cryptographic authority.
        data.insert("trusted".into(), Value::Bool(false));
        Ok(Value::Object(data))
    }

    pub fn sources(&mut self) -> Result<Value> {
        self.call("artifacts_list_sources", json!({}))
    }

    pub fn list(
        &mut self,
        source: Option<&str>,
        factory: Option<&SourceRef>,
        after: Option<&SourceRef>,
        limit: usize,
    ) -> Result<Value> {
        ensure!(
            (1..=50).contains(&limit),
            "artifact list limit must be 1..50"
        );
        let mut args = json!({"limit":limit});
        if let Some(source) = source {
            SourceRef::new(source.into(), "check".into())?;
            args["source_id"] = source.into();
        }
        for (name, value) in [("factory_ref", factory), ("after", after)] {
            if let Some(reference) = value {
                reference.validate()?;
                args[name] = serde_json::to_value(reference)?;
            }
        }
        self.call("artifacts_list", args)
    }

    pub fn get(&mut self, reference: &SourceRef) -> Result<Value> {
        reference.validate()?;
        self.call("artifacts_get", json!({"ref":reference}))
    }

    pub fn provenance(&mut self, reference: &SourceRef) -> Result<Value> {
        reference.validate()?;
        self.call("artifacts_get_provenance", json!({"ref":reference}))
    }

    pub fn read_frog(&mut self, reference: &SourceRef) -> Result<Value> {
        reference.validate()?;
        self.call("artifacts_read_frog", json!({"ref":reference}))
    }

    pub fn read_piece(
        &mut self,
        reference: &SourceRef,
        offset: usize,
        limit: usize,
        expected_revision: Option<&str>,
    ) -> Result<Value> {
        reference.validate()?;
        ensure!(
            offset <= 131072 && (1..=8000).contains(&limit),
            "piece offset must be 0..131072; limit must be 1..8000"
        );
        let mut args = json!({"ref":reference,"offset":offset,"limit":limit});
        if let Some(revision) = expected_revision {
            ensure!(
                !revision.is_empty() && revision.len() <= 512,
                "invalid expected revision"
            );
            args["expected_revision"] = revision.into();
        }
        self.call("artifacts_read_piece", args)
    }
}
