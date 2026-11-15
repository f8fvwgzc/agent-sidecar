//! `agentsc mcp import` and `agentsc mcp check` (docs/design/mcp-tools.md, decision 12): write a
//! `type: mcp` charter entry from a server's definition, and compare a charter's pins with the
//! live servers. MCP tool annotations are untrusted: they only become commented suggestions for
//! a person to read, never charter fields.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agentsc_charter::mcp::{self as spec, PROTOCOL_VERSION};
use agentsc_charter::{Charter, ToolType};
use agentsc_common::mcp_client::{self as client, ListOptions};
use anyhow::{Context, bail};
use serde_json::{Value, json};

/// Each request's timeout.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The most read of one answer.
const MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(clap::Subcommand)]
pub enum McpCmd {
    /// Print `type: mcp` tool entries for `agents[].tools`, with each definition's pin and the
    /// `effect` / `label` its annotations suggest (as comments: annotations are untrusted).
    Import(ImportArgs),
    /// Compare every `mcp` tool's pin with its server's current definition: exit 0 when all
    /// match, 1 when one drifted, is missing or is invalid, 2 when a server cannot be read.
    Check(CheckArgs),
}

#[derive(clap::Args)]
pub struct ImportArgs {
    /// The server's MCP endpoint (Streamable HTTP, protocol 2026-07-28).
    #[arg(long)]
    url: String,
    /// A tool to import, by its name at the server; repeat for more.
    #[arg(long = "tool", required_unless_present = "all")]
    tools: Vec<String>,
    /// Import every tool the server lists.
    #[arg(long, conflicts_with = "tools")]
    all: bool,
    /// A file holding a bearer token for the server (it is sent, never printed).
    #[arg(long)]
    credential_file: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct CheckArgs {
    /// The charter (plain or custom resource form).
    charter: PathBuf,
    /// Where the tools' `credential.secret` files are (as the sidecar's `--tool-secrets-dir`).
    #[arg(long, default_value = spec::DEFAULT_SECRETS_DIR)]
    secrets_dir: PathBuf,
    /// A bearer token file for tools without `credential` (a delegated tool's server, say).
    #[arg(long)]
    token_file: Option<PathBuf>,
}

pub fn run(cmd: McpCmd) -> anyhow::Result<i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match cmd {
        McpCmd::Import(a) => rt.block_on(import(&a)).map(|yaml| {
            print!("{yaml}");
            0
        }),
        McpCmd::Check(a) => rt.block_on(check(&a)),
    }
}

fn http() -> anyhow::Result<reqwest::Client> {
    // no redirects, as the sidecar: the pin is of what this URL answers
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

fn read_token(path: &Path) -> anyhow::Result<String> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let token = text.trim();
    if token.is_empty() || token.chars().any(char::is_control) {
        bail!("{} is empty or not a single-line token", path.display());
    }
    Ok(token.to_string())
}

async fn list(
    http: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
) -> Result<BTreeMap<String, Value>, client::McpError> {
    let timeout = || TIMEOUT;
    let options = ListOptions {
        bearer,
        traceparent: None,
        request_id: None,
        timeout: &timeout,
        max_bytes: MAX_BYTES,
    };
    Ok(client::list_tools(http, url, &options)
        .await?
        .0
        .into_iter()
        .collect())
}

/// `server/discover`'s `serverInfo`, as `name version`, if the server tells.
async fn server_info(http: &reqwest::Client, url: &str, bearer: Option<&str>) -> Option<String> {
    let result = client::post(
        http,
        client::Request {
            url,
            method: "server/discover",
            name: None,
            params: json!({}),
            param_headers: Vec::new(),
            bearer,
            traceparent: None,
            request_id: None,
            timeout: TIMEOUT,
            max_bytes: MAX_BYTES,
        },
    )
    .await
    .ok()?;
    let info = result.get("serverInfo")?;
    let s = |k: &str| info.get(k).and_then(Value::as_str).unwrap_or("");
    Some(format!("{} {}", s("name"), s("version")).trim().to_string())
}

/// The charter name for a server's tool name: the model API allows `^[a-zA-Z0-9_-]{1,64}$`.
fn charter_name(server_name: &str) -> String {
    let name: String = server_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if name.is_empty() { "tool".into() } else { name }
}

/// Comment lines with what a definition's annotations suggest.
fn suggestions(def: &Value) -> Vec<String> {
    let hint = |k: &str| {
        def.pointer(&format!("/annotations/{k}"))
            .and_then(Value::as_bool)
    };
    let mut out = Vec::new();
    match hint("readOnlyHint") {
        Some(true) => out.push("effect: read        # suggested by readOnlyHint: true".to_string()),
        _ => out.push(
            "effect: write       # the default for mcp tools (no readOnlyHint: true)".to_string(),
        ),
    }
    if hint("destructiveHint") == Some(true) {
        out.push("approval: {timeout_s: 600}   # suggested by destructiveHint: true".to_string());
    }
    if hint("openWorldHint") == Some(false) {
        out.push(
            "label: untrusted    # the default; openWorldHint: false says the tool reads no outside data"
                .to_string(),
        );
    }
    out
}

/// The YAML of the import: a comment naming the server, then one list item per tool.
async fn import(a: &ImportArgs) -> anyhow::Result<String> {
    let http = http()?;
    let bearer = a.credential_file.as_deref().map(read_token).transpose()?;
    let tools = list(&http, &a.url, bearer.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("{} ({})", e.reason, e.rule))?;
    let wanted: Vec<String> = if a.all {
        tools.keys().cloned().collect()
    } else {
        a.tools.clone()
    };
    let mut out = String::new();
    let server = server_info(&http, &a.url, bearer.as_deref())
        .await
        .map(|s| format!(" ({s})"))
        .unwrap_or_default();
    out.push_str(&format!(
        "# MCP tools of {}{server}, protocol {PROTOCOL_VERSION}, imported by agentsc mcp import.\n\
         # The descriptions and parameters are the server's: rewrite and narrow them as you need.\n\
         # Annotations are untrusted: read the suggested lines before you uncomment one.\n",
        a.url
    ));
    for name in wanted {
        let Some(def) = tools.get(&name) else {
            bail!("the server at {} lists no tool {name:?}", a.url);
        };
        let schema = def
            .get("inputSchema")
            .filter(|s| s.is_object())
            .with_context(|| format!("{name}: the definition has no inputSchema object"))?;
        if let Err(e) = spec::param_headers(schema) {
            bail!(
                "{name}: the definition breaks MCP's x-mcp-header rules ({e}); a client must ignore it"
            );
        }
        if let Err(e) = spec::arguments_validator(schema) {
            bail!(
                "{name}: its inputSchema does not compile as a JSON Schema the sidecar can check ({e})"
            );
        }
        let local = charter_name(&name);
        let mut entry = serde_json::Map::new();
        entry.insert("name".into(), json!(local));
        entry.insert("type".into(), json!("mcp"));
        entry.insert(
            "description".into(),
            json!(
                def.get("description")
                    .and_then(Value::as_str)
                    .unwrap_or(&name)
            ),
        );
        entry.insert("url".into(), json!(a.url));
        if local != name {
            entry.insert("mcp_tool".into(), json!(name));
        }
        entry.insert("pin".into(), json!(spec::definition_pin(def)));
        entry.insert("parameters".into(), schema.clone());
        let yaml = serde_yaml_ng::to_string(&vec![Value::Object(entry)])?;
        out.push_str(&yaml);
        for line in suggestions(def) {
            out.push_str(&format!("  # {line}\n"));
        }
    }
    Ok(out)
}

/// A server's tools by name, or why they could not be listed.
type Listed = Result<BTreeMap<String, Value>, String>;

/// One line per `mcp` tool, and the exit code.
async fn check(a: &CheckArgs) -> anyhow::Result<i32> {
    let charter = Charter::load(&a.charter)
        .map_err(|e| anyhow::anyhow!("{}", agentsc_common::error::chain(&e)))?;
    let http = http()?;
    let fallback = a.token_file.as_deref().map(read_token).transpose()?;
    // one tools/list per server and bearer
    let mut lists: BTreeMap<(String, Option<String>), Listed> = BTreeMap::new();
    let mut code = 0;
    let mut count = 0;
    for agent in &charter.agents {
        for tool in agent.tools.iter().filter(|t| t.tool_type == ToolType::Mcp) {
            count += 1;
            let at = format!("{}.{}", agent.name, tool.name);
            let url = tool.url.clone().unwrap_or_default();
            let bearer = match &tool.credential {
                Some(c) => match client::read_credential(&a.secrets_dir, &c.secret).await {
                    Ok(t) => Some(t),
                    Err(e) => {
                        println!("ERROR   {at}: {e}");
                        code = code.max(2);
                        continue;
                    }
                },
                None => fallback.clone(),
            };
            let key = (url.clone(), bearer.clone());
            if !lists.contains_key(&key) {
                let listed = list(&http, &url, bearer.as_deref())
                    .await
                    .map_err(|e| format!("{} ({})", e.reason, e.rule));
                lists.insert(key.clone(), listed);
            }
            let tools = match &lists[&key] {
                Ok(t) => t,
                Err(e) => {
                    println!("ERROR   {at}: {url}: {e}");
                    code = code.max(2);
                    continue;
                }
            };
            let def = tools.get(tool.mcp_tool_name());
            match client::check(tool, def) {
                Ok(_) => println!("ok      {at}: {} {}", tool.mcp_tool_name(), url),
                Err((rule, reason)) => {
                    let word = if rule == client::RULE_PIN_MISMATCH {
                        "DRIFT"
                    } else {
                        "MISSING"
                    };
                    println!("{word:<7} {at}: {reason}");
                    if let (Some(def), true) = (def, rule == client::RULE_PIN_MISMATCH) {
                        // what the server says now, for the reviewer (never for a model)
                        let mut now = serde_json::Map::new();
                        for f in spec::PINNED_FIELDS {
                            if let Some(v) = def.get(f) {
                                now.insert(f.to_string(), v.clone());
                            }
                        }
                        let pretty = serde_json::to_string_pretty(&Value::Object(now))?;
                        for line in pretty.lines() {
                            println!("          {line}");
                        }
                        println!("          new pin: {}", spec::definition_pin(def));
                    }
                    code = code.max(1);
                }
            }
        }
    }
    if count == 0 {
        println!("{}: no mcp tools", a.charter.display());
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_suggestions() {
        assert_eq!(charter_name("admin.tools.list"), "admin_tools_list");
        assert_eq!(charter_name(&"x".repeat(128)).len(), 64);
        let s =
            suggestions(&json!({"annotations": {"readOnlyHint": true, "openWorldHint": false}}));
        assert!(s[0].starts_with("effect: read"), "{s:?}");
        assert!(s.iter().any(|l| l.contains("openWorldHint")), "{s:?}");
        let s = suggestions(&json!({"annotations": {"destructiveHint": true}}));
        assert!(s[0].starts_with("effect: write"), "{s:?}");
        assert!(s.iter().any(|l| l.starts_with("approval:")), "{s:?}");
    }
}
