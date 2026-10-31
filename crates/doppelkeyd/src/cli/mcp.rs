//! `doppelkey mcp`: a Model Context Protocol server over stdio (JSON-RPC 2.0, one message per
//! line). Tools: `status`, `doctor`, `list_secrets`. Names and health only: no tool returns a
//! key, a handle's key, or anything that could be used to obtain one.

use super::client::Client;
use super::doctor;
use super::project::Manifest;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL: &str = "2025-06-18";

fn tools() -> Value {
    json!([
        { "name": "status", "description": "Is the doppelkey keeper running and unlocked? Lists protected key names (never values).", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "doctor", "description": "Check the doppelkey setup for the current project and return problems with the command that fixes each.", "inputSchema": { "type": "object", "properties": {} } },
        { "name": "list_secrets", "description": "Names of secrets protected in the current project (values in .env are handles; never replace them).", "inputSchema": { "type": "object", "properties": {} } }
    ])
}

fn call_tool(name: &str) -> Result<String, String> {
    let dir = std::env::current_dir().map_err(|e| e.to_string())?;
    match name {
        "status" => match Client::connect().and_then(|mut c| c.call("status", json!({}))) {
            Ok(s) => Ok(format!("keeper: {}\nlocked: {}\nkeys: {}", s["version"].as_str().unwrap_or("?"), s["locked"], s["keys"])),
            Err(e) => Ok(format!("keeper not available: {e}")),
        },
        "doctor" => {
            let (lines, failed) = doctor::check(&dir);
            Ok(format!("{}\n{}", lines.join("\n"), if failed == 0 { "All checks passed.".to_string() } else { format!("{failed} problem(s) found.") }))
        }
        "list_secrets" => Ok(match Manifest::load(&dir) {
            Some(m) if !m.secrets.is_empty() => m.secrets.iter().map(|s| format!("{} ({})", s.name, s.file)).collect::<Vec<_>>().join("\n"),
            _ => "No doppelkey-protected secrets in this project. The user can run \"doppelkey init\".".into(),
        }),
        other => Err(format!("unknown tool {other}")),
    }
}

fn handle(msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => {
            json!({ "protocolVersion": PROTOCOL, "capabilities": { "tools": {} }, "serverInfo": { "name": "doppelkey", "version": env!("CARGO_PKG_VERSION") } })
        }
        "tools/list" => json!({ "tools": tools() }),
        "tools/call" => {
            let name = msg
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            match call_tool(name) {
                Ok(text) => {
                    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
                }
                Err(e) => json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
            }
        }
        "ping" => json!({}),
        _ if id.is_none() => return None, // notifications (e.g. notifications/initialized)
        _ => {
            return Some(
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("method not found: {method}") } }),
            )
        }
    };
    id.map(|id| json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

pub fn serve() -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&msg),
            Err(_) => Some(
                json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } }),
            ),
        };
        if let Some(r) = reply {
            writeln!(out, "{r}")
                .and_then(|_| out.flush())
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
