//! `doppelkey doctor`: check everything a working setup needs and print the fix for each problem.

use super::client::Client;
use super::project::{self, Manifest};
use crate::{paths, store};
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

struct Report {
    failed: usize,
    lines: Vec<String>,
}

impl Report {
    fn ok(&mut self, msg: impl Into<String>) {
        self.lines.push(format!("  ok    {}", msg.into()));
    }
    fn warn(&mut self, msg: impl Into<String>, fix: impl Into<String>) {
        self.lines.push(format!(
            "  warn  {}\n        fix: {}",
            msg.into(),
            fix.into()
        ));
    }
    fn fail(&mut self, msg: impl Into<String>, fix: impl Into<String>) {
        self.failed += 1;
        self.lines.push(format!(
            "  FAIL  {}\n        fix: {}",
            msg.into(),
            fix.into()
        ));
    }
}

const PURE_JS: &[&str] = &[
    "crypto-js",
    "jssha",
    "js-sha256",
    "js-sha1",
    "js-sha512",
    "hash.js",
    "sjcl",
    "node-forge",
    "@stablelib/hmac",
    "@stablelib/hkdf",
    "tweetnacl",
    "@noble/ciphers",
];

/// Collect the checks as text lines (also used by the MCP server). Returns (lines, failures).
pub fn check(dir: &Path) -> (Vec<String>, usize) {
    let mut r = Report {
        failed: 0,
        lines: Vec::new(),
    };
    // Keeper
    let status = Client::connect().and_then(|mut c| c.call("status", json!({})));
    let keeper_ids: Vec<String> = match &status {
        Ok(s) => {
            r.ok(format!(
                "keeper running: {} at {}",
                s["version"].as_str().unwrap_or("?"),
                paths::socket_path().display()
            ));
            if s["locked"] == json!(true) {
                r.fail(
                    "keeper is locked: crypto with handles will fail",
                    "doppelkey unlock",
                );
            }
            match s["non_dumpable"].as_bool() {
                Some(true) => {
                    r.ok("keeper memory is protected from same-user reads (non-dumpable)")
                }
                Some(false) => r.warn(
                    "keeper is dumpable: same-user processes may read its memory",
                    "reinstall with \"doppelkey service install\"",
                ),
                None => {}
            }
            s["ids"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        }
        Err(e) => {
            r.fail(format!("{e}"), "doppelkey service install");
            Vec::new()
        }
    };
    // Vault
    match store::read_header(&paths::vault_file()) {
        Ok((h, _, _)) => match h.kek {
            store::KekKind::File => r.warn(
                "vault key is a plain file: a same-user agent can read the vault",
                "recreate the vault with --protect passphrase (or keychain on macOS)",
            ),
            k => r.ok(format!("vault protected by {k:?}").to_lowercase()),
        },
        Err(_) => r.fail("no vault", "doppelkey init"),
    }
    if project::find_shim(
        "DOPPELKEY_NODE_SHIM",
        "share/doppelkey/node/register.cjs",
        "shims/node/dist/register.cjs",
    )
    .is_none()
        && !dir.join("node_modules/doppelkey").exists()
        && dir.join("package.json").exists()
    {
        r.fail(
            "Node shim not found",
            "npm i -D doppelkey, or set DOPPELKEY_NODE_SHIM",
        );
    }
    // Service
    if super::service::installed() {
        r.ok(format!(
            "keeper service installed ({})",
            super::service::unit_path().display()
        ));
    } else if status.is_ok() {
        r.warn(
            "keeper is running but not as a user service (it won't start after a reboot)",
            "doppelkey service install",
        );
    }
    // Handles in .env files
    for f in project::env_files(dir) {
        let text = fs::read_to_string(&f).unwrap_or_default();
        for var in super::envfile::parse(&text) {
            for id in doppelkey_proto::handle::ids_in_text(&var.value) {
                if status.is_ok() && !keeper_ids.contains(&id) {
                    r.fail(
                        format!(
                            "{} in {} is a handle the keeper doesn't know",
                            var.name,
                            project::rel(dir, &f)
                        ),
                        format!("doppelkey set {}", var.name),
                    );
                }
            }
            if var.value.contains("dk1:")
                && doppelkey_proto::handle::ids_in_text(&var.value).is_empty()
            {
                r.fail(
                    format!(
                        "{} in {} looks like a damaged handle (bad checksum)",
                        var.name,
                        project::rel(dir, &f)
                    ),
                    format!("doppelkey set {}", var.name),
                );
            }
        }
    }
    // Auto-load
    let is_node = dir.join("package.json").exists();
    if is_node {
        let npmrc = fs::read_to_string(dir.join(".npmrc")).unwrap_or_default();
        if npmrc.contains("doppelkey") {
            r.ok(".npmrc loads the Node shim for npm/pnpm scripts");
            if std::env::var("NODE_OPTIONS")
                .is_ok_and(|v| !v.is_empty() && !v.contains("doppelkey"))
            {
                r.warn("your NODE_OPTIONS is set; npm and pnpm replace it with .npmrc's node-options inside scripts", "move your flags into .npmrc's node-options line");
            }
        } else {
            r.fail(
                "npm/pnpm scripts won't load the shim (.npmrc has no doppelkey line)",
                "doppelkey init",
            );
        }
        if dir.join("yarn.lock").exists() && !dir.join(".yarnrc.yml").exists() {
            r.warn(
                "Yarn 1 ignores .npmrc node-options",
                "use \"doppelkey run -- yarn <script>\"",
            );
        }
        for p in PURE_JS {
            if dir
                .join("node_modules")
                .join(p)
                .join("package.json")
                .exists()
            {
                r.warn(
                    format!("{p} computes crypto in pure JavaScript and bypasses the shim"),
                    "make sure no handle is passed to it as a key",
                );
            }
        }
        if let Ok(out) = std::process::Command::new("node")
            .arg("-p")
            .arg("typeof require('node:module').registerHooks")
            .output()
        {
            if String::from_utf8_lossy(&out.stdout).trim() != "function" {
                r.warn("this Node has no module.registerHooks (< 22.15): pure-JS adapters (svix, @noble/hashes) are off", "use Node 22.15 or newer");
            }
        }
    }
    for venv in [".venv", "venv"] {
        if dir.join(venv).join("pyvenv.cfg").exists() {
            let has = walk_for(&dir.join(venv).join("lib"), "doppelkey.pth");
            if has {
                r.ok(format!("{venv} loads the Python shim"))
            } else {
                r.fail(
                    format!("{venv} doesn't load the Python shim"),
                    "doppelkey init",
                )
            }
        }
    }
    if let Some(m) = Manifest::load(dir) {
        r.ok(format!(
            "{} secret(s) protected in this project",
            m.secrets.len()
        ));
    }
    (r.lines, r.failed)
}

fn walk_for(dir: &Path, name: &str) -> bool {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.path().join("site-packages").join(name).exists())
}

pub fn run(dir: &Path) -> ExitCode {
    println!("doppelkey doctor: {}", dir.display());
    let (lines, failed) = check(dir);
    for l in lines {
        println!("{l}");
    }
    if failed == 0 {
        println!("All checks passed.");
        ExitCode::SUCCESS
    } else {
        println!("{failed} problem(s) found.");
        ExitCode::from(1)
    }
}
