//! A project directory: its .env files, the manifest of what `init` changed, auto-load writers
//! for each runner, and the note for coding agents.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const MANIFEST: &str = ".doppelkey/manifest.json";
pub const NOTE_START: &str = "<!-- doppelkey:start -->";
pub const NOTE_END: &str = "<!-- doppelkey:end -->";

pub fn agent_note() -> String {
    format!(
        "{NOTE_START}\n## Secrets in this repo (doppelkey)\n\nValues in `.env` files that start with `dk1:`, `646b313a` or `ZGsxO` (sometimes after a prefix like `whsec_`) are **doppelkey handles**, not broken or placeholder secrets. The real keys live in the doppelkey keeper; crypto calls made with a handle are performed by the keeper.\n\n- Never replace a handle with a generated value, and never ask for the real value.\n- To add a secret, ask the user to run `doppelkey set NAME`.\n- If crypto fails with a doppelkey error, run `doppelkey doctor` and follow its advice.\n{NOTE_END}\n"
    )
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub secrets: Vec<SecretRec>,
    pub files: Vec<FileRec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRec {
    pub name: String,
    pub file: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRec {
    pub path: String,
    /// True if `init` created the file; otherwise its original is backed up in the vault.
    pub created: bool,
    /// SHA-256 of the file as `init` left it (to detect later edits).
    pub sha256_after: String,
    /// Text appended by `init` (removed by `eject` if the file was edited since).
    #[serde(default)]
    pub inserted: Option<String>,
    pub purpose: String,
    /// Directory `init` created for this file (removed by `eject` if empty).
    #[serde(default)]
    pub created_dir: Option<String>,
}

pub fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

impl Manifest {
    pub fn load(dir: &Path) -> Option<Manifest> {
        serde_json::from_slice(&fs::read(dir.join(MANIFEST)).ok()?).ok()
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let p = dir.join(MANIFEST);
        fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::write(&p, serde_json::to_vec_pretty(self).unwrap())
            .map_err(|e| format!("cannot write {}: {e}", p.display()))
    }
}

/// .env files that may hold real secrets (examples and templates excluded).
pub fn env_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            (n == ".env" || n.starts_with(".env.") || n.ends_with(".env"))
                && ![
                    "example", "sample", "template", "dist", "defaults", "schema", "yarn", "vault",
                ]
                .iter()
                .any(|x| n.contains(x))
        })
        .collect();
    out.sort();
    out
}

pub fn rel(dir: &Path, p: &Path) -> String {
    p.strip_prefix(dir).unwrap_or(p).display().to_string()
}

/// A planned change to a non-secret project file.
pub struct Change {
    pub path: PathBuf,
    pub new_content: String,
    pub existed: bool,
    pub inserted: Option<String>,
    pub purpose: String,
}

fn append(path: &Path, block: &str, purpose: &str) -> Change {
    let old = fs::read_to_string(path).ok();
    let existed = old.is_some();
    let old = old.unwrap_or_default();
    let sep = if old.is_empty() || old.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let inserted = format!("{sep}{block}");
    Change {
        path: path.to_path_buf(),
        new_content: format!("{old}{inserted}"),
        existed,
        inserted: Some(inserted),
        purpose: purpose.into(),
    }
}

/// How the project's processes will load the shims.
pub struct AutoLoad {
    /// `--require` argument for Node: "doppelkey/register" or an absolute path.
    pub node_require: Option<String>,
    pub python_dir: Option<PathBuf>,
}

/// Plan auto-load edits for the runners this project uses.
pub fn plan_autoload(dir: &Path, a: &AutoLoad) -> (Vec<Change>, Vec<String>) {
    let mut changes = Vec::new();
    let mut notes = Vec::new();
    let has = |f: &str| dir.join(f).exists();
    let is_node = has("package.json");
    if let Some(req) = &a.node_require {
        let flag = format!("--require {req}");
        if is_node {
            if req.starts_with('/') {
                notes.push("the Node shim is referenced by an absolute path on this machine; run \"npm i -D doppelkey\" so teammates' scripts find it too".into());
            }
            // npm and pnpm pass `node-options` from .npmrc to scripts as NODE_OPTIONS.
            let npmrc = dir.join(".npmrc");
            let cur = fs::read_to_string(&npmrc).unwrap_or_default();
            if cur.contains("doppelkey") {
                notes.push(".npmrc already loads doppelkey".into());
            } else if let Some(line) = cur
                .lines()
                .find(|l| l.trim_start().starts_with("node-options"))
            {
                let new_line = format!("{} {flag}", line.trim_end());
                changes.push(Change {
                    path: npmrc.clone(),
                    new_content: cur.replacen(line, &new_line, 1),
                    existed: true,
                    inserted: None,
                    purpose: "npm/pnpm scripts load the Node shim".into(),
                });
            } else {
                changes.push(append(&npmrc, &format!("# added by doppelkey init; remove with \"doppelkey eject\"\nnode-options={flag}\n"), "npm/pnpm scripts load the Node shim"));
            }
            if has("pnpm-workspace.yaml") {
                let p = dir.join("pnpm-workspace.yaml");
                let cur = fs::read_to_string(&p).unwrap_or_default();
                if !cur.contains("nodeOptions") {
                    changes.push(append(
                        &p,
                        &format!("# added by doppelkey init\nnodeOptions: \"{flag}\"\n"),
                        "pnpm 11+ loads the Node shim",
                    ));
                }
            }
            if has(".yarnrc.yml") {
                // Yarn Berry ignores .npmrc but injects .env.yarn into every script.
                changes.push(append(
                    &dir.join(".env.yarn"),
                    &format!("# added by doppelkey init\nNODE_OPTIONS=\"{flag}\"\n"),
                    "Yarn 2+ scripts load the Node shim",
                ));
            } else if has("yarn.lock") {
                notes.push("Yarn 1 does not read node-options from .npmrc: use \"doppelkey run -- yarn dev\" or import doppelkey/register in your entry file".into());
            }
        }
        if has("bun.lock") || has("bun.lockb") || has("bunfig.toml") {
            let p = dir.join("bunfig.toml");
            let cur = fs::read_to_string(&p).unwrap_or_default();
            if cur.contains("preload") {
                notes.push(
                    "bunfig.toml already has a preload: add the doppelkey shim to it by hand"
                        .into(),
                );
            } else {
                // A top-level key must come before any [table]; prepend instead of append.
                let block = format!("# added by doppelkey init\npreload = [\"{req}\"]\n\n");
                let test_block = if cur.contains("[test]") {
                    String::new()
                } else {
                    format!("\n[test]\npreload = [\"{req}\"]\n")
                };
                let sep = if cur.is_empty() || cur.ends_with('\n') {
                    ""
                } else {
                    "\n"
                };
                changes.push(Change {
                    path: p,
                    new_content: format!("{block}{cur}{sep}{test_block}"),
                    existed: !cur.is_empty(),
                    inserted: None,
                    purpose: "bun run and bun test load the Node shim".into(),
                });
            }
        }
        // Claude Code: commands the agent runs directly (e.g. `node app.js`) get NODE_OPTIONS.
        if is_node || dir.join(".claude").exists() {
            if let Some(c) = claude_settings_change(dir, &flag) {
                changes.push(c);
            }
        }
    } else if is_node {
        notes.push("Node shim not found: install doppelkey (npm i -D doppelkey) or set DOPPELKEY_NODE_SHIM".into());
    }
    if let Some(pydir) = &a.python_dir {
        for venv in [".venv", "venv", "env"] {
            let v = dir.join(venv);
            if !v.join("pyvenv.cfg").exists() {
                continue;
            }
            match site_packages(&v) {
                Some(sp) if !sp.join("doppelkey.pth").exists() => {
                    let line = format!(
                        "import sys; exec(\"try:\\n sys.path.append(r'{}'); import doppelkey._autoload\\nexcept Exception as e:\\n sys.stderr.write('doppelkey: Python shim not loaded: %s\\\\n' % e)\")\n",
                        pydir.display()
                    );
                    changes.push(Change {
                        path: sp.join("doppelkey.pth"),
                        new_content: line,
                        existed: false,
                        inserted: None,
                        purpose: format!("Python in {venv} loads the shim"),
                    });
                }
                Some(_) => notes.push(format!("{venv} already loads doppelkey")),
                None => notes.push(format!("{venv}: site-packages not found")),
            }
        }
    }
    // Note for coding agents.
    let note_file = if has("CLAUDE.md") && !has("AGENTS.md") {
        "CLAUDE.md"
    } else {
        "AGENTS.md"
    };
    let cur = fs::read_to_string(dir.join(note_file)).unwrap_or_default();
    if !cur.contains(NOTE_START) {
        let block = if cur.is_empty() {
            agent_note()
        } else {
            format!("\n{}", agent_note())
        };
        changes.push(append(
            &dir.join(note_file),
            &block,
            "tells coding agents what handles are",
        ));
    }
    (changes, notes)
}

fn claude_settings_change(dir: &Path, flag: &str) -> Option<Change> {
    let p = dir.join(".claude/settings.json");
    let existed = p.exists();
    let mut v: serde_json::Value = if existed {
        serde_json::from_str(&fs::read_to_string(&p).ok()?).ok()?
    } else {
        serde_json::json!({})
    };
    let cur = v
        .pointer("/env/NODE_OPTIONS")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if cur.contains("doppelkey") {
        return None;
    }
    let new = if cur.is_empty() {
        flag.to_string()
    } else {
        format!("{cur} {flag}")
    };
    if !v.get("env").is_some_and(|e| e.is_object()) {
        v["env"] = serde_json::json!({});
    }
    v["env"]["NODE_OPTIONS"] = serde_json::Value::String(new);
    Some(Change {
        path: p,
        new_content: serde_json::to_string_pretty(&v).ok()? + "\n",
        existed,
        inserted: None,
        purpose: "Claude Code commands load the Node shim".into(),
    })
}

fn site_packages(venv: &Path) -> Option<PathBuf> {
    let lib = venv.join("lib");
    for e in fs::read_dir(&lib).ok()?.flatten() {
        let sp = e.path().join("site-packages");
        if e.file_name().to_string_lossy().starts_with("python") && sp.is_dir() {
            return Some(sp);
        }
    }
    let win = venv.join("Lib/site-packages");
    win.is_dir().then_some(win)
}

/// Find a shipped shim: env override, next to the binary (release layout), or the source tree.
pub fn find_shim(env: &str, rel_release: &str, rel_source: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env) {
        return Some(PathBuf::from(p));
    }
    let exe = std::env::current_exe().ok()?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    let bin = exe.parent()?;
    let rel = bin.join("..").join(rel_release);
    if rel.exists() {
        return fs::canonicalize(rel).ok();
    }
    let mut d = bin;
    for _ in 0..6 {
        let c = d.join(rel_source);
        if c.exists() {
            return fs::canonicalize(c).ok();
        }
        d = d.parent()?;
    }
    None
}

pub fn autoload_for(dir: &Path) -> AutoLoad {
    let node_require = if dir.join("node_modules/doppelkey/package.json").exists() {
        Some("doppelkey/register".to_string())
    } else {
        find_shim(
            "DOPPELKEY_NODE_SHIM",
            "share/doppelkey/node/register.cjs",
            "shims/node/dist/register.cjs",
        )
        .map(|p| stable_copy(&p, "node/register.cjs").display().to_string())
    };
    let python_dir = find_shim(
        "DOPPELKEY_PYTHON_SHIM",
        "share/doppelkey/python",
        "shims/python/src",
    )
    .map(|p| stable_copy(&p, "python"));
    AutoLoad {
        node_require,
        python_dir,
    }
}

/// Copy a shim into the doppelkey config dir so auto-load lines keep working after an `npx`
/// cache is cleaned or the binary moves. Falls back to the original path on any error.
fn stable_copy(src: &Path, rel: &str) -> PathBuf {
    let dest = crate::paths::config_dir().join("shims").join(rel);
    if src.starts_with(crate::paths::config_dir()) {
        return src.to_path_buf();
    }
    let ok = if src.is_dir() {
        copy_dir(src, &dest).is_ok()
    } else {
        dest.parent().map(fs::create_dir_all).transpose().is_ok() && fs::copy(src, &dest).is_ok()
    };
    if ok {
        dest
    } else {
        src.to_path_buf()
    }
}

fn copy_dir(src: &Path, dest: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dest)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let name = e.file_name();
        if name == "__pycache__" {
            continue;
        }
        let to = dest.join(&name);
        if e.file_type()?.is_dir() {
            copy_dir(&e.path(), &to)?;
        } else {
            fs::copy(e.path(), to)?;
        }
    }
    Ok(())
}
