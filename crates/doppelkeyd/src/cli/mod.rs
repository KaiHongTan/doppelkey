//! `doppelkey`: the command-line interface.

pub mod classify;
pub mod client;
pub mod doctor;
pub mod envfile;
pub mod mcp;
pub mod project;
pub mod prompt;
pub mod service;

use crate::state::{Policy, ALL_OPS};
use crate::store::{self, Header, KekKind, StoredKey, VaultData};
use crate::{audit, paths};
use base64::Engine;
use clap::{Parser, Subcommand};
use classify::Decision;
use client::Client;
use doppelkey_proto::{handle, Form};
use project::{FileRec, Manifest, SecretRec};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Parser)]
#[command(
    name = "doppelkey",
    version,
    about = "An ssh-agent for app secrets: keep signing and encryption keys out of your app (and your coding agent's reach)."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Protect this project's secrets: preview, move values to the vault, write handles and auto-load lines.
    Init {
        /// Apply without asking.
        #[arg(long, short = 'y')]
        yes: bool,
        /// Show what would change and exit.
        #[arg(long)]
        dry_run: bool,
        /// Vault protection for a new vault: passphrase, keychain (macOS) or file.
        #[arg(long)]
        protect: Option<KekKind>,
        /// Don't install or start the keeper service.
        #[arg(long)]
        no_service: bool,
        /// Project directory (default: current directory).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Protect one secret that is already in a .env file.
    Protect {
        name: String,
        #[arg(long)]
        file: Option<PathBuf>,
        /// Handle form: long, compact, hex, base64 (default: chosen from the value's shape).
        #[arg(long)]
        form: Option<Form>,
        /// Allowed operations (repeatable). Default: chosen from the name.
        #[arg(long)]
        allow: Vec<String>,
    },
    /// Add a secret by typing its value (for teammates onboarding). The value never touches disk.
    Set {
        name: String,
        #[arg(long, default_value = ".env")]
        file: PathBuf,
        #[arg(long)]
        form: Option<Form>,
        #[arg(long)]
        allow: Vec<String>,
        /// Read the value from stdin instead of the terminal.
        #[arg(long)]
        stdin: bool,
    },
    /// Undo `init`: put real values back in .env files and remove everything init added.
    Eject {
        /// Keep the keys in the vault after restoring the files.
        #[arg(long)]
        keep_keys: bool,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Check the keeper, vault, handles and auto-load setup, and print fixes.
    Doctor {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Run one command with the shims loaded (escape hatch; normal commands load them automatically).
    Run {
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Show the audit log.
    Log {
        #[arg(short = 'n', default_value_t = 50)]
        lines: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show or change a key's policy. With no flags, prints the policy as TOML.
    Policy {
        name: Option<String>,
        #[arg(long)]
        allow: Vec<String>,
        #[arg(long)]
        deny: Vec<String>,
        /// Maximum operations per minute.
        #[arg(long)]
        rate: Option<u32>,
        #[arg(long)]
        no_rate: bool,
        /// Ask the human before each use (approval cached for 5 minutes).
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        no_confirm: bool,
        #[arg(long)]
        allow_service: Vec<String>,
        #[arg(long)]
        deny_service: Vec<String>,
    },
    /// List this project's protected secrets.
    List {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show keeper and vault status.
    Status,
    /// Unlock a passphrase-protected vault in the running keeper.
    Unlock,
    /// Wipe keys from the keeper's memory until the next unlock.
    Lock,
    /// Manage the keeper user service.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// MCP server (stdio) for coding agents: status, doctor, list_secrets (names only).
    Mcp,
    /// Print shell `export` lines that load the shims for this project (used by agent hooks).
    Env {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    Install,
    Uninstall,
    Status,
}

type R<T> = Result<T, String>;

pub fn main() -> ExitCode {
    // Behave like other CLIs when piped into `head`: exit quietly on a closed pipe.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Init {
            yes,
            dry_run,
            protect,
            no_service,
            dir,
        } => init(&dir_or_cwd(dir), yes, dry_run, protect, no_service),
        Cmd::Protect {
            name,
            file,
            form,
            allow,
        } => protect_one(&cwd(), &name, file, form, allow),
        Cmd::Set {
            name,
            file,
            form,
            allow,
            stdin,
        } => set(&cwd(), &name, &file, form, allow, stdin),
        Cmd::Eject { keep_keys, dir } => eject(&dir_or_cwd(dir), keep_keys),
        Cmd::Doctor { dir } => return doctor::run(&dir_or_cwd(dir)),
        Cmd::Run { cmd } => run_cmd(&cmd),
        Cmd::Log { lines, json } => log(lines, json),
        Cmd::Policy {
            name,
            allow,
            deny,
            rate,
            no_rate,
            confirm,
            no_confirm,
            allow_service,
            deny_service,
        } => policy(
            &cwd(),
            name,
            PolicyEdit {
                allow,
                deny,
                rate,
                no_rate,
                confirm,
                no_confirm,
                allow_service,
                deny_service,
            },
        ),
        Cmd::List { dir } => list(&dir_or_cwd(dir)),
        Cmd::Status => status(),
        Cmd::Unlock => unlock(),
        Cmd::Lock => Client::connect()
            .and_then(|mut c| c.call("lock", json!({})))
            .map(|_| println!("Keeper locked: keys wiped from memory."))
            .map_err(|e| e.to_string()),
        Cmd::Service { action } => match action {
            ServiceAction::Install => service::install().map(|m| println!("{m}")),
            ServiceAction::Uninstall => service::uninstall().map(|m| println!("{m}")),
            ServiceAction::Status => {
                println!(
                    "{}: {}",
                    service::unit_path().display(),
                    if service::installed() {
                        "installed"
                    } else {
                        "not installed"
                    }
                );
                Ok(())
            }
        },
        Cmd::Mcp => mcp::serve(),
        Cmd::Env { dir } => print_env(&dir_or_cwd(dir)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("doppelkey: {e}");
            ExitCode::from(1)
        }
    }
}

fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
fn dir_or_cwd(d: Option<PathBuf>) -> PathBuf {
    let d = d.unwrap_or_else(cwd);
    fs::canonicalize(&d).unwrap_or(d)
}

// ---------- vault access ----------

pub struct Vault {
    path: PathBuf,
    header: Header,
    kek: crate::state::LockedKey,
    pub data: VaultData,
    /// Passphrase used this session (to unlock a freshly started keeper).
    passphrase: Option<String>,
}

impl Vault {
    pub fn open() -> R<Vault> {
        let path = paths::vault_file();
        if !path.exists() {
            return Err("no vault yet. Run \"doppelkey init\" first".into());
        }
        let (header, _, _) = store::read_header(&path)?;
        let passphrase = if header.kek == KekKind::Passphrase {
            Some(prompt::passphrase("Vault passphrase: ")?)
        } else {
            None
        };
        let kek = store::kek_for(&header, passphrase.as_deref())?;
        let (header, data) = store::open(&path, kek.bytes())?;
        Ok(Vault {
            path,
            header,
            kek,
            data,
            passphrase,
        })
    }

    fn open_or_create(kind: Option<KekKind>) -> R<Vault> {
        let path = paths::vault_file();
        if path.exists() {
            return Vault::open();
        }
        let kind = match kind {
            Some(k) => k,
            None if cfg!(all(target_os = "macos", feature = "macos-keychain")) => KekKind::Keychain,
            None if prompt::is_interactive() || std::env::var_os("DOPPELKEY_PASSPHRASE").is_some() => KekKind::Passphrase,
            None => return Err("choose how to protect the new vault: --protect passphrase (recommended) or --protect file (no protection at rest)".into()),
        };
        let passphrase = if kind == KekKind::Passphrase {
            println!("Creating the doppelkey vault. Its passphrase unlocks the keeper after each login; agents never see it.");
            Some(prompt::new_passphrase()?)
        } else {
            None
        };
        if kind == KekKind::File {
            eprintln!("doppelkey: warning: --protect file stores the vault key next to the vault. A same-user process can read both; use it only for throwaway keys.");
        }
        store::create(&path, kind, passphrase.as_deref())?;
        let kek = store::kek_for(&store::read_header(&path)?.0, passphrase.as_deref())?;
        let (header, data) = store::open(&path, kek.bytes())?;
        Ok(Vault {
            path,
            header,
            kek,
            data,
            passphrase,
        })
    }

    pub fn save(&self) -> R<()> {
        store::save(&self.path, &self.header, self.kek.bytes(), &self.data)
    }
}

/// Tell the keeper about vault changes; start it if needed. Returns a status line.
fn sync_keeper(v: &Vault, start: bool) -> String {
    match client::reload_keeper() {
        Ok(true) => {
            if let Some(p) = &v.passphrase {
                if let Ok(mut c) = Client::connect() {
                    let _ = c.call("unlock", json!({ "passphrase": p }));
                }
            }
            "keeper updated".into()
        }
        Ok(false) if start => match service::install() {
            Ok(m) => {
                if let Some(p) = &v.passphrase {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    if let Ok(mut c) = Client::connect() {
                        let _ = c.call("unlock", json!({ "passphrase": p }));
                    }
                }
                m
            }
            Err(e) => format!("could not start the keeper: {e}"),
        },
        Ok(false) => "keeper not running (start it with \"doppelkey service install\")".into(),
        Err(e) => format!("keeper did not reload: {e}"),
    }
}

/// A human must approve: a terminal prompt, or a prompt shown by the keeper. The keeper runs
/// its prompt with its own environment, so a non-interactive caller (an agent) can't approve
/// its own request, e.g. by setting DOPPELKEY_ASKPASS for this process.
fn human_confirm(action: &str, detail: &str) -> bool {
    if prompt::is_interactive() {
        return prompt::yes_no(&format!("Allow doppelkey to {detail}?"));
    }
    match Client::connect()
        .and_then(|mut c| c.call("confirm", json!({ "action": action, "detail": detail })))
    {
        Ok(r) => r.get("allowed") == Some(&json!(true)),
        Err(e) => {
            eprintln!("doppelkey: cannot ask for confirmation: {e}");
            false
        }
    }
}

fn new_id(v: &VaultData) -> String {
    loop {
        let id = handle::new_id(crate::crypto::random_bytes::<6>());
        if !v.keys.contains_key(&id) {
            return id;
        }
    }
}

fn now() -> String {
    audit::now_rfc3339()
}

// ---------- init / protect / set ----------

struct Planned {
    file: PathBuf,
    var: envfile::Var,
    plan: classify::Plan,
}

fn init(dir: &Path, yes: bool, dry_run: bool, protect: Option<KekKind>, no_service: bool) -> R<()> {
    let files = project::env_files(dir);
    let mut planned = Vec::new();
    println!("doppelkey init: {}", dir.display());
    if files.is_empty() {
        println!("  no .env files found (add secrets later with \"doppelkey set NAME\")");
    }
    for f in &files {
        let text =
            fs::read_to_string(f).map_err(|e| format!("cannot read {}: {e}", f.display()))?;
        let vars = envfile::parse(&text);
        let others: Vec<(String, String)> = vars
            .iter()
            .map(|v| (v.name.clone(), v.value.clone()))
            .collect();
        println!("\n  {}", project::rel(dir, f));
        for var in vars {
            match classify::classify(&var.name, &var.value, &others) {
                Decision::Protect(plan) => {
                    println!(
                        "    + {:<28} protect: {} ({:?} handle, allows {})",
                        var.name,
                        plan.kind,
                        plan.form,
                        plan.policy.allow.join(", ")
                    );
                    planned.push(Planned {
                        file: f.clone(),
                        var,
                        plan,
                    });
                }
                Decision::Skip(why) => println!("    - {:<28} skip: {why}", var.name),
            }
        }
    }
    let al = project::autoload_for(dir);
    let (changes, notes) = project::plan_autoload(dir, &al);
    if !changes.is_empty() {
        println!("\n  Files to update so normal commands load the shim:");
        for c in &changes {
            println!(
                "    {} {:<34} {}",
                if c.existed { "~" } else { "+" },
                project::rel(dir, &c.path),
                c.purpose
            );
        }
    }
    for n in &notes {
        println!("  note: {n}");
    }
    if dry_run {
        println!("\nDry run: nothing changed.");
        return Ok(());
    }
    if planned.is_empty() && changes.is_empty() {
        println!("\nNothing to do.");
        return Ok(());
    }
    if !yes {
        if !prompt::is_interactive() {
            return Err("this is a preview. Run \"doppelkey init --yes\" to apply it".into());
        }
        if !prompt::yes_no("\nApply these changes?") {
            return Err("cancelled".into());
        }
    }
    let mut v = Vault::open_or_create(protect)?;
    let mut manifest = Manifest::load(dir).unwrap_or(Manifest {
        version: 1,
        ..Default::default()
    });
    let mut by_file: BTreeMap<PathBuf, Vec<Planned>> = BTreeMap::new();
    for p in planned {
        by_file.entry(p.file.clone()).or_default().push(p);
    }
    let mut count = 0;
    for (file, items) in by_file {
        let text = fs::read_to_string(&file).map_err(|e| e.to_string())?;
        let mut edits = Vec::new();
        for p in items {
            let id = reuse_or_new(&v.data, dir, &p.plan.key);
            let written =
                handle::env_value(&id, p.plan.form, &p.plan.prefix, p.plan.key.len(), false)?;
            v.data.keys.entry(id.clone()).or_insert_with(|| StoredKey {
                name: p.var.name.clone(),
                value: B64.encode(&p.plan.key),
                policy: p.plan.policy.clone(),
                form: p.plan.form,
                project: Some(dir.display().to_string()),
                file: Some(file.display().to_string()),
                original: Some(p.var.value.clone()),
                written: Some(written.clone()),
                created: now(),
            });
            manifest.secrets.push(SecretRec {
                name: p.var.name.clone(),
                file: project::rel(dir, &file),
                id,
            });
            edits.push((p.var.start, p.var.end, written));
            count += 1;
        }
        fs::write(&file, envfile::splice(&text, edits))
            .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    }
    apply_changes(dir, &mut v, &mut manifest, changes)?;
    v.save()?;
    manifest.save(dir)?;
    let keeper = if no_service {
        "keeper not started (--no-service)".to_string()
    } else {
        sync_keeper(&v, true)
    };
    println!("\nProtected {count} secret(s); {keeper}.");
    println!("Next: run your app and tests as usual. Check the setup with \"doppelkey doctor\"; undo with \"doppelkey eject\".");
    Ok(())
}

/// Same value in the same project gets the same handle (e.g. in .env and .env.local).
fn reuse_or_new(data: &VaultData, dir: &Path, key: &[u8]) -> String {
    let want = B64.encode(key);
    let proj = dir.display().to_string();
    data.keys
        .iter()
        .find(|(_, k)| k.value == want && k.project.as_deref() == Some(proj.as_str()))
        .map(|(id, _)| id.clone())
        .unwrap_or_else(|| new_id(data))
}

fn apply_changes(
    dir: &Path,
    v: &mut Vault,
    manifest: &mut Manifest,
    changes: Vec<project::Change>,
) -> R<()> {
    for c in changes {
        let abs = c.path.display().to_string();
        if c.existed && !v.data.backups.contains_key(&abs) {
            let orig = fs::read(&c.path).map_err(|e| e.to_string())?;
            v.data.backups.insert(abs.clone(), B64.encode(orig));
        }
        let mut created_dir = None;
        if let Some(parent) = c.path.parent() {
            if !parent.exists() {
                created_dir = Some(project::rel(dir, parent));
            }
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(&c.path, &c.new_content)
            .map_err(|e| format!("cannot write {}: {e}", c.path.display()))?;
        manifest
            .files
            .retain(|f| f.path != project::rel(dir, &c.path));
        manifest.files.push(FileRec {
            path: project::rel(dir, &c.path),
            created: !c.existed,
            sha256_after: project::sha256_hex(c.new_content.as_bytes()),
            inserted: c.inserted,
            purpose: c.purpose,
            created_dir,
        });
    }
    Ok(())
}

fn find_env_var(
    dir: &Path,
    name: &str,
    file: Option<PathBuf>,
) -> R<(PathBuf, String, envfile::Var)> {
    let files = match file {
        Some(f) => vec![dir.join(f)],
        None => project::env_files(dir),
    };
    for f in files {
        let text = fs::read_to_string(&f).unwrap_or_default();
        if let Some(var) = envfile::parse(&text).into_iter().find(|v| v.name == name) {
            return Ok((f, text, var));
        }
    }
    Err(format!(
        "{name} is not in any .env file here. Use \"doppelkey set {name}\" to add it"
    ))
}

fn ops_from(allow: Vec<String>) -> R<Vec<String>> {
    for a in &allow {
        if !ALL_OPS.contains(&a.as_str()) {
            return Err(format!(
                "unknown operation \"{a}\" (one of: {})",
                ALL_OPS.join(", ")
            ));
        }
    }
    Ok(allow)
}

fn protect_one(
    dir: &Path,
    name: &str,
    file: Option<PathBuf>,
    form: Option<Form>,
    allow: Vec<String>,
) -> R<()> {
    let (f, text, var) = find_env_var(dir, name, file)?;
    let others = envfile::parse(&text)
        .into_iter()
        .map(|v| (v.name, v.value))
        .collect::<Vec<_>>();
    let mut plan = match classify::classify(name, &var.value, &others) {
        Decision::Protect(p) => p,
        Decision::Skip(why) if why.contains("already") => {
            return Err(format!("{name} is already a doppelkey handle"))
        }
        Decision::Skip(why) => {
            eprintln!("doppelkey: note: {name} would normally be skipped ({why}); protecting it as a signing secret because you asked");
            classify::Plan {
                form: Form::Long,
                prefix: String::new(),
                key: var.value.as_bytes().to_vec(),
                policy: Policy {
                    allow: vec!["hmac".into(), "hkdf".into(), "pbkdf2".into()],
                    ..Default::default()
                },
                kind: "signing secret",
            }
        }
    };
    if let Some(fm) = form {
        if fm != plan.form {
            plan.form = fm;
            plan.prefix.clear();
            plan.key = var.value.as_bytes().to_vec();
            if matches!(fm, Form::Hex | Form::Base64) {
                return Err("--form hex/base64 only applies to values that are hex/base64 encoded; doppelkey picks those automatically".into());
            }
        }
    }
    if !allow.is_empty() {
        plan.policy.allow = ops_from(allow)?;
    }
    let mut v = Vault::open()?;
    let id = reuse_or_new(&v.data, dir, &plan.key);
    let written = handle::env_value(&id, plan.form, &plan.prefix, plan.key.len(), false)?;
    v.data.keys.insert(
        id.clone(),
        StoredKey {
            name: name.into(),
            value: B64.encode(&plan.key),
            policy: plan.policy,
            form: plan.form,
            project: Some(dir.display().to_string()),
            file: Some(f.display().to_string()),
            original: Some(var.value.clone()),
            written: Some(written.clone()),
            created: now(),
        },
    );
    fs::write(
        &f,
        envfile::splice(&text, vec![(var.start, var.end, written)]),
    )
    .map_err(|e| e.to_string())?;
    let mut m = Manifest::load(dir).unwrap_or(Manifest {
        version: 1,
        ..Default::default()
    });
    m.secrets.push(SecretRec {
        name: name.into(),
        file: project::rel(dir, &f),
        id,
    });
    v.save()?;
    m.save(dir)?;
    println!(
        "Protected {name} in {}; {}.",
        project::rel(dir, &f),
        sync_keeper(&v, false)
    );
    Ok(())
}

fn set(
    dir: &Path,
    name: &str,
    file: &Path,
    form: Option<Form>,
    allow: Vec<String>,
    from_stdin: bool,
) -> R<()> {
    let value = if from_stdin {
        let mut s = String::new();
        std::io::stdin()
            .read_line(&mut s)
            .map_err(|e| e.to_string())?;
        s.trim_end_matches(['\n', '\r']).to_string()
    } else {
        prompt::secret(&format!("Value for {name} (input hidden): "))?
    };
    if value.is_empty() {
        return Err("empty value".into());
    }
    let mut plan = match classify::classify(name, &value, &[]) {
        Decision::Protect(p) => p,
        Decision::Skip(why) if why.contains("already") => {
            return Err("that value is already a doppelkey handle".into())
        }
        Decision::Skip(_) => classify::Plan {
            form: Form::Long,
            prefix: String::new(),
            key: value.as_bytes().to_vec(),
            policy: Policy {
                allow: vec!["hmac".into(), "hkdf".into(), "pbkdf2".into()],
                ..Default::default()
            },
            kind: "signing secret",
        },
    };
    if let Some(fm) = form.filter(|f| matches!(f, Form::Long | Form::Compact)) {
        plan.form = fm;
        plan.prefix.clear();
        plan.key = value.as_bytes().to_vec();
    }
    if !allow.is_empty() {
        plan.policy.allow = ops_from(allow)?;
    }
    let mut v = Vault::open_or_create(None)?;
    let id = reuse_or_new(&v.data, dir, &plan.key);
    let written = handle::env_value(&id, plan.form, &plan.prefix, plan.key.len(), false)?;
    let path = dir.join(file);
    let text = fs::read_to_string(&path).unwrap_or_default();
    let new_text = match envfile::parse(&text).into_iter().find(|x| x.name == name) {
        Some(var) => envfile::splice(&text, vec![(var.start, var.end, written.clone())]),
        None => format!(
            "{text}{}{name}={written}\n",
            if text.is_empty() || text.ends_with('\n') {
                ""
            } else {
                "\n"
            }
        ),
    };
    v.data.keys.insert(
        id.clone(),
        StoredKey {
            name: name.into(),
            value: B64.encode(&plan.key),
            policy: plan.policy,
            form: plan.form,
            project: Some(dir.display().to_string()),
            file: Some(path.display().to_string()),
            original: Some(value),
            written: Some(written),
            created: now(),
        },
    );
    fs::write(&path, new_text).map_err(|e| e.to_string())?;
    let mut m = Manifest::load(dir).unwrap_or(Manifest {
        version: 1,
        ..Default::default()
    });
    m.secrets
        .retain(|s| !(s.name == name && s.file == project::rel(dir, &path)));
    m.secrets.push(SecretRec {
        name: name.into(),
        file: project::rel(dir, &path),
        id,
    });
    v.save()?;
    m.save(dir)?;
    println!(
        "Stored {name}; {} now holds its handle; {}.",
        project::rel(dir, &path),
        sync_keeper(&v, false)
    );
    Ok(())
}

// ---------- eject ----------

fn eject(dir: &Path, keep_keys: bool) -> R<()> {
    let m = Manifest::load(dir).ok_or(
        "this project has no doppelkey manifest (.doppelkey/manifest.json); nothing to eject",
    )?;
    if !human_confirm(
        "eject",
        &format!(
            "write the real values of the secrets back into the .env files of {}",
            dir.display()
        ),
    ) {
        return Err("eject writes real secrets to disk, so a human must confirm it in a terminal or in the keeper's prompt. Nothing changed".into());
    }
    let mut v = Vault::open()?;
    let mut problems = Vec::new();
    let mut by_file: BTreeMap<String, Vec<&SecretRec>> = BTreeMap::new();
    for s in &m.secrets {
        by_file.entry(s.file.clone()).or_default().push(s);
    }
    for (file, secrets) in by_file {
        let path = dir.join(&file);
        let mut text = fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        for s in secrets {
            let Some(k) = v.data.keys.get(&s.id) else {
                problems.push(format!("{}: {} is not in the vault", file, s.name));
                continue;
            };
            let (Some(written), Some(original)) = (&k.written, &k.original) else {
                continue;
            };
            if text.contains(written.as_str()) {
                text = text.replace(written.as_str(), original);
            } else {
                problems.push(format!(
                    "{file}: the handle for {} was not found (edited by hand?)",
                    s.name
                ));
            }
        }
        fs::write(&path, text).map_err(|e| e.to_string())?;
    }
    for f in m.files.iter().rev() {
        let path = dir.join(&f.path);
        let abs = path.display().to_string();
        let Ok(cur) = fs::read(&path) else { continue };
        let untouched = project::sha256_hex(&cur) == f.sha256_after;
        if f.created && untouched {
            let _ = fs::remove_file(&path);
        } else if !f.created && untouched {
            if let Some(orig) = v.data.backups.get(&abs).and_then(|b| B64.decode(b).ok()) {
                fs::write(&path, orig).map_err(|e| e.to_string())?;
            }
        } else if let Some(ins) = f
            .inserted
            .as_deref()
            .filter(|i| String::from_utf8_lossy(&cur).contains(*i))
        {
            let s = String::from_utf8_lossy(&cur).replacen(ins, "", 1);
            if f.created && s.trim().is_empty() {
                let _ = fs::remove_file(&path);
            } else {
                fs::write(&path, s).map_err(|e| e.to_string())?;
            }
        } else {
            problems.push(format!(
                "{}: changed since init; remove the doppelkey lines by hand",
                f.path
            ));
        }
        v.data.backups.remove(&abs);
        if let Some(d) = &f.created_dir {
            let _ = fs::remove_dir(dir.join(d)); // only succeeds if empty
        }
    }
    if !keep_keys {
        let others = other_manifests_ids(dir);
        for s in &m.secrets {
            if !others.contains(&s.id) {
                v.data.keys.remove(&s.id);
            }
        }
    }
    let _ = fs::remove_file(dir.join(project::MANIFEST));
    let _ = fs::remove_dir(dir.join(".doppelkey"));
    v.save()?;
    let k = sync_keeper(&v, false);
    for p in &problems {
        eprintln!("doppelkey: warning: {p}");
    }
    println!(
        "Ejected: real values restored in {} secret(s); {k}.",
        m.secrets.len()
    );
    Ok(())
}

fn other_manifests_ids(_dir: &Path) -> Vec<String> {
    Vec::new()
}

// ---------- run / log / status / unlock / list ----------

fn run_cmd(cmd: &[String]) -> R<()> {
    use std::os::unix::process::CommandExt;
    let al = project::autoload_for(&cwd());
    let mut c = std::process::Command::new(&cmd[0]);
    c.args(&cmd[1..]);
    if let Some(req) = &al.node_require {
        let cur = std::env::var("NODE_OPTIONS").unwrap_or_default();
        c.env("NODE_OPTIONS", format!("{cur} --require {req}").trim());
    }
    if let Some(py) = &al.python_dir {
        let cur = std::env::var("PYTHONPATH").unwrap_or_default();
        let sep = if cur.is_empty() { "" } else { ":" };
        c.env("PYTHONPATH", format!("{}{sep}{cur}", py.display()));
    }
    if let Some(rb) = &al.ruby_register {
        let cur = std::env::var("RUBYOPT").unwrap_or_default();
        c.env("RUBYOPT", format!("{cur} -r{}", rb.display()).trim());
    }
    if let Some(jar) = &al.java_agent {
        let cur = std::env::var("JAVA_TOOL_OPTIONS").unwrap_or_default();
        c.env(
            "JAVA_TOOL_OPTIONS",
            format!("{cur} -javaagent:{}", jar.display()).trim(),
        );
    }
    let e = c.exec();
    Err(format!("cannot run {}: {e}", cmd[0]))
}

fn log(lines: usize, as_json: bool) -> R<()> {
    let p = paths::audit_file();
    let text =
        fs::read_to_string(&p).map_err(|_| format!("no audit log at {} yet", p.display()))?;
    let all: Vec<&str> = text.lines().collect();
    for l in &all[all.len().saturating_sub(lines)..] {
        if as_json {
            println!("{l}");
            continue;
        }
        let e: serde_json::Value = serde_json::from_str(l).unwrap_or_default();
        let s = |k: &str| e.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let ok = if e.get("ok") == Some(&json!(true)) {
            "ok".to_string()
        } else {
            s("code")
        };
        let who = match (e.get("pid"), s("exe")) {
            (Some(p), x) if !x.is_empty() => format!("{x} [{p}]"),
            (Some(p), _) => format!("pid {p}"),
            _ => String::new(),
        };
        println!(
            "{}  {:<11} {:<24} {:<16} {} {}",
            s("ts"),
            s("op"),
            s("key"),
            ok,
            s("scope"),
            who
        );
    }
    Ok(())
}

fn status() -> R<()> {
    let vault = paths::vault_file();
    match store::read_header(&vault) {
        Ok((h, _, _)) => println!("vault:   {} (protected by {:?})", vault.display(), h.kek),
        Err(_) => println!("vault:   none (run \"doppelkey init\")"),
    }
    match Client::connect().and_then(|mut c| c.call("status", json!({}))) {
        Ok(s) => {
            println!(
                "keeper:  {} at {}{}",
                s["version"].as_str().unwrap_or("?"),
                paths::socket_path().display(),
                if s["locked"] == json!(true) {
                    " (locked: run \"doppelkey unlock\")"
                } else {
                    ""
                }
            );
            let names: Vec<&str> = s["keys"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            println!(
                "keys:    {}",
                if names.is_empty() {
                    "none".into()
                } else {
                    names.join(", ")
                }
            );
        }
        Err(e) => println!("keeper:  {e}"),
    }
    println!("audit:   {}", paths::audit_file().display());
    Ok(())
}

fn unlock() -> R<()> {
    let (h, _, _) = store::read_header(&paths::vault_file())
        .map_err(|_| "no vault yet. Run \"doppelkey init\"".to_string())?;
    let mut c = Client::connect().map_err(|e| e.to_string())?;
    let pass = if h.kek == KekKind::Passphrase {
        Some(prompt::passphrase("Vault passphrase: ")?)
    } else {
        None
    };
    c.call("unlock", json!({ "passphrase": pass }))
        .map_err(|e| e.to_string())?;
    println!("Keeper unlocked.");
    Ok(())
}

fn list(dir: &Path) -> R<()> {
    let m = Manifest::load(dir).ok_or("no doppelkey manifest here (run \"doppelkey init\")")?;
    for s in &m.secrets {
        println!("{:<28} {:<20} id {}", s.name, s.file, s.id);
    }
    Ok(())
}

/// `export` lines for a POSIX shell. Values are single-quoted; existing values are kept.
fn print_env(dir: &Path) -> R<()> {
    let al = project::autoload_for(dir);
    let q = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    if let Some(req) = &al.node_require {
        println!(
            "export NODE_OPTIONS=\"${{NODE_OPTIONS:+$NODE_OPTIONS }}\"{}",
            q(&format!("--require {req}"))
        );
    }
    let is_python = [
        "manage.py",
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "Pipfile",
    ]
    .iter()
    .any(|f| dir.join(f).exists());
    if let (true, Some(py)) = (is_python, &al.python_dir) {
        println!(
            "export PYTHONPATH={}\"${{PYTHONPATH:+:$PYTHONPATH}}\"",
            q(&py.display().to_string())
        );
    }
    if let (true, Some(rb)) = (dir.join("Gemfile").exists(), &al.ruby_register) {
        println!(
            "export RUBYOPT=\"${{RUBYOPT:+$RUBYOPT }}\"{}",
            q(&format!("-r{}", rb.display()))
        );
    }
    let is_java = ["pom.xml", "build.gradle", "build.gradle.kts"]
        .iter()
        .any(|f| dir.join(f).exists());
    if let (true, Some(jar)) = (is_java, &al.java_agent) {
        println!(
            "export JAVA_TOOL_OPTIONS=\"${{JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }}\"{}",
            q(&format!("-javaagent:{}", jar.display()))
        );
    }
    if let Some(sock) = std::env::var_os("DOPPELKEY_SOCK") {
        println!("export DOPPELKEY_SOCK={}", q(&sock.to_string_lossy()));
    }
    Ok(())
}

// ---------- policy ----------

struct PolicyEdit {
    allow: Vec<String>,
    deny: Vec<String>,
    rate: Option<u32>,
    no_rate: bool,
    confirm: bool,
    no_confirm: bool,
    allow_service: Vec<String>,
    deny_service: Vec<String>,
}

impl PolicyEdit {
    fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.deny.is_empty()
            && self.rate.is_none()
            && !self.no_rate
            && !self.confirm
            && !self.no_confirm
            && self.allow_service.is_empty()
            && self.deny_service.is_empty()
    }
    /// Does this edit make the key usable in more ways? Those need a human.
    fn loosens(&self) -> bool {
        !self.allow.is_empty() || self.no_rate || self.no_confirm || !self.allow_service.is_empty()
    }
}

fn ids_for_name(dir: &Path, v: &VaultData, name: &str) -> R<Vec<String>> {
    if let Some(m) = Manifest::load(dir) {
        let ids: Vec<String> = m
            .secrets
            .iter()
            .filter(|s| s.name == name)
            .map(|s| s.id.clone())
            .collect();
        if !ids.is_empty() {
            return Ok(ids);
        }
    }
    let ids: Vec<String> = v
        .keys
        .iter()
        .filter(|(_, k)| k.name == name)
        .map(|(id, _)| id.clone())
        .collect();
    match ids.len() {
        0 => Err(format!("no key named {name} in the vault")),
        _ => Ok(ids),
    }
}

fn policy_toml(name: &str, p: &Policy) -> String {
    let mut t = toml::Table::new();
    let v = toml::Value::try_from(p).unwrap_or(toml::Value::Table(Default::default()));
    t.insert(name.to_string(), v);
    toml::to_string(&t).unwrap_or_default()
}

fn policy(dir: &Path, name: Option<String>, edit: PolicyEdit) -> R<()> {
    let mut v = Vault::open()?;
    let Some(name) = name else {
        for k in v.data.keys.values() {
            print!("{}", policy_toml(&k.name, &k.policy));
        }
        return Ok(());
    };
    let ids = ids_for_name(dir, &v.data, &name)?;
    if edit.is_empty() {
        for id in &ids {
            print!("{}", policy_toml(&name, &v.data.keys[id].policy));
        }
        return Ok(());
    }
    let mut allow_ops = Vec::new();
    let mut sigv2 = None;
    for a in &edit.allow {
        if a == "sigv2" {
            sigv2 = Some(true);
        } else {
            allow_ops.push(a.clone());
        }
    }
    let deny_sigv2 = edit.deny.iter().any(|d| d == "sigv2");
    let allow_ops = ops_from(allow_ops)?;
    if edit.loosens() && !human_confirm("loosen_policy", &format!("loosen the policy for {name}")) {
        return Err("loosening a policy needs a human to confirm it in a terminal or in the keeper's prompt. Nothing changed".into());
    }
    for id in &ids {
        let p = &mut v.data.keys.get_mut(id).unwrap().policy;
        for a in &allow_ops {
            if !p.allow.contains(a) {
                p.allow.push(a.clone());
            }
        }
        p.allow.retain(|a| !edit.deny.contains(a));
        if let Some(s) = sigv2 {
            p.sigv2 = s;
        }
        if deny_sigv2 {
            p.sigv2 = false;
        }
        if let Some(r) = edit.rate {
            p.rate_per_minute = Some(r);
        }
        if edit.no_rate {
            p.rate_per_minute = None;
        }
        if edit.confirm {
            p.confirm = true;
        }
        if edit.no_confirm {
            p.confirm = false;
        }
        if !edit.allow_service.is_empty() || !edit.deny_service.is_empty() {
            let mut s = p.services.clone().unwrap_or_default();
            for x in &edit.allow_service {
                if !s.contains(x) {
                    s.push(x.clone());
                }
            }
            s.retain(|x| !edit.deny_service.contains(x));
            p.services = Some(s);
        }
        print!("{}", policy_toml(&name, p));
    }
    v.save()?;
    println!("# {}", sync_keeper(&v, false));
    Ok(())
}
