//! `doppelkeyd`: the keeper daemon entry point.

use crate::audit::Audit;
use crate::server::{self, Shared, Source};
use crate::state::State;
use crate::{harden, paths, store};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(
    name = "doppelkeyd",
    version,
    about = "doppelkey keeper: holds app keys and performs operations on them; never exports them"
)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Socket path (default: $DOPPELKEY_SOCK, $XDG_RUNTIME_DIR/doppelkey/doppelkeyd.sock, or <tmp>/doppelkey-<uid>/)
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Audit log (default: the state directory's audit.jsonl)
    #[arg(long, global = true)]
    audit: Option<PathBuf>,
    /// Encrypted vault file (default: the config directory's vault.dk)
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the encrypted vault (the default).
    Serve,
    /// TEST ONLY: serve a plaintext JSON vault of fake secrets (used by compat/).
    InsecureTestKeeper,
}

pub fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let bad = harden::injection_vars();
    if !bad.is_empty() {
        eprintln!("doppelkeyd: refusing to start with {} set: it could inject code into the keeper. Unset it, or run \"doppelkey doctor\".", bad.join(", "));
        return std::process::ExitCode::from(1);
    }
    for note in harden::apply() {
        eprintln!("doppelkeyd: warning: {note}");
    }
    let socket = args.socket.unwrap_or_else(paths::socket_path);
    let (source, state, audit) = match args.cmd {
        Some(Cmd::InsecureTestKeeper) => {
            let Some(v) = args.vault else {
                eprintln!("doppelkeyd: insecure-test-keeper needs --vault <test-vault.json>");
                return std::process::ExitCode::from(2);
            };
            match store::load_test_vault(&v) {
                Ok(s) => (Source::TestVault(v), s, args.audit),
                Err(e) => {
                    eprintln!("doppelkeyd: {e}");
                    return std::process::ExitCode::from(1);
                }
            }
        }
        _ => {
            let path = args.vault.unwrap_or_else(paths::vault_file);
            let audit = Some(args.audit.unwrap_or_else(paths::audit_file));
            (
                Source::Vault {
                    path,
                    kek: Mutex::new(None),
                },
                State::locked(),
                audit,
            )
        }
    };
    let shared = Arc::new(Shared::new(state, Audit::new(audit), source));
    if let Source::Vault { path, .. } = &shared.source {
        // Vaults protected by the Keychain or a key file unlock at start; passphrase vaults wait for `doppelkey unlock`.
        match store::read_header(path) {
            Ok((h, _, _)) if h.kek != store::KekKind::Passphrase => {
                if let Err(e) = server::reload_now(&shared) {
                    eprintln!("doppelkeyd: could not unlock the vault: {e}");
                }
            }
            Ok(_) => eprintln!(
                "doppelkeyd: vault is passphrase-protected; waiting for \"doppelkey unlock\""
            ),
            Err(_) => eprintln!(
                "doppelkeyd: no vault at {} yet; run \"doppelkey init\"",
                path.display()
            ),
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let sock_for_cleanup = socket.clone();
    let result = rt.block_on(async move {
        let serve = server::serve(&socket, shared, |p| {
            println!("doppelkey keeper listening on {}", p.display())
        });
        tokio::select! {
            r = serve => r,
            _ = shutdown() => Ok(()),
        }
    });
    let _ = std::fs::remove_file(&sock_for_cleanup);
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("doppelkeyd: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

async fn shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("signal");
    let mut int = signal(SignalKind::interrupt()).expect("signal");
    tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
}
