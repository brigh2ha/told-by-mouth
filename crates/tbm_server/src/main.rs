//! `tbm_server --config /etc/tbm/tbm-server.toml`
//! `tbm_server --config ... --print-server-key` prints the public key to build into the apps.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tbm_core::crypto::{hex, Signer};
use tbm_server::config::Config;
use tbm_server::providers::{
    Attestation, DevAttestation, DevIdentity, IdentityProvider, NotConfigured,
};
use tbm_server::{app, db::Db, keys, system_clock, AppState};

fn usage() -> ! {
    eprintln!("usage: tbm_server --config <file> [--print-server-key]");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tbm_server=info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mut config_path = None;
    let mut print_key = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config_path = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--print-server-key" => print_key = true,
            _ => usage(),
        }
    }
    let config_path = config_path.unwrap_or_else(|| usage());
    let cfg = Config::load(&config_path).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    let key = keys::load_or_create(&cfg.server_key).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    if print_key {
        println!("server_key_id = {}", cfg.server_key_id);
        println!("public_key    = {}", hex(&key.public_key().0));
        return;
    }

    let admin_token = match &cfg.admin_token_file {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(t) if t.trim().len() >= 32 => Some(t.trim().to_owned()),
            Ok(_) => {
                eprintln!(
                    "{}: admin token must be at least 32 characters",
                    p.display()
                );
                std::process::exit(1);
            }
            Err(e) => {
                tracing::warn!("admin endpoints off: cannot read {}: {e}", p.display());
                None
            }
        },
        None => None,
    };

    let (identity, attestation): (Box<dyn IdentityProvider>, Box<dyn Attestation>) = if cfg.dev_mode
    {
        tracing::warn!("DEV MODE: stub identity check and stub attestation accept anyone. Never use in production.");
        (Box::new(DevIdentity), Box::new(DevAttestation))
    } else {
        (Box::new(NotConfigured), Box::new(NotConfigured))
    };

    let db = Db::open(&cfg.database).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let state = Arc::new(AppState {
        db: Mutex::new(db),
        key,
        key_id: cfg.server_key_id,
        identity,
        attestation,
        admin_token,
        clock: system_clock(),
    });

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("cannot listen on {}: {e}", cfg.listen);
            std::process::exit(1);
        });
    tracing::info!("listening on {}", cfg.listen);
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown())
        .await
        .expect("server error");
}

/// Stops on Ctrl-C or SIGTERM (what systemd sends).
async fn shutdown() {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
    }
    tracing::info!("shutting down");
}
