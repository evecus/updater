//! Linux 更新管理器（Rust 重写版）程序入口（对应 Go 版 main.go）。

mod auth;
mod downloader;
mod github;
mod panel;
mod scheduler;
mod server;
mod store;
mod updater;

use scheduler::Scheduler;
use server::{AppState, build_router};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use store::Store;

struct Config {
    data_dir: PathBuf,
    port: u16,
    password: String,
}

fn parse_args() -> Config {
    let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let default_data = exe
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("data");

    let mut data_dir = default_data;
    let mut port: u16 = 9191;
    let mut password = String::new();

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (key, inline_val) = match arg.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let take_value = |i: &mut usize| -> Option<String> {
            if let Some(v) = &inline_val {
                return Some(v.clone());
            }
            if *i + 1 < args.len() {
                *i += 1;
                Some(args[*i].clone())
            } else {
                None
            }
        };
        match key.as_str() {
            "--dir" | "-dir" => {
                if let Some(v) = take_value(&mut i) {
                    data_dir = PathBuf::from(v);
                }
            }
            "--port" | "-port" => {
                if let Some(v) = take_value(&mut i) {
                    port = v.parse().unwrap_or(port);
                }
            }
            "--password" | "-password" => {
                if let Some(v) = take_value(&mut i) {
                    password = v;
                }
            }
            "--help" | "-h" => {
                println!("用法: updater [选项]\n  --dir <path>       数据目录 (默认 <程序目录>/data)\n  --port <int>       Web 面板端口 (默认 9191)\n  --password <str>   启用登录鉴权 (或设置 UPDATER_PASSWORD 环境变量)");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    // --password 优先；未设置则回退到环境变量。
    if password.is_empty() {
        password = env::var("UPDATER_PASSWORD").unwrap_or_default();
    }

    Config {
        data_dir,
        port,
        password,
    }
}

#[tokio::main]
async fn main() {
    let cfg = parse_args();

    if let Err(e) = fs::create_dir_all(&cfg.data_dir) {
        eprintln!("failed to create data dir: {}", e);
        std::process::exit(1);
    }

    let store = Arc::new(Store::new(cfg.data_dir.clone()));
    if let Err(e) = store.load() {
        eprintln!("failed to load store: {}", e);
        std::process::exit(1);
    }

    let scheduler = Arc::new(Scheduler::new(store.clone()));
    scheduler.start();

    let auth = Arc::new(auth::Auth::new(cfg.password));
    if auth.enabled() {
        let a = auth.clone();
        tokio::spawn(async move { a.gc().await });
        eprintln!(
            "login auth enabled (brute-force protection: lock IP for 15min after 5 failed attempts within 10min)"
        );
    } else {
        eprintln!("login auth disabled (no --password / UPDATER_PASSWORD set)");
    }

    let state = AppState {
        store: store.clone(),
        scheduler,
        auth,
    };
    let app = build_router(state);

    let addr: SocketAddr = format!("0.0.0.0:{}", cfg.port)
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 9191)));
    eprintln!(
        "updater panel running at http://{}  (data: {})",
        addr,
        cfg.data_dir.display()
    );

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("server error: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        eprintln!("server error: {}", e);
        std::process::exit(1);
    }
}
