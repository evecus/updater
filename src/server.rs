//! HTTP 服务器与全部 API 路由（对应 Go 版 server.go）。

use crate::auth::{self, Auth};
use crate::github::parse_owner_repo;
use crate::panel::PANEL_HTML;
use crate::scheduler::Scheduler;
use crate::store::{Store, Task, UpdateType};
use crate::updater::{check_update, run_update, TaskLogger};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub scheduler: Arc<Scheduler>,
    pub auth: Arc<Auth>,
}

pub fn build_router(state: AppState) -> Router {
    let inner = Router::new()
        .route("/", get(handle_index))
        .route(
            "/api/tasks",
            get(handle_tasks_list).post(handle_tasks_create),
        )
        .route(
            "/api/tasks/:id",
            get(handle_task_get).put(handle_task_put).delete(handle_task_delete),
        )
        .route("/api/check/:id", post(handle_check))
        .route("/api/update/:id", post(handle_update))
        .route("/api/logs/:id", get(handle_logs))
        .route(
            "/api/settings",
            get(handle_settings_get).put(handle_settings_put),
        )
        .route("/login", get(handle_login_page))
        .route("/api/login", post(handle_login_api))
        .route("/api/logout", post(handle_logout_api));

    inner
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

/// 鉴权中间件：未登录时 API 返回 401，页面重定向到 /login。
async fn auth_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    if !state.auth.enabled() || auth::is_public_auth_path(&path) {
        return next.run(req).await;
    }
    if !state.auth.is_authed(req.headers()) {
        if path.starts_with("/api/") {
            return auth::json_response(
                StatusCode::UNAUTHORIZED,
                &serde_json::json!({"error": "unauthorized"}),
                &HeaderMap::new(),
            );
        }
        // 对齐 Go 的 http.Redirect(..., http.StatusFound) 即 302。
        return (
            StatusCode::FOUND,
            [(header::LOCATION, "/login")],
        )
            .into_response();
    }
    let _ = addr; // 保留 ConnectInfo 提取以确保扩展可用
    next.run(req).await
}

fn json_err(code: StatusCode, msg: &str) -> Response {
    auth::json_response(code, &serde_json::json!({"error": msg}), &HeaderMap::new())
}

async fn handle_index() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(PANEL_HTML),
    )
        .into_response()
}

async fn handle_login_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    state.auth.handle_login_page(&headers)
}

async fn handle_login_api(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state
        .auth
        .handle_login_api(&headers, Some(&addr.to_string()), &body)
}

async fn handle_logout_api(State(state): State<AppState>, headers: HeaderMap) -> Response {
    state.auth.handle_logout_api(&headers)
}

/// GET /api/tasks -> 按名称排序的任务列表。
async fn handle_tasks_list(State(state): State<AppState>) -> Response {
    let mut tasks = state.store.list_tasks();
    tasks.sort_by(|a, b| a.name.cmp(&b.name));
    (StatusCode::OK, Json(tasks)).into_response()
}

/// POST /api/tasks -> 创建任务。
async fn handle_tasks_create(State(state): State<AppState>, req: Request) -> Response {
    let body = match extract_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let mut task: Task = match serde_json::from_slice(&body) {
        Ok(t) => t,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let pkg = task.update_type == UpdateType::Package;
    if task.repo_url.is_empty()
        || task.file_keyword.is_empty()
        || (!pkg && task.target_path.is_empty())
    {
        return json_err(
            StatusCode::BAD_REQUEST,
            "repo_url and file_keyword are required; target_path is required for core/file types",
        );
    }
    if task.id.is_empty() {
        task.id = new_id();
    }
    task.status = "idle".to_string();
    if let Err(e) = state.store.upsert_task(task.clone()) {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }
    state.scheduler.register(&task);
    (StatusCode::CREATED, Json(task)).into_response()
}

async fn handle_task_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    match state.store.get_task(&id) {
        Some(t) => (StatusCode::OK, Json(t)).into_response(),
        None => json_err(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn handle_task_put(
    State(state): State<AppState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let body = match extract_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let mut task: Task = match serde_json::from_slice(&body) {
        Ok(t) => t,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    task.id = id;
    if let Err(e) = state.store.upsert_task(task.clone()) {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }
    state.scheduler.register(&task);
    (StatusCode::OK, Json(task)).into_response()
}

async fn handle_task_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    state.scheduler.unregister(&id);
    let _ = std::fs::remove_file(state.store.log_path(&id));
    if let Err(e) = state.store.delete_task(&id) {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }
    auth::json_response(
        StatusCode::OK,
        &serde_json::json!({"ok": "deleted"}),
        &HeaderMap::new(),
    )
}

/// POST /api/check/:id -> 非阻塞检查更新。
async fn handle_check(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let Some(task) = state.store.get_task(&id) else {
        return json_err(StatusCode::NOT_FOUND, "not found");
    };
    let store = state.store.clone();
    tokio::spawn(async move {
        let _ = store.update_task_field(&id, |t| t.status = "checking".to_string());
        let log_path = store.log_path(&id);
        let mut logger = TaskLogger::open(&log_path);
        logger.raw(&format!(
            "\n========== check {} ==========\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S")
        ));
        match check_update(&task, &mut logger).await {
            Err(e) => {
                let e2 = e.clone();
                let _ = store.update_task_field(&id, |t| {
                    t.status = "error".to_string();
                    t.last_error = e2;
                    t.last_check = Some(Utc::now());
                });
            }
            Ok(result) => {
                let latest = result.latest_version.clone();
                let has_update = result.has_update;
                let _ = store.update_task_field(&id, |t| {
                    t.last_check = Some(Utc::now());
                    t.latest_version = latest.clone();
                    t.status = if has_update {
                        "update_available".to_string()
                    } else {
                        "ok".to_string()
                    };
                    t.last_error.clear();
                });
            }
        }
    });
    auth::json_response(
        StatusCode::ACCEPTED,
        &serde_json::json!({"status": "checking"}),
        &HeaderMap::new(),
    )
}

/// POST /api/update/:id -> 非阻塞执行更新。
async fn handle_update(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let Some(task) = state.store.get_task(&id) else {
        return json_err(StatusCode::NOT_FOUND, "not found");
    };
    let store = state.store.clone();
    tokio::spawn(async move {
        run_update(task, &store).await;
    });
    auth::json_response(
        StatusCode::ACCEPTED,
        &serde_json::json!({"status": "updating"}),
        &HeaderMap::new(),
    )
}

/// GET /api/logs/:id -> 返回任务日志全文。
async fn handle_logs(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let log = std::fs::read_to_string(state.store.log_path(&id)).unwrap_or_default();
    (StatusCode::OK, Json(serde_json::json!({"log": log}))).into_response()
}

async fn handle_settings_get(State(state): State<AppState>) -> Response {
    (StatusCode::OK, Json(state.store.get_settings())).into_response()
}

#[derive(serde::Deserialize)]
struct SettingsUpdate {
    github_proxy_enabled: Option<bool>,
}

async fn handle_settings_put(State(state): State<AppState>, req: Request) -> Response {
    let body = match extract_body(req).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let update: SettingsUpdate = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    if let Some(enabled) = update.github_proxy_enabled {
        if let Err(e) = state
            .store
            .update_settings(|s| s.github_proxy_enabled = enabled)
        {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
    }
    (StatusCode::OK, Json(state.store.get_settings())).into_response()
}

/// 读取请求体；失败时返回 400 响应。
async fn extract_body(req: Request) -> Result<Bytes, Response> {
    let (parts, body) = req.into_parts();
    let _ = parts;
    match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => Ok(b),
        Err(e) => Err(json_err(StatusCode::BAD_REQUEST, &e.to_string())),
    }
}

fn new_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..6).map(|_| rng.gen::<u8>()).collect();
    hex::encode(bytes)
}

/// 保留对 parse_owner_repo 的引用（server 层暂不直接使用，供后续扩展）。
#[allow(dead_code)]
fn _assert_owner_repo() {
    let _ = parse_owner_repo("https://github.com/owner/repo");
}
