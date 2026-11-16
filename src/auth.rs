//! 登录鉴权、会话与暴力破解保护（对应 Go 版 auth.go）。

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Mutex;
use subtle::ConstantTimeEq;
use tokio::time::interval;

const SESSION_COOKIE: &str = "updater_session";
const SESSION_TTL: Duration = Duration::hours(24);
const MAX_FAILED_ATTEMPTS: usize = 5;
const LOCKOUT_WINDOW: Duration = Duration::minutes(10);
const LOCKOUT_DURATION: Duration = Duration::minutes(15);

struct IpGuard {
    failures: Vec<chrono::DateTime<Utc>>,
    locked_till: chrono::DateTime<Utc>,
}

/// 鉴权管理器。password 为空时功能完全关闭，所有请求放行。
pub struct Auth {
    password: String,
    sessions: Mutex<HashMap<String, chrono::DateTime<Utc>>>,
    guards: Mutex<HashMap<String, IpGuard>>,
}

impl Auth {
    pub fn new(password: String) -> Self {
        Self {
            password,
            sessions: Mutex::new(HashMap::new()),
            guards: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.password.is_empty()
    }

    fn random_token() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// 从请求中提取客户端 IP：优先 X-Forwarded-For 第一段，否则 RemoteAddr 主机部分。
    pub fn client_ip(headers: &HeaderMap, remote_addr: Option<&str>) -> String {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            let ip = xff.split(',').next().unwrap_or("").trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
        if let Some(addr) = remote_addr {
            if let Some((host, _)) = addr.rsplit_once(':') {
                return host.to_string();
            }
            return addr.to_string();
        }
        "unknown".to_string()
    }

    /// 返回 (是否锁定, 剩余时长字符串)。
    pub fn is_locked(&self, ip: &str) -> (bool, String) {
        let guards = self.guards.lock().unwrap();
        if let Some(g) = guards.get(ip) {
            let now = Utc::now();
            if now < g.locked_till {
                // 对齐 Go 的 time.Duration.Round(time.Second).String()，如 "14m59s"。
                let secs = (g.locked_till - now).num_seconds().max(0) as u64;
                return (true, go_duration_string(secs));
            }
        }
        (false, String::new())
    }

    pub fn record_failure(&self, ip: &str) {
        let mut guards = self.guards.lock().unwrap();
        let g = guards.entry(ip.to_string()).or_insert_with(|| IpGuard {
            failures: Vec::new(),
            locked_till: Utc::now() - Duration::seconds(1),
        });
        let now = Utc::now();
        g.failures.retain(|t| now.signed_duration_since(*t) <= LOCKOUT_WINDOW);
        g.failures.push(now);
        if g.failures.len() >= MAX_FAILED_ATTEMPTS {
            g.locked_till = now + LOCKOUT_DURATION;
            g.failures.clear();
        }
    }

    pub fn record_success(&self, ip: &str) {
        self.guards.lock().unwrap().remove(ip);
    }

    fn check_password(&self, candidate: &str) -> bool {
        bool::from(
            candidate
                .as_bytes()
                .ct_eq(self.password.as_bytes()),
        )
    }

    fn create_session(&self) -> String {
        let token = Self::random_token();
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), Utc::now() + SESSION_TTL);
        token
    }

    fn valid_session(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(exp) if Utc::now() <= *exp => true,
            Some(_) => {
                sessions.remove(token);
                false
            }
            None => false,
        }
    }

    fn destroy_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    pub fn is_authed(&self, headers: &HeaderMap) -> bool {
        match cookie_value(headers, SESSION_COOKIE) {
            Some(token) => self.valid_session(&token),
            None => false,
        }
    }

    /// 周期清理过期会话与失效的 IP 锁定记录。
    pub async fn gc(self: std::sync::Arc<Self>) {
        let mut ticker = interval(std::time::Duration::from_secs(600));
        loop {
            ticker.tick().await;
            let now = Utc::now();
            self.sessions
                .lock()
                .unwrap()
                .retain(|_, exp| now <= *exp);
            self.guards.lock().unwrap().retain(|_, g| {
                !(now > g.locked_till && g.failures.is_empty())
            });
        }
    }

    fn set_session_cookie(&self, headers: &mut HeaderMap, token: &str) {
        let expires = (Utc::now() + SESSION_TTL)
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let value = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Expires={}",
            SESSION_COOKIE, token, expires
        );
        if let Ok(v) = value.parse() {
            headers.insert(header::SET_COOKIE, v);
        }
    }

    fn clear_session_cookie(headers: &mut HeaderMap) {
        let value = format!("{}=; Path=/; HttpOnly; Max-Age=-1", SESSION_COOKIE);
        if let Ok(v) = value.parse() {
            headers.insert(header::SET_COOKIE, v);
        }
    }

    /// GET /login：登录页。
    pub fn handle_login_page(&self, headers: &HeaderMap) -> Response {
        if self.is_authed(headers) {
            // 对齐 Go 的 http.Redirect(..., http.StatusFound) 即 302。
            return (
                StatusCode::FOUND,
                [(header::LOCATION, "/")],
            )
                .into_response();
        }
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            LOGIN_HTML,
        )
            .into_response()
    }

    /// POST /api/login：校验密码 + 防爆破 + 签发会话。
    pub fn handle_login_api(
        &self,
        headers: &HeaderMap,
        remote_addr: Option<&str>,
        body: &[u8],
    ) -> Response {
        let ip = Self::client_ip(headers, remote_addr);
        if let (true, remaining) = self.is_locked(&ip) {
            return json_response(
                StatusCode::TOO_MANY_REQUESTS,
                &serde_json::json!({
                    "error": format!("too many failed attempts, please try again in {}", remaining)
                }),
                &HeaderMap::new(),
            );
        }

        let password: String = serde_json::from_slice::<LoginRequest>(body)
            .map(|r| r.password)
            .unwrap_or_default();

        if !self.check_password(&password) {
            self.record_failure(&ip);
            return json_response(
                StatusCode::UNAUTHORIZED,
                &serde_json::json!({"error": "密码错误"}),
                &HeaderMap::new(),
            );
        }

        self.record_success(&ip);
        let token = self.create_session();
        let mut resp_headers = HeaderMap::new();
        self.set_session_cookie(&mut resp_headers, &token);
        json_response(
            StatusCode::OK,
            &serde_json::json!({"ok": "logged in"}),
            &resp_headers,
        )
    }

    /// POST /api/logout：销毁会话。
    pub fn handle_logout_api(&self, headers: &HeaderMap) -> Response {
        if let Some(token) = cookie_value(headers, SESSION_COOKIE) {
            self.destroy_session(&token);
        }
        let mut resp_headers = HeaderMap::new();
        Self::clear_session_cookie(&mut resp_headers);
        json_response(
            StatusCode::OK,
            &serde_json::json!({"ok": "logged out"}),
            &resp_headers,
        )
    }
}

#[derive(serde::Deserialize)]
struct LoginRequest {
    #[serde(default)]
    password: String,
}

/// 将秒数格式化为 Go time.Duration.String() 风格（如 899 -> "14m59s", 3600 -> "1h0m0s"）。
fn go_duration_string(total_secs: u64) -> String {
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if h > 0 {
        format!("{}h{}m{}s", h, m, s)
    } else if m > 0 {
        format!("{}m{}s", m, s)
    } else {
        format!("{}s", s)
    }
}

/// 从 HeaderMap 中读取指定 cookie。
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(header::COOKIE).iter() {
        if let Ok(s) = value.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=') {
                    if k == name {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

/// 免鉴权的公开路径。
pub fn is_public_auth_path(path: &str) -> bool {
    matches!(path, "/login" | "/api/login" | "/api/logout")
}

/// 构造 JSON 响应（可选附加自定义头）。
pub fn json_response(code: StatusCode, value: &serde_json::Value, extra: &HeaderMap) -> Response {
    let mut resp = (code, axum::Json(value.clone())).into_response();
    for (k, v) in extra {
        resp.headers_mut().insert(k.clone(), v.clone());
    }
    resp
}

/// 登录页 HTML —— 由原 auth.go 中的 loginHTML 原样迁移（.rs 承载）。
pub const LOGIN_HTML: &str = r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
<title>登录 - Linux 更新管理器</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#f4f6fa;color:#1e293b;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
    min-height:100vh;display:flex;align-items:center;justify-content:center}
  .box{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:32px 28px;width:100%;max-width:340px;
    box-shadow:0 1px 8px rgba(0,0,0,.07),0 4px 14px rgba(0,0,0,.05)}
  h1{font-size:1.05rem;font-weight:700;margin-bottom:18px;text-align:center}
  input{width:100%;background:#f8f9fc;border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;
    font-size:.9rem;outline:none;margin-bottom:12px}
  input:focus{border-color:#6c63ff;background:#fff}
  button{width:100%;padding:10px;border:none;border-radius:8px;background:#6c63ff;color:#fff;
    font-size:.9rem;font-weight:600;cursor:pointer}
  button:hover{background:#5a52e0}
  button:disabled{opacity:.6;cursor:not-allowed}
  .err{color:#ef4444;font-size:.8rem;margin-bottom:10px;min-height:1em;text-align:center}
</style>
</head>
<body>
  <form class="box" id="loginForm">
    <h1>&#x1F512; 需要登录</h1>
    <div class="err" id="err"></div>
    <input type="password" id="password" placeholder="请输入密码" autofocus autocomplete="current-password">
    <button type="submit" id="submitBtn">登录</button>
  </form>
  <script>
    var form=document.getElementById('loginForm');
    var errBox=document.getElementById('err');
    var btn=document.getElementById('submitBtn');
    form.addEventListener('submit',function(e){
      e.preventDefault();
      var pwd=document.getElementById('password').value;
      btn.disabled=true;
      errBox.textContent='';
      fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd})})
        .then(function(r){return r.json().then(function(d){return {ok:r.ok,data:d};});})
        .then(function(res){
          if(res.ok){
            window.location.href='/';
          } else {
            errBox.textContent=res.data.error||'登录失败';
            btn.disabled=false;
          }
        })
        .catch(function(){
          errBox.textContent='网络错误，请重试';
          btn.disabled=false;
        });
    });
  </script>
</body>
</html>"##;
