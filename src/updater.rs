//! 更新检查与执行主流程（对应 Go 版 updater.go）。

use crate::downloader::{copy_file, download_file, extract_and_find_binary};
use crate::github::{fetch_latest_release, parse_owner_repo, semver_compare, GhAsset};
use crate::store::{Store, Task, UpdateType};
use chrono::Local;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

/// 任务日志写入器，每次输出带 HH:MM:SS 前缀并追加到任务独立日志文件。
pub struct TaskLogger {
    file: Option<File>,
}

impl TaskLogger {
    pub fn open(path: &Path) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok();
        Self { file }
    }

    pub fn raw(&mut self, text: &str) {
        if let Some(f) = self.file.as_mut() {
            let _ = f.write_all(text.as_bytes());
            let _ = f.flush();
        }
    }

    pub fn log(&mut self, msg: &str) {
        let line = format!("[{}] {}\n", Local::now().format("%H:%M:%S"), msg);
        self.raw(&line);
    }
}

/// 一次检查/更新的结果。
pub struct UpdateResult {
    pub has_update: bool,
    pub current_version: String,
    pub latest_version: String,
    pub asset: Option<GhAsset>,
}

/// 查询 GitHub 并判断是否有新版本。
pub async fn check_update(task: &Task, logger: &mut TaskLogger) -> Result<UpdateResult, String> {
    let (owner, repo) = parse_owner_repo(&task.repo_url)?;
    logger.log(&format!("🔎 checking {}/{} ...", owner, repo));

    let rel = fetch_latest_release(&owner, &repo).await?;
    logger.log(&format!(
        "📋 latest release tag: {}  (current: {})",
        rel.tag_name, task.current_version
    ));

    let mut result = UpdateResult {
        has_update: false,
        current_version: task.current_version.clone(),
        latest_version: rel.tag_name.clone(),
        asset: None,
    };

    if task.current_version.is_empty() {
        result.has_update = true;
    } else {
        result.has_update = semver_compare(&task.current_version, &rel.tag_name);
    }

    if result.has_update {
        let asset = crate::github::best_asset(&rel.assets, &task.file_keyword)
            .ok_or_else(|| format!("no assets found in release {}", rel.tag_name))?;
        logger.log(&format!(
            "📎 matched asset: {} ({:.1} MB)",
            asset.name,
            asset.size as f64 / 1024.0 / 1024.0
        ));
        result.asset = Some(asset);
    }
    Ok(result)
}

fn set_status(store: &Store, id: &str, status: &str, err_msg: &str) {
    let status = status.to_string();
    let err_msg = err_msg.to_string();
    let _ = store.update_task_field(id, |t| {
        t.status = status;
        t.last_error = err_msg;
        t.last_check = Some(chrono::Utc::now());
    });
}

/// 执行一次完整更新（由定时任务、手动触发在非阻塞任务中调用）。
pub async fn run_update(task: Task, store: &Arc<Store>) {
    let log_path = store.log_path(&task.id);
    let mut logger = TaskLogger::open(&log_path);
    logger.raw(&format!(
        "\n========== update started {} ==========\n",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    ));

    set_status(store, &task.id, "checking", "");
    let result = match check_update(&task, &mut logger).await {
        Ok(r) => r,
        Err(e) => {
            logger.log(&format!("❌ check failed: {}", e));
            set_status(store, &task.id, "error", &e);
            return;
        }
    };

    // 记录已知的最新版本。
    let latest = result.latest_version.clone();
    let _ = store.update_task_field(&task.id, |t| t.latest_version = latest.clone());

    if !result.has_update {
        logger.log(&format!("✅ already up-to-date ({})", result.current_version));
        set_status(store, &task.id, "ok", "");
        return;
    }

    logger.log(&format!(
        "🆕 update available: {} → {}",
        result.current_version, result.latest_version
    ));
    set_status(store, &task.id, "updating", "");

    let asset = result.asset.clone().unwrap();
    let proxy_enabled = store.get_settings().github_proxy_enabled;
    let tmp_file = match download_file(
        &asset.browser_download_url,
        proxy_enabled,
        &mut |m: &str| logger.log(m),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            logger.log(&format!("❌ download failed: {}", e));
            set_status(store, &task.id, "error", &e);
            return;
        }
    };
    let tmp_path = PathBuf::from(&tmp_file);
    let _cleanup_tmp = TempCleanup::new(tmp_path.clone(), false);

    // ---- package 类型：调用系统包管理器安装 ----
    if task.update_type == UpdateType::Package {
        if !task.pre_cmd.is_empty() {
            logger.log(&format!("⚙ running pre-update: {}", task.pre_cmd));
            match run_shell(&task.pre_cmd) {
                Ok(out) => {
                    if !out.is_empty() {
                        logger.log(&format!("pre-update output: {}", out));
                    }
                }
                Err(e) => {
                    logger.log(&format!("❌ pre-update failed: {}", e));
                    set_status(store, &task.id, "error", &format!("pre-cmd: {}", e));
                    return;
                }
            }
        }

        let (pkg_mgr, install_cmd) = match detect_package_manager(&tmp_path, &mut logger) {
            Ok(v) => v,
            Err(e) => {
                logger.log(&format!("❌ package manager detection failed: {}", e));
                set_status(store, &task.id, "error", &e);
                return;
            }
        };
        logger.log(&format!("📦 detected package manager: {}", pkg_mgr));
        logger.log(&format!("⚙ installing: {}", install_cmd));
        match run_shell(&install_cmd) {
            Ok(out) => {
                if !out.is_empty() {
                    logger.log(&format!("install output: {}", out));
                }
            }
            Err(e) => {
                logger.log(&format!("❌ install failed: {}", e));
                set_status(store, &task.id, "error", &format!("install: {}", e));
                return;
            }
        }
        logger.log("✅ package installed successfully");

        if !task.post_cmd.is_empty() {
            logger.log(&format!("⚙ running post-update: {}", task.post_cmd));
            match run_shell(&task.post_cmd) {
                Ok(out) => {
                    if !out.is_empty() {
                        logger.log(&format!("post-update output: {}", out));
                    }
                }
                Err(e) => logger.log(&format!("⚠ post-update failed: {}", e)),
            }
        }

        mark_success(store, &task.id, &result.latest_version);
        logger.log(&format!("🎉 updated to {}", result.latest_version));
        return;
    }

    let deploy_file: PathBuf;

    if task.update_type == UpdateType::Core {
        let (_, repo) = parse_owner_repo(&task.repo_url).unwrap_or_default();
        let binary_path = match extract_and_find_binary(
            &tmp_file,
            &repo,
            &task.binary_keyword,
            &mut |m: &str| logger.log(m),
        ) {
            Ok(p) => PathBuf::from(p),
            Err(e) => {
                logger.log(&format!("❌ extract failed: {}", e));
                set_status(store, &task.id, "error", &e);
                return;
            }
        };
        let _cleanup_dir = TempCleanup::new(
            binary_path
                .parent()
                .unwrap_or(Path::new("/tmp"))
                .to_path_buf(),
            true,
        );

        let final_name = if task.rename.is_empty() {
            binary_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default()
        } else {
            task.rename.clone()
        };
        let renamed = binary_path.parent().unwrap().join(&final_name);
        if binary_path != renamed {
            if let Err(e) = fs::rename(&binary_path, &renamed) {
                let msg = e.to_string();
                logger.log(&format!("❌ rename failed: {}", msg));
                set_status(store, &task.id, "error", &msg);
                return;
            }
        }
        set_exec(&renamed);
        deploy_file = renamed;
        logger.log(&format!("✓ binary ready: {}", final_name));
    } else {
        // file 类型：原样替换。
        let final_name = if task.rename.is_empty() {
            asset.name.clone()
        } else {
            task.rename.clone()
        };
        let renamed = tmp_path.parent().unwrap().join(&final_name);
        if fs::rename(&tmp_path, &renamed).is_err() {
            if let Err(e) = copy_file(&tmp_path, &renamed) {
                logger.log(&format!("❌ rename/copy failed: {}", e));
                set_status(store, &task.id, "error", &e);
                return;
            }
        }
        deploy_file = renamed;
        logger.log(&format!("✓ file ready: {}", final_name));
    }

    if !task.pre_cmd.is_empty() {
        logger.log(&format!("⚙ running pre-update: {}", task.pre_cmd));
        match run_shell(&task.pre_cmd) {
            Ok(out) => {
                if !out.is_empty() {
                    logger.log(&format!("pre-update output: {}", out));
                }
            }
            Err(e) => {
                logger.log(&format!("❌ pre-update failed: {}", e));
                set_status(store, &task.id, "error", &format!("pre-cmd: {}", e));
                return;
            }
        }
    }

    let target_dir = Path::new(&task.target_path);
    if let Err(e) = fs::create_dir_all(target_dir) {
        let msg = e.to_string();
        logger.log(&format!("❌ create target dir failed: {}", msg));
        set_status(store, &task.id, "error", &msg);
        return;
    }

    let dest = target_dir.join(deploy_file.file_name().unwrap_or_default());
    logger.log(&format!("📂 deploying to: {}", dest.display()));
    if fs::rename(&deploy_file, &dest).is_err() {
        if let Err(e) = copy_file(&deploy_file, &dest) {
            logger.log(&format!("❌ deploy failed: {}", e));
            set_status(store, &task.id, "error", &e);
            return;
        }
        let _ = fs::remove_file(&deploy_file);
    }

    if task.update_type == UpdateType::Core {
        set_exec(&dest);
    }

    if !task.post_cmd.is_empty() {
        logger.log(&format!("⚙ running post-update: {}", task.post_cmd));
        match run_shell(&task.post_cmd) {
            Ok(out) => {
                if !out.is_empty() {
                    logger.log(&format!("post-update output: {}", out));
                }
            }
            Err(e) => logger.log(&format!("⚠ post-update failed: {}", e)),
        }
    }

    mark_success(store, &task.id, &result.latest_version);
    logger.log(&format!("🎉 updated to {}", result.latest_version));
}

fn mark_success(store: &Store, id: &str, version: &str) {
    let version = version.to_string();
    let _ = store.update_task_field(id, |t| {
        t.current_version = version.clone();
        t.last_update = Some(chrono::Utc::now());
        t.last_check = Some(chrono::Utc::now());
        t.status = "ok".to_string();
        t.last_error.clear();
    });
}

/// RAII 清理：退出作用域时删除临时文件或目录（对齐 Go 的 defer os.Remove / RemoveAll）。
struct TempCleanup {
    path: PathBuf,
    dir: bool,
}
impl TempCleanup {
    fn new(path: PathBuf, dir: bool) -> Self {
        Self { path, dir }
    }
}
impl Drop for TempCleanup {
    fn drop(&mut self) {
        if self.dir {
            let _ = fs::remove_dir_all(&self.path);
        } else {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
fn set_exec(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o755)) {
        eprintln!("warn: chmod failed: {}", e);
    }
}
#[cfg(not(unix))]
fn set_exec(_path: &Path) {}

/// 根据下载文件后缀与系统可用命令，推断包管理器与安装命令。
fn detect_package_manager(pkg_file: &Path, logger: &mut TaskLogger) -> Result<(String, String), String> {
    let lower = pkg_file.to_string_lossy().to_lowercase();
    let p = pkg_file.to_string_lossy().to_string();

    if lower.ends_with(".deb") {
        for (mgr, cmd) in [
            ("apt", format!("apt install -y {}", p)),
            ("apt-get", format!("apt-get install -y {}", p)),
            ("dpkg", format!("dpkg -i {}", p)),
        ] {
            if command_exists(mgr) {
                return Ok((mgr.to_string(), cmd));
            }
        }
        Err("no suitable package manager found for .deb (tried apt, apt-get, dpkg)".to_string())
    } else if lower.ends_with(".rpm") {
        for (mgr, cmd) in [
            ("dnf", format!("dnf install -y {}", p)),
            ("yum", format!("yum install -y {}", p)),
            ("zypper", format!("zypper --non-interactive install {}", p)),
            ("rpm", format!("rpm -Uvh {}", p)),
        ] {
            if command_exists(mgr) {
                return Ok((mgr.to_string(), cmd));
            }
        }
        Err("no suitable package manager found for .rpm (tried dnf, yum, zypper, rpm)".to_string())
    } else if lower.ends_with(".pkg.tar.zst")
        || lower.ends_with(".pkg.tar.xz")
        || lower.ends_with(".pkg.tar.gz")
    {
        if command_exists("pacman") {
            return Ok((
                "pacman".to_string(),
                format!("pacman -U --noconfirm {}", p),
            ));
        }
        Err("pacman not found; cannot install .pkg.tar.* package".to_string())
    } else {
        logger.log("⚠ file extension not recognised, probing system package managers…");
        if command_exists("apt") {
            return Ok(("apt".to_string(), format!("apt install -y {}", p)));
        }
        if command_exists("dnf") {
            return Ok(("dnf".to_string(), format!("dnf install -y {}", p)));
        }
        if command_exists("pacman") {
            return Ok(("pacman".to_string(), format!("pacman -U --noconfirm {}", p)));
        }
        Err(format!(
            "cannot determine package format or package manager for file: {}",
            pkg_file.file_name().unwrap_or_default().to_string_lossy()
        ))
    }
}

fn command_exists(cmd: &str) -> bool {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(cmd);
            if candidate.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = fs::metadata(&candidate) {
                        if meta.permissions().mode() & 0o111 != 0 {
                            return true;
                        }
                    }
                    continue;
                }
                #[cfg(not(unix))]
                return true;
            }
        }
    }
    false
}

/// 通过 sh -c 执行 shell 命令，返回合并输出（trim 后）。
pub fn run_shell(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(format!("{} (exit {})", combined.trim(), output.status));
    }
    Ok(combined.trim().to_string())
}
