//! 任务与全局设置的内存存储 + JSON 原子持久化（对应 Go 版 store.go）。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// 更新类型：core=可执行文件 / file=原样替换 / package=系统安装包。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateType {
    Core,
    File,
    Package,
}

impl Default for UpdateType {
    fn default() -> Self {
        UpdateType::Core
    }
}

/// 一个自动更新任务。字段命名与 Go 版 JSON tag 完全一致（snake_case）。
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub update_type: UpdateType,
    pub repo_url: String,
    pub current_version: String,
    pub latest_version: String,
    pub file_keyword: String,
    /// core 类型专用：压缩包内多个 ELF 时用于挑选。
    pub binary_keyword: String,
    pub rename: String,
    pub target_path: String,
    pub pre_cmd: String,
    pub post_cmd: String,
    /// 标准 5 段 cron，空 = 仅手动触发。
    pub cron: String,
    /// None 序列化为 null，前端 timeFmt 视为「无」（等价 Go 零值时间）。
    pub last_check: Option<DateTime<Utc>>,
    pub last_update: Option<DateTime<Utc>>,
    /// idle / checking / updating / ok / error / update_available
    pub status: String,
    pub last_error: String,
}

/// 全局设置。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub github_proxy_enabled: bool,
}

/// 磁盘上的统一结构：tasks + settings。
#[derive(Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    tasks: HashMap<String, Task>,
    #[serde(default)]
    settings: Settings,
}

#[derive(Default)]
struct StoreData {
    tasks: HashMap<String, Task>,
    settings: Settings,
}

/// 受 RwLock 保护的内存存储；所有写操作后立即原子落盘（tmp + rename）。
pub struct Store {
    data_dir: PathBuf,
    data: RwLock<StoreData>,
}

impl Store {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            data: RwLock::new(StoreData::default()),
        }
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("tasks.json")
    }

    /// 加载时兼容两种格式：
    ///  - 新格式 {"tasks": {...}, "settings": {...}}
    ///  - 旧格式：文件本身就是 {taskId: Task} 的 map
    pub fn load(&self) -> Result<(), String> {
        let path = self.db_path();
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("read {}: {}", path.display(), e)),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&data).map_err(|e| format!("parse {}: {}", path.display(), e))?;

        let is_new_format = value
            .as_object()
            .and_then(|o| o.get("tasks"))
            .map(|v| v.is_object())
            .unwrap_or(false);

        let mut guard = self.data.write().map_err(|e| e.to_string())?;
        if is_new_format {
            let sf: StoreFile =
                serde_json::from_value(value).map_err(|e| format!("parse store: {}", e))?;
            guard.tasks = sf.tasks;
            guard.settings = sf.settings;
        } else {
            let legacy: HashMap<String, Task> =
                serde_json::from_value(value).map_err(|e| format!("parse legacy store: {}", e))?;
            guard.tasks = legacy;
        }
        Ok(())
    }

    /// 在持写锁时调用；原子写 tmp 再 rename。
    fn save_inner(&self, d: &StoreData) -> Result<(), String> {
        let sf = StoreFile {
            tasks: d.tasks.clone(),
            settings: d.settings.clone(),
        };
        let body = serde_json::to_string_pretty(&sf).map_err(|e| e.to_string())?;
        let tmp = self.data_dir.join("tasks.json.tmp");
        fs::write(&tmp, body).map_err(|e| format!("write tmp: {}", e))?;
        fs::rename(&tmp, self.db_path()).map_err(|e| format!("rename: {}", e))
    }

    pub fn get_settings(&self) -> Settings {
        self.data.read().unwrap().settings.clone()
    }

    pub fn update_settings<F: FnOnce(&mut Settings)>(&self, f: F) -> Result<(), String> {
        let mut guard = self.data.write().map_err(|e| e.to_string())?;
        f(&mut guard.settings);
        self.save_inner(&guard)
    }

    pub fn get_task(&self, id: &str) -> Option<Task> {
        self.data.read().unwrap().tasks.get(id).cloned()
    }

    pub fn list_tasks(&self) -> Vec<Task> {
        self.data.read().unwrap().tasks.values().cloned().collect()
    }

    pub fn upsert_task(&self, task: Task) -> Result<(), String> {
        let mut guard = self.data.write().map_err(|e| e.to_string())?;
        guard.tasks.insert(task.id.clone(), task);
        self.save_inner(&guard)
    }

    pub fn delete_task(&self, id: &str) -> Result<(), String> {
        let mut guard = self.data.write().map_err(|e| e.to_string())?;
        guard.tasks.remove(id);
        self.save_inner(&guard)
    }

    pub fn update_task_field<F: FnOnce(&mut Task)>(&self, id: &str, f: F) -> Result<(), String> {
        let mut guard = self.data.write().map_err(|e| e.to_string())?;
        if let Some(t) = guard.tasks.get_mut(id) {
            f(t);
            self.save_inner(&guard)
        } else {
            Ok(())
        }
    }

    /// 任务运行日志放在系统临时目录（与 Go 版 /tmp/updater-log-<id>.log 一致）。
    pub fn log_path(&self, task_id: &str) -> PathBuf {
        Path::new("/tmp").join(format!("updater-log-{}.log", task_id))
    }
}
