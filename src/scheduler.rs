//! Cron 定时任务调度（对应 Go 版 scheduler.go）。
//!
//! Go 版使用 robfig/cron v3 的 5 段表达式（分 时 日 月 周）；Rust 的 cron crate
//! 使用 6 段（秒 分 时 日 月 周），因此注册时在前面补一个秒字段 "0"。

use crate::store::{Store, Task};
use crate::updater::run_update;
use chrono::Utc;
use cron::Schedule;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

pub struct Scheduler {
    entries: Mutex<HashMap<String, JoinHandle<()>>>,
    store: Arc<Store>,
}

impl Scheduler {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            store,
        }
    }

    /// 启动调度器并注册已有任务。
    pub fn start(&self) {
        for task in self.store.list_tasks() {
            if !task.cron.is_empty() {
                self.register(&task);
            }
        }
        eprintln!("scheduler started");
    }

    /// 将 Go 的 5 段 cron 转为 Rust cron crate 的 6 段（前面补秒 0）。
    fn normalize_cron(expr: &str) -> String {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        if parts.len() == 5 {
            format!("0 {}", parts.join(" "))
        } else {
            expr.to_string()
        }
    }

    /// 为任务新增或替换一个 cron 作业。
    pub fn register(&self, task: &Task) {
        if task.cron.is_empty() {
            self.unregister(&task.id);
            return;
        }
        let normalized = Self::normalize_cron(&task.cron);
        let schedule = match Schedule::from_str(&normalized) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[scheduler] invalid cron {:?} for task {}: {}",
                    task.cron, task.id, e
                );
                return;
            }
        };

        // 移除旧作业。
        if let Some(handle) = self.entries.lock().unwrap().remove(&task.id) {
            handle.abort();
        }

        let task_id = task.id.clone();
        let store = self.store.clone();
        let handle: JoinHandle<()> = tokio::spawn(async move {
            loop {
                // 找出下一次触发时间并等待。
                let next = schedule.upcoming(Utc).next();
                let Some(next) = next else { break };
                let now = Utc::now();
                let delay = (next - now).to_std().unwrap_or(Duration::from_secs(1));
                sleep(delay).await;

                if let Some(t) = store.get_task(&task_id) {
                    eprintln!("[cron] running update for task {} ({})", t.id, t.name);
                    run_update(t, &store).await;
                }
            }
        });

        self.entries
            .lock()
            .unwrap()
            .insert(task.id.clone(), handle);
        eprintln!("[scheduler] registered task {} with cron {:?}", task.id, task.cron);
    }

    /// 移除指定任务的 cron 作业。
    pub fn unregister(&self, task_id: &str) {
        if let Some(handle) = self.entries.lock().unwrap().remove(task_id) {
            handle.abort();
        }
    }
}
