//! GitHub Release API、URL 解析、语义化版本比较、最佳 Asset 匹配（对应 Go 版 github.go）。

use regex::Regex;
use serde::Deserialize;
use std::sync::OnceLock;
use std::time::Duration;

/// GitHub Release API 我们需要的子集。
#[derive(Debug, Clone, Deserialize)]
pub struct GhRelease {
    pub tag_name: String,
    #[serde(default)]
    pub assets: Vec<GhAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GhAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub size: i64,
}

fn gh_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("build github http client")
    })
}

/// 查询 owner/repo 的最新 release。
pub async fn fetch_latest_release(owner: &str, repo: &str) -> Result<GhRelease, String> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        owner, repo
    );
    let resp = gh_client()
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "linux-updater/1.0")
        .send()
        .await
        .map_err(|e| format!("github request failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("github API returned {}", resp.status().as_u16()));
    }
    resp.json::<GhRelease>()
        .await
        .map_err(|e| format!("decode release: {}", e))
}

/// 从 GitHub URL 中提取 owner / repo，接受 https://github.com/owner/repo 与 github.com/owner/repo。
pub fn parse_owner_repo(repo_url: &str) -> Result<(String, String), String> {
    let mut s = repo_url.trim_end_matches('/').trim_end_matches(".git").to_string();
    // Go 版末尾处理顺序为：TrimSuffix("/") 再 TrimSuffix(".git")；这里用等价的循环确保 "...git/" 与 ".../.git" 都覆盖。
    loop {
        let t = s.trim_end_matches('/').trim_end_matches(".git").to_string();
        if t == s {
            break;
        }
        s = t;
    }
    let re = Regex::new(r"github\.com[/:]([^/]+)/([^/]+)").unwrap();
    let caps = re
        .captures(&s)
        .ok_or_else(|| format!("cannot parse github URL: {}", repo_url))?;
    Ok((caps[1].to_string(), caps[2].to_string()))
}

#[derive(Debug)]
struct SemVer {
    major: i64,
    minor: i64,
    patch: i64,
    pre: String,
}

fn parse_semver(s: &str) -> Option<SemVer> {
    let re = Regex::new(r"v?(\d+)\.(\d+)(?:\.(\d+))?(?:[.\-](.+))?").unwrap();
    let caps = re.captures(s.trim())?;
    let major = caps[1].parse().unwrap_or(0);
    let minor = caps[2].parse().unwrap_or(0);
    let patch = caps
        .get(3)
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(0);
    let pre = caps.get(4).map(|m| m.as_str().to_string()).unwrap_or_default();
    Some(SemVer {
        major,
        minor,
        patch,
        pre,
    })
}

/// 返回 b 是否比 a 新。解析失败时退化为「字符串不等即视为有更新」。
pub fn semver_compare(a: &str, b: &str) -> bool {
    let (sa, sb) = match (parse_semver(a), parse_semver(b)) {
        (Some(x), Some(y)) => (x, y),
        _ => return a != b,
    };
    if sa.major != sb.major {
        return sb.major > sa.major;
    }
    if sa.minor != sb.minor {
        return sb.minor > sa.minor;
    }
    if sa.patch != sb.patch {
        return sb.patch > sa.patch;
    }
    // 预发布：空（稳定版）> 非空（预发布）。
    if sa.pre != sb.pre {
        if sa.pre.is_empty() {
            return false;
        }
        if sb.pre.is_empty() {
            return true;
        }
        return sb.pre > sa.pre;
    }
    false
}

/// 依据关键词为 release assets 打分，挑出最佳文件。
///
/// 规则（按顺序）：
///  1. 优先包含全部关键词的 asset（full-match 组），否则退化为部分匹配。
///  2. 同组内优先文件名最短者。
///  3. 长度相同则优先命中关键词字符数最多者。
pub fn best_asset(assets: &[GhAsset], keyword: &str) -> Option<GhAsset> {
    if assets.is_empty() {
        return None;
    }
    let lower = keyword.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.is_empty() {
        return Some(assets[0].clone());
    }

    struct Candidate {
        asset: GhAsset,
        matched_len: usize,
        all_match: bool,
    }

    let mut candidates: Vec<Candidate> = Vec::new();
    for asset in assets {
        let name = asset.name.to_lowercase();
        let mut matched = 0usize;
        let mut all = true;
        for tok in &tokens {
            if name.contains(tok) {
                matched += tok.len();
            } else {
                all = false;
            }
        }
        if matched > 0 {
            candidates.push(Candidate {
                asset: asset.clone(),
                matched_len: matched,
                all_match: all,
            });
        }
    }
    if candidates.is_empty() {
        return None;
    }

    let has_full_match = candidates.iter().any(|c| c.all_match);
    let mut best: Option<Candidate> = None;
    for c in candidates {
        if has_full_match && !c.all_match {
            continue;
        }
        let take = match &best {
            None => true,
            Some(b) => {
                let nl = c.asset.name.len();
                let bl = b.asset.name.len();
                nl < bl || (nl == bl && c.matched_len > b.matched_len)
            }
        };
        if take {
            best = Some(c);
        }
    }
    best.map(|c| c.asset)
}
