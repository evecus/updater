//! 下载、GitHub 加速代理探测、递归解压与 ELF 二进制查找（对应 Go 版 downloader.go / xz.go）。

use rand::Rng;
use reqwest::Url;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

/// GitHub 加速代理前缀列表（下载前并发探测，按延迟从低到高尝试）。
const GH_PROXY_PREFIXES: &[&str] = &[
    "https://ghfast.top/",
    "https://gh-proxy.com/",
    "https://gh.ddlc.top/",
    "https://ghproxy.it/",
    "https://ghproxy.net/",
    "https://gh.con.sh/",
    "https://gh-proxy.net/",
    "https://cdn.gh-proxy.com/",
];

/// 被视为 GitHub 相关、可走加速代理的域名。
const GH_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "releases.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "gist.githubusercontent.com",
    "gist.github.com",
];

/// 判断是否为常见 GitHub 链接。
fn is_github_url(raw_url: &str) -> bool {
    let Ok(u) = Url::parse(raw_url) else {
        return false;
    };
    let host = u.host_str().unwrap_or("").to_lowercase();
    GH_HOSTS
        .iter()
        .any(|gh| host == *gh || host.ends_with(&format!(".{}", gh)))
}

/// 并发探测所有代理前缀的可用性与延迟，返回按延迟升序排列的可用前缀。
async fn rank_github_proxies(sample_url: &str) -> Vec<String> {
    let probe_client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut set = JoinSet::new();
    for prefix in GH_PROXY_PREFIXES {
        let client = probe_client.clone();
        let target = format!("{}{}", prefix, sample_url);
        let prefix = (*prefix).to_string();
        set.spawn(async move {
            let start = Instant::now();
            // 优先 HEAD；部分代理不支持则退化为带 Range 的小 GET。
            let ok = match client.head(&target).send().await {
                Ok(resp) => resp.status().as_u16() < 400,
                Err(_) => match client
                    .get(&target)
                    .header("Range", "bytes=0-0")
                    .send()
                    .await
                {
                    Ok(resp) => resp.status().as_u16() < 400,
                    Err(_) => false,
                },
            };
            (prefix, start.elapsed(), ok)
        });
    }

    let mut results: Vec<(String, Duration)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((prefix, latency, ok)) = joined {
            if ok {
                results.push((prefix, latency));
            }
        }
    }
    results.sort_by_key(|(_, d)| *d);
    results.into_iter().map(|(p, _)| p).collect()
}

fn dl_client() -> &'static reqwest::Client {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("build download http client")
    })
}

fn random_hex(bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    let buf: Vec<u8> = (0..bytes).map(|_| rng.gen::<u8>()).collect();
    hex::encode(buf)
}

/// 保留原始扩展名的复合后缀（用于后续按后缀判断格式）。
const COMPOUND_EXTS: &[&str] = &[
    ".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tar.lz4", ".tar.lz", ".pkg.tar.zst",
    ".pkg.tar.xz",
];

/// 下载 raw_url 到本地临时文件并返回路径。
///
/// proxy_enabled=false：始终直连。
/// proxy_enabled=true 且为 GitHub 链接：探测并按延迟尝试代理，不尝试直连（对齐 CloudOne 面板行为）。
pub async fn download_file(
    raw_url: &str,
    proxy_enabled: bool,
    logger: &mut (dyn FnMut(&str) + Send),
) -> Result<String, String> {
    let orig_name = raw_url
        .split('?')
        .next()
        .unwrap_or(raw_url)
        .rsplit('/')
        .next()
        .unwrap_or("download");
    let lower = orig_name.to_lowercase();
    let mut ext = String::new();
    for compound in COMPOUND_EXTS {
        if lower.ends_with(compound) {
            ext = (*compound).to_string();
            break;
        }
    }
    if ext.is_empty() {
        ext = Path::new(orig_name)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
    }

    let tmp = std::env::temp_dir().join(format!("updater-dl-{}{}", random_hex(8), ext));
    // 先创建空文件（对齐 Go os.CreateTemp 的语义：占位并保留扩展名）。
    File::create(&tmp).map_err(|e| format!("create temp: {}", e))?.sync_all().ok();

    let gh = proxy_enabled && is_github_url(raw_url);
    let urls_to_try: Vec<String> = if gh {
        logger("🔎 probing GitHub proxy mirrors...");
        let ranked = rank_github_proxies(raw_url).await;
        if ranked.is_empty() {
            let _ = fs::remove_file(&tmp);
            return Err(
                "no available github proxy, please try again later or disable acceleration"
                    .to_string(),
            );
        }
        ranked.iter().map(|p| format!("{}{}", p, raw_url)).collect()
    } else {
        vec![raw_url.to_string()]
    };

    let mut last_err = String::from("unknown error");
    for (i, u) in urls_to_try.iter().enumerate() {
        if gh {
            logger(&format!(
                "⬇ downloading via proxy ({}/{}): {}",
                i + 1,
                urls_to_try.len(),
                u
            ));
        } else {
            logger(&format!("⬇ downloading (direct): {}", u));
        }
        match download_to(u, &tmp).await {
            Ok(()) => {
                logger("✓ download complete");
                return Ok(tmp.to_string_lossy().to_string());
            }
            Err(e) => {
                logger(&format!("✗ failed: {}", e));
                last_err = e;
            }
        }
    }
    let _ = fs::remove_file(&tmp);
    Err(format!(
        "all download attempts failed for {}: {}",
        raw_url, last_err
    ))
}

async fn download_to(url: &str, dest: &Path) -> Result<(), String> {
    let resp = dl_client()
        .get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {}", status));
    }
    let mut file = File::create(dest).map_err(|e| format!("open dest: {}", e))?;
    let mut resp = resp;
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        file.write_all(&chunk).map_err(|e| format!("write: {}", e))?;
    }
    Ok(())
}

fn magic_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 8];
    let n = f.read(&mut buf).unwrap_or(0);
    Ok(buf[..n].to_vec())
}

fn has_prefix(b: &[u8], hex_str: &str) -> bool {
    let needle = hex::decode(hex_str).unwrap_or_default();
    b.len() >= needle.len() && &b[..needle.len()] == needle.as_slice()
}

const ARCHIVE_EXTS: &[&str] = &[
    ".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tar.lz4", ".tar.lz", ".tgz", ".txz",
    ".tbz2", ".tar", ".zip", ".gz", ".xz", ".bz2",
];

fn is_archive_name(name: &str) -> bool {
    let low = name.to_lowercase();
    ARCHIVE_EXTS.iter().any(|ext| low.ends_with(ext))
}

fn has_no_extension(name: &Path) -> bool {
    !name
        .file_name()
        .map(|n| n.to_string_lossy().contains('.'))
        .unwrap_or(false)
}

/// 递归解压下载文件，返回其中的 ELF 二进制路径。
pub fn extract_and_find_binary(
    file_path: &str,
    repo_name: &str,
    binary_keyword: &str,
    logger: &mut (dyn FnMut(&str) + Send),
) -> Result<String, String> {
    let extract_dir = std::env::temp_dir().join(format!("updater-extract-{}", random_hex(8)));
    fs::create_dir_all(&extract_dir).map_err(|e| format!("mkdtemp: {}", e))?;

    fn extract_recursive(
        src: &Path,
        dir: &Path,
        depth: usize,
        logger: &mut (dyn FnMut(&str) + Send),
    ) -> Result<(), String> {
        if depth > 5 {
            return Err("too many nested archive layers".to_string());
        }
        let magic = magic_bytes(src)?;
        let src_name = src
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let base = src.file_name().unwrap_or_default().to_string_lossy();

        if has_prefix(&magic, "504b0304") {
            logger(&format!("📦 [layer {}] zip → extracting {}", depth, base));
            extract_zip(src, dir)?;
        } else if has_prefix(&magic, "1f8b") {
            logger(&format!("📦 [layer {}] gzip → extracting {}", depth, base));
            if extract_tar_gz(src, dir).is_err() {
                let out = dir.join(base.trim_end_matches(".gz"));
                extract_gzip(src, &out)?;
            }
        } else if has_prefix(&magic, "fd377a585a00") {
            logger(&format!("📦 [layer {}] xz → extracting {}", depth, base));
            if extract_tar_xz(src, dir).is_err() {
                let out = dir.join(base.trim_end_matches(".xz"));
                extract_xz(src, &out)?;
            }
        } else if has_prefix(&magic, "425a68") {
            logger(&format!("📦 [layer {}] bzip2 → extracting {}", depth, base));
            extract_tar_bz2(src, dir)?;
        } else if has_prefix(&magic, "7f454c46") {
            logger(&format!("🔧 [layer {}] ELF binary: {}", depth, base));
            return copy_file(src, &dir.join(&*base));
        } else if src_name.ends_with(".tar") {
            logger(&format!("📦 [layer {}] bare tar → {}", depth, base));
            extract_tar_auto(src, dir)?;
        } else {
            logger(&format!(
                "⚠ [layer {}] unknown format, copying as-is: {}",
                depth, base
            ));
            return copy_file(src, &dir.join(&*base));
        }

        // 解压后对出现的归档文件递归解压（先收集路径，避免遍历时修改目录）。
        let mut archives: Vec<PathBuf> = Vec::new();
        collect_archives(dir, &mut archives)?;
        for path in archives {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let sub_dir = dir.join(format!("__sub_{}", name));
            fs::create_dir_all(&sub_dir).map_err(|e| e.to_string())?;
            extract_recursive(&path, &sub_dir, depth + 1, logger)?;
            let _ = fs::remove_file(&path);
        }
        Ok(())
    }

    fn collect_archives(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_dir() {
                collect_archives(&p, out)?;
            } else if is_archive_name(&entry.file_name().to_string_lossy()) {
                out.push(p);
            }
        }
        Ok(())
    }

    extract_recursive(Path::new(file_path), &extract_dir, 1, logger)?;
    find_binary(&extract_dir, repo_name, binary_keyword, logger)
}

struct Candidate {
    path: PathBuf,
    size: u64,
    no_ext: bool,
    kw_match: bool,
    hint_match: bool,
}

fn find_binary(
    dir: &Path,
    hint: &str,
    binary_keyword: &str,
    logger: &mut (dyn FnMut(&str) + Send),
) -> Result<String, String> {
    fn walk(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_dir() {
                walk(&p, out)?;
            } else {
                out.push(p);
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    walk(dir, &mut files)?;
    let mut elfs: Vec<Candidate> = Vec::new();
    for path in files {
        let magic = magic_bytes(&path).unwrap_or_default();
        if !has_prefix(&magic, "7f454c46") {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let kw_match = !binary_keyword.is_empty() && name.contains(&binary_keyword.to_lowercase());
        let hint_match = !hint.is_empty() && name.contains(&hint.to_lowercase());
        let no_ext = has_no_extension(&path);
        elfs.push(Candidate {
            path,
            size,
            no_ext,
            kw_match,
            hint_match,
        });
    }
    if elfs.is_empty() {
        return Err("no ELF binary found in extracted archive".to_string());
    }

    // 排序：noExt > kwMatch > hintMatch > size（降序）。
    elfs.sort_by(|a, b| {
        b.no_ext
            .cmp(&a.no_ext)
            .then(b.kw_match.cmp(&a.kw_match))
            .then(b.hint_match.cmp(&a.hint_match))
            .then(b.size.cmp(&a.size))
    });
    let chosen = &elfs[0];
    let reason = if chosen.kw_match {
        format!("keyword={:?}", binary_keyword)
    } else if chosen.hint_match {
        format!("repo name={:?}", hint)
    } else if chosen.no_ext {
        "no file extension".to_string()
    } else {
        "largest ELF".to_string()
    };
    logger(&format!(
        "🔍 selected binary: {}  (reason: {})",
        chosen.path.file_name().unwrap_or_default().to_string_lossy(),
        reason
    ));
    Ok(chosen.path.to_string_lossy().to_string())
}

// ---- 解压辅助 ----

fn safe_join(dst: &Path, name: &str) -> PathBuf {
    // 过滤绝对路径与 ".." 路径穿越，防止 zip-slip。
    let mut out = dst.to_path_buf();
    for comp in Path::new(name).components() {
        match comp {
            std::path::Component::Normal(c) => out.push(c),
            _ => continue,
        }
    }
    out
}

fn extract_zip(src: &Path, dst: &Path) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(File::open(src).map_err(|e| e.to_string())?)
        .map_err(|e| format!("open zip: {}", e))?;
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = f.name().to_string();
        let out_path = safe_join(dst, &name);
        if f.is_dir() {
            fs::create_dir_all(&out_path).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut out = File::create(&out_path).map_err(|e| e.to_string())?;
        std::io::copy(&mut f, &mut out).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn extract_tar<R: Read>(reader: R, dst: &Path) -> Result<(), String> {
    let mut ar = tar::Archive::new(reader);
    ar.unpack(dst).map_err(|e| format!("tar unpack: {}", e))
}

fn extract_tar_gz(src: &Path, dst: &Path) -> Result<(), String> {
    let f = File::open(src).map_err(|e| e.to_string())?;
    let gz = flate2::read::MultiGzDecoder::new(f);
    extract_tar(gz, dst)
}

fn extract_gzip(src: &Path, dst: &Path) -> Result<(), String> {
    let f = File::open(src).map_err(|e| e.to_string())?;
    let mut gz = flate2::read::MultiGzDecoder::new(f);
    let mut out = File::create(dst).map_err(|e| e.to_string())?;
    std::io::copy(&mut gz, &mut out).map_err(|e| e.to_string())?;
    Ok(())
}

fn extract_tar_bz2(src: &Path, dst: &Path) -> Result<(), String> {
    let f = File::open(src).map_err(|e| e.to_string())?;
    let bz = bzip2::read::BzDecoder::new(f);
    extract_tar(bz, dst)
}

fn extract_tar_xz(src: &Path, dst: &Path) -> Result<(), String> {
    let f = File::open(src).map_err(|e| e.to_string())?;
    let xz = xz2::read::XzDecoder::new(f);
    extract_tar(xz, dst)
}

fn extract_xz(src: &Path, dst: &Path) -> Result<(), String> {
    let f = File::open(src).map_err(|e| e.to_string())?;
    let mut xz = xz2::read::XzDecoder::new(f);
    let mut out = File::create(dst).map_err(|e| e.to_string())?;
    std::io::copy(&mut xz, &mut out).map_err(|e| e.to_string())?;
    Ok(())
}

fn extract_tar_auto(src: &Path, dst: &Path) -> Result<(), String> {
    let f = File::open(src).map_err(|e| e.to_string())?;
    extract_tar(f, dst)
}

pub fn copy_file(src: &Path, dst: &Path) -> Result<(), String> {
    let mut input = File::open(src).map_err(|e| e.to_string())?;
    let mut output = File::create(dst).map_err(|e| e.to_string())?;
    std::io::copy(&mut input, &mut output).map_err(|e| e.to_string())?;
    Ok(())
}
