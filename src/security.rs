//! 凭据加载、敏感值登记与统一脱敏、按条目原子回写、跨进程锁。
//!
//! 对应 Python 版 `security.py`。差异：
//! - 脱敏表是 [`SecretsRegistry`] 实例（`Arc` 传递），不再有进程级全局单例；
//! - 跨进程锁用 `fs2`（Unix `flock` / Windows `LockFileEx`），
//!   避开 Python 版 `msvcrt.locking` 在 Windows 上让他人无法以写方式打开锁文件的问题。

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use regex::Regex;
use serde_json::{Map, Value};

use crate::cookies::CookieBag;

/// 敏感字段清单：值可进内存与请求头，但不得进日志、异常信息或版本库。
pub const SENSITIVE_FIELDS: [&str; 3] = ["GL-XSRF-TOKEN", "GOD_UUID", "device_id"];

/// 兜底正则：即使某个凭据没经过 register，也按 `key=value` 形态脱敏。
fn secret_pattern() -> &'static [Regex] {
    use std::sync::OnceLock;
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![Regex::new(
            r#"(?i)(GL-XSRF-TOKEN|GL-X-XSRF-TOKEN|GOD_UUID|GL-Uid|GL-DeviceId|GL-CheckSum|ds-website-uuid)\s*[=:]\s*[^\s;&"']+"#
        ).unwrap()]
    })
}

/// 敏感值登记表：登记过的明文值在 [`SecretsRegistry::redact`] 时替换为 `***`。
#[derive(Debug, Default)]
pub struct SecretsRegistry {
    secrets: Mutex<HashSet<String>>,
}

impl SecretsRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn register(&self, value: Option<&str>) {
        if let Some(v) = value {
            // 与 Python 版一致：长度 >= 6 才登记（更短的值容易误伤普通文本）
            if v.chars().count() >= 6 {
                self.secrets.lock().unwrap().insert(v.to_string());
            }
        }
    }

    pub fn register_auth(&self, auth: &Auth) {
        self.register(Some(&auth.xsrf_token));
        self.register(Some(&auth.god_uuid));
        self.register(Some(&auth.device_id));
        for (_, v) in auth.cookies.iter() {
            self.register(Some(v));
        }
    }

    pub fn clear(&self) {
        self.secrets.lock().unwrap().clear();
    }

    /// 统一脱敏入口。永不 panic，输入任意类型都返回字符串。
    pub fn redact(&self, text: Option<&str>) -> String {
        let mut text = match text {
            Some(t) => t.to_string(),
            None => return String::new(),
        };
        if text.is_empty() {
            return text;
        }
        // 先替长值再替短值，避免长串被短串截断后漏替
        let snapshot: Vec<String> = {
            let guard = self.secrets.lock().unwrap();
            let mut v: Vec<String> = guard.iter().cloned().collect();
            v.sort_by_key(|s| std::cmp::Reverse(s.chars().count()));
            v
        };
        for secret in snapshot {
            if !secret.is_empty() && text.contains(&secret) {
                text = text.replace(&secret, "***");
            }
        }
        for pat in secret_pattern() {
            text = pat.replace_all(&text, "$1=***").to_string();
        }
        text
    }
}

// ---------------------------------------------------------------------------
// 账号凭据
// ---------------------------------------------------------------------------

/// 一个已归一化的账号。
#[derive(Debug, Clone)]
pub struct Auth {
    pub label: String,
    pub xsrf_token: String,
    pub god_uuid: String,
    pub device_id: String,
    pub cookies: CookieBag,
    /// 来源认证文件（用于轮换回写）。
    pub auth_file: Option<PathBuf>,
    /// 多账号数组文件里的条目序号。
    pub auth_index: Option<usize>,
    /// 账号级通知通道（缺省 = 沿用全局）。
    pub notify_targets: Option<Vec<String>>,
    /// 账号级收件人（缺省 = 沿用全局）。
    pub notify_to: Option<Vec<String>>,
}

impl Auth {
    /// 用于请求签名的 Cookie 头种子：以 auth cookies 为准，顶层鉴权字段权威覆盖。
    pub fn cookie_seed(&self) -> CookieBag {
        let mut seed = self.cookies.clone();
        seed.insert("GL-XSRF-TOKEN", &self.xsrf_token);
        seed.insert("GOD_UUID", &self.god_uuid);
        seed
    }
}

fn as_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// 统一三种 cookies 形态为 [`CookieBag`]：
/// dict；浏览器导出数组 `[{name, value}, ...]`；单键对象数组 `[{k: v}, ...]`。
fn coerce_cookies(raw: Option<&Value>) -> Result<CookieBag, String> {
    let mut bag = CookieBag::new();
    match raw {
        None => Ok(bag),
        Some(Value::Object(map)) => {
            for (k, v) in map {
                let value = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => continue,
                };
                if !value.is_empty() {
                    bag.insert(k, &value);
                }
            }
            Ok(bag)
        }
        Some(Value::Array(items)) => {
            for item in items {
                let obj = match item.as_object() {
                    Some(o) => o,
                    None => return Err("cookies 数组条目应为对象".into()),
                };
                if let Some(name) = obj.get("name") {
                    if let Some(value) = obj.get("value") {
                        if !value.is_null() && !value.as_str().unwrap_or("").is_empty() {
                            bag.insert(&as_string(Some(name)), &as_string(Some(value)));
                        }
                    }
                } else if obj.len() == 1 {
                    let (k, v) = obj.iter().next().unwrap();
                    let value = as_string(Some(v));
                    if !value.is_empty() {
                        bag.insert(k, &value);
                    }
                } else {
                    return Err("cookies 数组条目格式无法识别".into());
                }
            }
            Ok(bag)
        }
        Some(_) => Err("cookies 字段格式错误（应为对象或数组）".into()),
    }
}

fn read_json(p: &Path, path: &str) -> Result<Value, String> {
    let text = fs::read_to_string(p).map_err(|e| format!("认证文件读取失败: {}: {}", path, e))?;
    serde_json::from_str(&text).map_err(|e| {
        // serde_json 的行列信息在 Display 里，原样带出即可定位
        format!("认证文件不是合法 JSON: {}（{}）", path, e)
    })
}

/// 清理上次崩溃残留的中转文件（含凭据，不能长期躺在磁盘上）。
/// 只删 60 秒前的：并发进程可能正在写自己的中转文件。
fn cleanup_orphan_tmp(p: &Path) {
    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    let parent = match p.parent() {
        Some(d) => d,
        None => return,
    };
    let prefix = format!("{}.", p.file_name().unwrap_or_default().to_string_lossy());
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    if mtime < cutoff {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

fn pick(auth: &Map<String, Value>, cookies: &CookieBag, key: &str) -> String {
    if let Some(v) = auth.get(key) {
        let s = as_string(Some(v));
        if !s.is_empty() {
            return s;
        }
    }
    cookies.get(key).unwrap_or_default().to_string()
}

/// 单条账号字典 -> 归一化 [`Auth`]。错误只报文件名与字段名，不报值。
fn normalize_entry(
    entry: &Map<String, Value>,
    p: &Path,
    path: &str,
    index: Option<usize>,
    secrets: &Arc<SecretsRegistry>,
) -> Result<Auth, String> {
    let cookies = coerce_cookies(entry.get("cookies")).map_err(|e| format!("{}: {}", path, e))?;

    let xsrf = pick(entry, &cookies, "GL-XSRF-TOKEN");
    let uuid = pick(entry, &cookies, "GOD_UUID");
    let device = {
        let d = pick(entry, &cookies, "device_id");
        if !d.is_empty() {
            d
        } else {
            pick(entry, &cookies, "ds-website-uuid")
        }
    };

    let missing: Vec<&str> = SENSITIVE_FIELDS
        .iter()
        .filter(|k| match **k {
            "GL-XSRF-TOKEN" => xsrf.is_empty(),
            "GOD_UUID" => uuid.is_empty(),
            _ => device.is_empty(),
        })
        .copied()
        .collect();
    if !missing.is_empty() {
        let where_ = match index {
            Some(i) => format!("{}[{}]", path, i),
            None => path.to_string(),
        };
        return Err(format!("{} 缺少字段: {}", where_, missing.join(", ")));
    }

    // cookies 与顶层对齐（顶层为权威）
    let mut cookies = cookies;
    cookies.insert("GL-XSRF-TOKEN", &xsrf);
    cookies.insert("GOD_UUID", &uuid);

    // 账号标识：优先取自 cookie 里的手机号（脱敏成 前3****后4），
    // 解析不到才退回 文件名#序号
    let label = match entry.get("label").and_then(Value::as_str) {
        Some(l) if !l.is_empty() => l.to_string(),
        _ => match phone_from_cookies(&cookies) {
            Some(phone) => mask_phone(&phone),
            None => match index {
                Some(i) => format!("{}#{}", path, i),
                None => path.to_string(),
            },
        },
    };

    let (notify_targets, notify_to) = parse_routing(entry);
    let auth = Auth {
        label,
        xsrf_token: xsrf,
        god_uuid: uuid,
        device_id: device,
        cookies,
        auth_file: Some(p.to_path_buf()),
        auth_index: index,
        notify_targets,
        notify_to,
    };

    // POSIX 下权限对组/其他用户可读时警告（Windows 无等价语义）
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(p) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                eprintln!(
                    "警告: {} 权限对组/其他用户可读（{:o}），建议 chmod 600",
                    path,
                    mode & 0o777
                );
            }
        }
    }

    secrets.register_auth(&auth);
    Ok(auth)
}

// ---------------------------------------------------------------------------
// 账号标识：从 cookie 解析手机号
// ---------------------------------------------------------------------------

fn value_to_str_list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// 解析账号条目里的通知路由：`notify.targets` / `notify.to`，
/// 以及「只换收件人」的简写 `notify_mail`。
fn parse_routing(entry: &Map<String, Value>) -> (Option<Vec<String>>, Option<Vec<String>>) {
    let mut targets = None;
    let mut to = None;
    if let Some(spec) = entry.get("notify").and_then(Value::as_object) {
        if let Some(t) = spec
            .get("targets")
            .or_else(|| spec.get("channels"))
            .or_else(|| spec.get("channel"))
        {
            targets = Some(value_to_str_list(t));
        }
        if let Some(m) = spec
            .get("to")
            .or_else(|| spec.get("to_mail"))
            .or_else(|| spec.get("to_mails"))
        {
            to = Some(value_to_str_list(m));
        }
    }
    if let Some(m) = entry
        .get("notify_mail")
        .or_else(|| entry.get("notify_mailbox"))
    {
        to = Some(value_to_str_list(m));
    }
    (targets, to)
}

fn phone_pattern() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    // 注意：regex crate 不支持 lookaround，用「非数字边界」等价实现
    RE.get_or_init(|| Regex::new(r"(?:^|[^0-9])(1[3-9]\d{9})(?:[^0-9]|$)").unwrap())
}

/// 从 cookie 里解析账号手机号：`P_INFO` / `S_INFO` / `NTES_YD_PASSPORT` 常含
/// URL 编码的手机号（实测 `P_INFO` 稳定携带）。解析不到返回 `None`。
pub fn phone_from_cookies(cookies: &CookieBag) -> Option<String> {
    for name in ["P_INFO", "S_INFO", "NTES_YD_PASSPORT"] {
        let raw = match cookies.get(name) {
            Some(v) if !v.is_empty() => v,
            _ => continue,
        };
        let decoded = percent_encoding::percent_decode_str(raw)
            .decode_utf8_lossy()
            .to_string();
        if let Some(c) = phone_pattern().captures(&decoded) {
            if let Some(m) = c.get(1) {
                return Some(m.as_str().to_string());
            }
        }
    }
    None
}

/// 手机号掩码：前 3 后 4（如 `177****7689`）。
pub fn mask_phone(phone: &str) -> String {
    format!("{}****{}", &phone[..3], &phone[phone.len() - 4..])
}

/// label 重复一律加序号去重——label 是客户端字典、退避表与报告的键，
/// 重复会静默顶掉账号。
fn dedupe_labels(auths: &mut [Auth]) {
    use std::collections::HashMap as Map;
    let mut counts: Map<String, usize> = Map::new();
    for a in auths.iter() {
        *counts.entry(a.label.clone()).or_insert(0) += 1;
    }
    let dup: HashSet<String> = counts
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(k, _)| k.clone())
        .collect();
    if dup.is_empty() {
        return;
    }
    let mut seen: Map<String, usize> = Map::new();
    for a in auths.iter_mut() {
        if dup.contains(&a.label) {
            let n = seen.entry(a.label.clone()).or_insert(0);
            *n += 1;
            a.label = format!("{}#{}", a.label, n);
        }
    }
}

/// 从若干认证文件加载全部账号。每个文件顶层可以是单对象或数组。
pub fn load_auths(
    paths: &[String],
    base_dir: &Path,
    secrets: &Arc<SecretsRegistry>,
) -> Result<Vec<Auth>, String> {
    let mut auths = Vec::new();
    for path in paths {
        let p = base_dir.join(path);
        if !p.exists() {
            continue;
        }
        cleanup_orphan_tmp(&p);
        let raw = read_json(&p, path)?;
        let entries: Vec<(Map<String, Value>, Option<usize>)> = match raw {
            Value::Object(map) => vec![(map, None)],
            Value::Array(items) => {
                let mut out = Vec::new();
                for (i, item) in items.iter().enumerate() {
                    match item.as_object() {
                        Some(o) => out.push((o.clone(), Some(i))),
                        None => return Err(format!("认证文件第 {} 个条目不是对象: {}", i, path)),
                    }
                }
                out
            }
            _ => {
                return Err(format!(
                    "认证文件格式错误（应为 JSON 对象或账号数组）: {}",
                    path
                ))
            }
        };
        for (entry, index) in entries {
            auths.push(normalize_entry(&entry, &p, path, index, secrets)?);
        }
    }
    dedupe_labels(&mut auths);
    Ok(auths)
}

// ---------------------------------------------------------------------------
// 跨进程锁与原子写
// ---------------------------------------------------------------------------

/// 跨进程排他锁：把「读 -> 改 -> 写」整段包起来。
///
/// 进程内 `Mutex` 只防同进程多线程，防不住 cron 与手动运行并发：
/// 两个进程各自读到旧数组、各改自己那一条、再先后替换，
/// 后写的会把前者刚轮换的会话覆盖掉。
///
/// 用**旁路锁文件**（目标同名 + `.lock`）：不能锁目标本身，
/// 替换会把目标换成新 inode，锁在旧 inode 上直接失效。
#[derive(Debug)]
pub struct FileLock {
    _file: fs::File,
}

impl FileLock {
    pub fn acquire(target: &Path, timeout: std::time::Duration) -> Result<Self, String> {
        // 锁文件 = 目标同名 + ".lock"（cookies.json -> cookies.json.lock）
        let lock_path = target.with_file_name(format!(
            "{}.lock",
            target.file_name().unwrap_or_default().to_string_lossy()
        ));
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| format!("打开锁文件失败 {}: {}", lock_path.display(), e))?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(_) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "等待凭据文件锁超时（可能有两个实例在跑）: {}",
                            target.display()
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

/// 原子写 JSON：同目录中转文件 + rename。POSIX 下收紧 600。
fn atomic_write_json(p: &Path, data: &Value) -> Result<(), String> {
    let tmp = p.with_file_name(format!(
        "{}.{}.tmp",
        p.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let text = serde_json::to_string_pretty(data).map_err(|e| format!("JSON 序列化失败: {}", e))?;
    if let Err(e) = fs::write(&tmp, text) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("写入中转文件失败: {}", e));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    // std::fs::rename 在 Windows 上同样替换已存在的目标（MoveFileExW + MOVEFILE_REPLACE_EXISTING）
    if let Err(e) = fs::rename(&tmp, p) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("替换目标文件失败: {}", e));
    }
    Ok(())
}

/// 把轮换后的 cookies 就地写回文件对应条目，其余字段原样保留。
/// 读-改-写全程持有跨进程锁。
pub fn update_auth_cookies(
    cookies: &CookieBag,
    path: &Path,
    index: Option<usize>,
) -> Result<(), String> {
    let _lock = FileLock::acquire(path, std::time::Duration::from_secs(10))?;
    let mut raw = read_json(path, &path.to_string_lossy())?;
    let map = cookies.to_json_map();
    match (&mut raw, index) {
        (Value::Object(obj), None) => {
            obj.insert("cookies".into(), Value::Object(map));
        }
        (Value::Array(arr), Some(i)) if i < arr.len() && arr[i].is_object() => {
            arr[i]
                .as_object_mut()
                .unwrap()
                .insert("cookies".into(), Value::Object(map));
        }
        _ => return Err(format!("认证文件里找不到对应条目: {}", path.display())),
    }
    atomic_write_json(path, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("meituan-sec-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(p: &Path, v: serde_json::Value) {
        std::fs::write(p, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    }

    fn auth(label: &str, jsid: &str) -> serde_json::Value {
        serde_json::json!({
            "label": label,
            "GL-XSRF-TOKEN": "xsrf-token-value",
            "GOD_UUID": "god-uuid-value",
            "device_id": "device-id-value",
            "cookies": {"JSESSIONID": jsid},
        })
    }

    #[test]
    fn redact_registered_and_fallback_patterns() {
        let r = SecretsRegistry::new();
        r.register(Some("SYNTHETIC_SECRET_LONG"));
        r.register(Some("tiny")); // <6 字符不登记
        let out = r.redact(Some("x SYNTHETIC_SECRET_LONG y tiny z"));
        assert_eq!(out, "x *** y tiny z");
        // 兜底：未登记的 key=value 形态
        assert_eq!(
            r.redact(Some("GL-XSRF-TOKEN=abcdef123456 xxx")),
            "GL-XSRF-TOKEN=*** xxx"
        );
        assert_eq!(r.redact(Some("GOD_UUID: u-123456")), "GOD_UUID=***");
        // 长值先替，避免被短串截断后漏替
        r.register(Some("aa-bbbbbbbbbb"));
        r.register(Some("bbbccc"));
        assert_eq!(r.redact(Some("v aa-bbbbbbbbbb w bbbccc")), "v *** w ***");
        assert_eq!(r.redact(None), "");
    }

    #[test]
    fn load_single_object_file() {
        let d = tmpdir("single");
        write(&d.join("cookies.json"), auth("老号", "js-1"));
        let r = SecretsRegistry::new();
        let auths = load_auths(&["cookies.json".into()], &d, &r).unwrap();
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0].label, "老号");
        assert_eq!(auths[0].xsrf_token, "xsrf-token-value");
        assert_eq!(auths[0].cookies.get("JSESSIONID"), Some("js-1"));
        // 鉴权字段被登记脱敏
        assert_eq!(r.redact(Some("leak xsrf-token-value")), "leak ***");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn load_multi_account_array_and_dedup_labels() {
        let d = tmpdir("multi");
        write(
            &d.join("cookies.json"),
            serde_json::json!([
                auth("A", "js-a"),
                auth("A", "js-b"),
                auth("A#1", "js-c"),
                auth("B", "js-d"),
            ]),
        );
        let r = SecretsRegistry::new();
        let auths = load_auths(&["cookies.json".into()], &d, &r).unwrap();
        let labels: Vec<&str> = auths.iter().map(|a| a.label.as_str()).collect();
        assert_eq!(labels, vec!["A#1", "A#2", "A#1", "B"]);
        // 去重后无重复（这正是要修的：旧实现会生成与既有 A#1 冲突的新标签）
        assert_eq!(labels.len(), 4);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_field_reports_name_only() {
        let d = tmpdir("missing");
        write(
            &d.join("cookies.json"),
            serde_json::json!([
                {"label": "ok", "GL-XSRF-TOKEN": "t-v", "GOD_UUID": "u-v",
                 "device_id": "d-v", "cookies": {}},
                {"label": "缺字段", "GL-XSRF-TOKEN": "t-v", "device_id": "d-v",
                 "cookies": {}},
            ]),
        );
        let r = SecretsRegistry::new();
        let err = load_auths(&["cookies.json".into()], &d, &r).unwrap_err();
        assert!(err.contains("cookies.json[1]"), "应指出下标: {}", err);
        assert!(err.contains("GOD_UUID"), "应指出字段名: {}", err);
        assert!(!err.contains("u-v"), "不得输出凭据值: {}", err);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn label_falls_back_to_phone_in_p_info() {
        let d = tmpdir("phone");
        write(
            &d.join("cookies.json"),
            serde_json::json!([{
                "GL-XSRF-TOKEN": "t-v", "GOD_UUID": "u-v", "device_id": "d-v",
                "cookies": {"JSESSIONID": "j",
                            "P_INFO": "phone%3D17712347689%26ts%3D1"},
            }]),
        );
        let r = SecretsRegistry::new();
        let auths = load_auths(&["cookies.json".into()], &d, &r).unwrap();
        assert_eq!(auths[0].label, "177****7689");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn explicit_label_wins_over_phone() {
        let d = tmpdir("labelwins");
        write(
            &d.join("cookies.json"),
            serde_json::json!([{
                "label": "自定义",
                "GL-XSRF-TOKEN": "t-v", "GOD_UUID": "u-v", "device_id": "d-v",
                "cookies": {"P_INFO": "phone%3D17712347689"},
            }]),
        );
        let r = SecretsRegistry::new();
        let auths = load_auths(&["cookies.json".into()], &d, &r).unwrap();
        assert_eq!(auths[0].label, "自定义");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn phone_helpers() {
        let mut b = CookieBag::new();
        b.insert("P_INFO", "phone%3D13812345678");
        assert_eq!(phone_from_cookies(&b).as_deref(), Some("13812345678"));
        assert_eq!(mask_phone("13812345678"), "138****5678");
        let empty = CookieBag::new();
        assert_eq!(phone_from_cookies(&empty), None);
    }

    #[test]
    fn browser_export_array_format_is_accepted() {
        // 浏览器导出的 [{name,value},...] 放在 cookies 字段里（与 Python 版一致）；
        // 顶层数组是「账号数组」，两者的解析规则不同。
        let d = tmpdir("export");
        write(
            &d.join("cookies-new.json"),
            serde_json::json!({
                "label": "导出号",
                "cookies": [
                    {"name": "GL-XSRF-TOKEN", "value": "t-v"},
                    {"name": "GOD_UUID", "value": "u-v"},
                    {"name": "device_id", "value": "d-v"},
                    {"name": "JSESSIONID", "value": "j-v"},
                ],
            }),
        );
        let r = SecretsRegistry::new();
        let auths = load_auths(&["cookies-new.json".into()], &d, &r).unwrap();
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0].xsrf_token, "t-v");
        assert_eq!(auths[0].device_id, "d-v");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn notify_routing_parsing() {
        let d = tmpdir("routing");
        write(
            &d.join("cookies.json"),
            serde_json::json!([
                {"label": "A", "GL-XSRF-TOKEN": "t-v", "GOD_UUID": "u-v",
                 "device_id": "d-v", "cookies": {},
                 "notify": {"targets": ["email"], "to": ["a@x.com"]}},
                {"label": "B", "GL-XSRF-TOKEN": "t-v", "GOD_UUID": "u-v",
                 "device_id": "d-v", "cookies": {}, "notify_mail": "b@x.com"},
                {"label": "C", "GL-XSRF-TOKEN": "t-v", "GOD_UUID": "u-v",
                 "device_id": "d-v", "cookies": {}},
            ]),
        );
        let r = SecretsRegistry::new();
        let auths = load_auths(&["cookies.json".into()], &d, &r).unwrap();
        assert_eq!(
            auths[0].notify_targets.as_deref(),
            Some(&["email".to_string()][..])
        );
        assert_eq!(
            auths[0].notify_to.as_deref(),
            Some(&["a@x.com".to_string()][..])
        );
        assert_eq!(auths[1].notify_targets, None);
        assert_eq!(
            auths[1].notify_to.as_deref(),
            Some(&["b@x.com".to_string()][..])
        );
        assert_eq!(auths[2].notify_targets, None);
        assert_eq!(auths[2].notify_to, None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn update_auth_cookies_touches_only_its_own_entry() {
        let d = tmpdir("update");
        let p = d.join("cookies.json");
        write(
            &p,
            serde_json::json!([auth("A", "js-a"), auth("B", "js-b")]),
        );
        let r = SecretsRegistry::new();
        let _ = load_auths(&["cookies.json".into()], &d, &r).unwrap();

        let mut rotated = CookieBag::new();
        rotated.insert("JSESSIONID", "js-rotated");
        update_auth_cookies(&rotated, &p, Some(1)).unwrap();

        let data: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let arr = data.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0]["cookies"]["JSESSIONID"], "js-a",
            "别人的条目不能被抹掉"
        );
        assert_eq!(arr[1]["cookies"]["JSESSIONID"], "js-rotated");
        assert_eq!(arr[1]["label"], "B", "其他字段原样保留");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn file_lock_is_exclusive() {
        let d = tmpdir("lock");
        let p = d.join("cookies.json");
        write(&p, serde_json::json!({}));
        let _held = FileLock::acquire(&p, Duration::from_secs(5)).unwrap();
        // 同一路径再取：应超时而不是共享
        let err = FileLock::acquire(&p, Duration::from_millis(200)).unwrap_err();
        assert!(err.contains("锁"), "{}", err);
        drop(_held);
        // 释放后可以拿到
        let _again = FileLock::acquire(&p, Duration::from_secs(5)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}
