//! Cookie 单一真源：有序集合 `CookieBag` + 服务端更新跟踪 `CookieStore`。
//!
//! 对应 Python 版 `cookies.py`：
//! - 大小写不敏感、保留原始拼写与插入顺序；
//! - `header()` 是请求 Cookie 头的唯一出口；
//! - 服务端 `Set-Cookie` 只允许更新「跟踪名单」内的名字
//!   （默认 `JSESSIONID`）——`GL-XSRF-TOKEN` 等签名依赖字段不允许被响应改写；
//! - 任何进入 store 的值都自动登记进脱敏表。
//!
//! 线程安全：内部 `Mutex` 支撑同账号并发请求（loop 第一波共享同一 store）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::security::SecretsRegistry;

/// 有序 Cookie 集合。大小写不敏感查找，保留原始拼写与插入顺序。
#[derive(Debug, Clone, Default)]
pub struct CookieBag {
    entries: Vec<(String, String)>,
}

impl CookieBag {
    pub fn new() -> Self {
        Self::default()
    }

    /// 写入（同名先删后插，保持「最后写入」且顺序可预期）。空值等于删除。
    pub fn insert(&mut self, name: &str, value: &str) {
        self.remove(name);
        if !value.is_empty() {
            self.entries.push((name.to_string(), value.to_string()));
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        let before = self.entries.len();
        self.entries
            .retain(|(n, _)| n.to_ascii_lowercase() != lower);
        before != self.entries.len()
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|(n, _)| n.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// `name=value; name2=value2`，按插入顺序。
    pub fn header(&self) -> String {
        self.entries
            .iter()
            .map(|(n, v)| format!("{}={}", n, v))
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub fn to_json_map(&self) -> serde_json::Map<String, serde_json::Value> {
        self.entries
            .iter()
            .map(|(n, v)| (n.clone(), serde_json::Value::String(v.clone())))
            .collect()
    }
}

struct Inner {
    bag: CookieBag,
    /// 小写名 -> 原始拼写（跟踪名单）。
    tracked: HashMap<String, String>,
    secrets: Arc<SecretsRegistry>,
}

/// 单账号 Cookie 的单一真源。
pub struct CookieStore {
    inner: Mutex<Inner>,
}

impl CookieStore {
    /// 以 `initial` 为种子建立 store；跟踪名单决定哪些名字可被服务端改写。
    pub fn new(
        initial: &CookieBag,
        tracked_names: &[String],
        secrets: Arc<SecretsRegistry>,
    ) -> Self {
        let bag = initial.clone();
        for (_name, value) in bag.iter() {
            secrets.register(Some(value));
        }
        let tracked = tracked_names
            .iter()
            .map(|n| (n.to_ascii_lowercase(), n.clone()))
            .collect();
        Self {
            inner: Mutex::new(Inner {
                bag,
                tracked,
                secrets,
            }),
        }
    }

    /// 本地写入，返回是否发生变化（新名字算变化）。
    pub fn set(&self, name: &str, value: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let unchanged = inner.bag.get(name) == Some(value);
        if unchanged {
            return false;
        }
        inner.bag.insert(name, value);
        if !value.is_empty() {
            inner.secrets.register(Some(value));
        }
        true
    }

    pub fn get(&self, name: &str) -> Option<String> {
        self.inner.lock().unwrap().bag.get(name).map(String::from)
    }

    pub fn header(&self) -> String {
        self.inner.lock().unwrap().bag.header()
    }

    pub fn to_bag(&self) -> CookieBag {
        self.inner.lock().unwrap().bag.clone()
    }

    /// 应用响应里的 `Set-Cookie` 原始头值，仅更新跟踪名单内的名字。
    ///
    /// 返回发生变化的显示名列表；非跟踪名字一律忽略（鉴权字段由本地掌控）。
    /// 自己解析 `Set-Cookie` 而不是依赖 `reqwest` 的 cookie 特性——
    /// 只需要第一个 `name=value` 段，且不引入额外 feature。
    pub fn apply_set_cookie_headers(&self, raw_headers: &[String]) -> Vec<String> {
        let mut inner = self.inner.lock().unwrap();
        let mut changed = Vec::new();
        for raw in raw_headers {
            // 形如 "JSESSIONID=abc123; Path=/; HttpOnly"
            let first = match raw.split(';').next() {
                Some(s) => s.trim(),
                None => continue,
            };
            let (name, value) = match first.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            let name = name.trim();
            let value = value.trim().trim_matches('"');
            if name.is_empty() || value.is_empty() {
                continue; // 空值是删除指令，按 Python 版语义忽略
            }
            let lower = name.to_ascii_lowercase();
            let canonical = match inner.tracked.get(&lower) {
                Some(c) => c.clone(),
                None => continue, // 不在跟踪名单内
            };
            if inner.bag.get(&canonical) != Some(value) {
                inner.bag.insert(&canonical, value);
                inner.secrets.register(Some(value));
                changed.push(canonical);
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecretsRegistry;

    #[test]
    fn bag_preserves_order_and_is_case_insensitive() {
        let mut b = CookieBag::new();
        b.insert("JSESSIONID", "abc");
        b.insert("GOD_UUID", "u1");
        assert_eq!(b.header(), "JSESSIONID=abc; GOD_UUID=u1");
        assert_eq!(b.get("jsessionid"), Some("abc"));
        assert_eq!(b.get("JsEsSiOnId"), Some("abc"));
        // 同名再插入：仍是单份，按「后写排后面」的可预期顺序
        b.insert("JSESSIONID", "xyz");
        assert_eq!(b.len(), 2);
        assert_eq!(b.header(), "GOD_UUID=u1; JSESSIONID=xyz");
        assert_eq!(b.get("GOD_UUID"), Some("u1"));
        assert_eq!(b.get("JSESSIONID"), Some("xyz"));
    }

    #[test]
    fn empty_value_means_remove() {
        let mut b = CookieBag::new();
        b.insert("A", "1");
        b.insert("A", "");
        assert_eq!(b.len(), 0);
        assert_eq!(b.get("A"), None);
    }

    #[test]
    fn store_registers_values_for_redaction() {
        let secrets = SecretsRegistry::new();
        let mut bag = CookieBag::new();
        bag.insert("JSESSIONID", "session-secret-value");
        let store = CookieStore::new(&bag, &["JSESSIONID".to_string()], Arc::clone(&secrets));
        assert!(store.header().contains("session-secret-value"));
        assert_eq!(
            secrets.redact(Some("泄漏 session-secret-value")),
            "泄漏 ***"
        );
        assert!(!store.set("JSESSIONID", "session-secret-value"));
        assert!(store.set("JSESSIONID", "rotated-123456"));
        assert_eq!(store.get("JSESSIONID").as_deref(), Some("rotated-123456"));
    }

    #[test]
    fn only_tracked_names_can_be_changed_by_server() {
        let secrets = SecretsRegistry::new();
        let mut bag = CookieBag::new();
        bag.insert("JSESSIONID", "old-value");
        bag.insert("GL-XSRF-TOKEN", "keep-me-please");
        let store = CookieStore::new(&bag, &["JSESSIONID".to_string()], Arc::clone(&secrets));
        let changed = store.apply_set_cookie_headers(&[
            "JSESSIONID=new-value; Path=/; HttpOnly".to_string(),
            "GL-XSRF-TOKEN=evil-value; Path=/".to_string(),
            "OTHER=ignored".to_string(),
        ]);
        assert_eq!(changed, vec!["JSESSIONID"]);
        assert_eq!(store.get("JSESSIONID").as_deref(), Some("new-value"));
        // 鉴权字段不被服务端改写
        assert_eq!(
            store.get("GL-XSRF-TOKEN").as_deref(),
            Some("keep-me-please")
        );
    }

    #[test]
    fn empty_set_cookie_value_is_ignored() {
        let secrets = SecretsRegistry::new();
        let mut bag = CookieBag::new();
        bag.insert("JSESSIONID", "keep");
        let store = CookieStore::new(&bag, &["JSESSIONID".to_string()], Arc::clone(&secrets));
        let changed = store.apply_set_cookie_headers(&["JSESSIONID=; Path=/".into()]);
        assert!(changed.is_empty());
        assert_eq!(store.get("JSESSIONID").as_deref(), Some("keep"));
    }
}
