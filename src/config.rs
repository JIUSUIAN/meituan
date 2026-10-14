//! 配置：dataclass 默认值 < claim.config.json < MEITUAN_* 环境变量 < CLI。
//!
//! 对应 Python 版 `config.py`。字段名与默认值保持一致，
//! 这样 `claim.config.json` 与环境变量名可以原样沿用。
//!
//! 与 Python 版的差异：
//! - 键名写错会**报错**（`deny_unknown_fields`），下划线开头的键视为注释忽略；
//! - 布尔值无法识别时报错（Python 版静默按 false 处理，容易埋坑）；
//! - JSON 数组 -> `Vec<String>`；`fixed_coupons` 不支持环境变量覆盖。

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

pub const DEFAULT_CONFIG_FILE: &str = "claim.config.json";
pub const ENV_PREFIX: &str = "MEITUAN_";

/// 查找基准目录：`MEITUAN_BASE_DIR` > 当前工作目录。
///
/// Python 版按「包目录的上一级」解析；Rust 二进制随安装位置漂移，故改为显式基准。
pub fn base_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("MEITUAN_BASE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn home_dir() -> PathBuf {
    for key in ["USERPROFILE", "HOME"] {
        if let Some(v) = std::env::var_os(key) {
            if !v.is_empty() {
                return PathBuf::from(v);
            }
        }
    }
    PathBuf::from(".")
}

fn default_hidden_dir() -> PathBuf {
    home_dir()
        .join("workspace")
        .join("goals")
        .join("goal")
        .join("hidden_files")
}

macro_rules! s {
    ($v:expr) => {
        $v.to_string()
    };
}

/// 默认用户代理（与页面一致，复刻签名时一并带上）。
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/// 默认固定券阵容（与 Python 版 `Config.fixed_coupons` 完全一致）。
fn default_fixed_coupons() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "couponId": "6a5f1a1d4d7fef55f1590b26",
            "couponName": "【外卖券】满28减10", "couponType": "PHONE_REWARD"}),
        serde_json::json!({
            "couponId": "6a5f1a02f34ee33e0d7d9978",
            "couponName": "【5折外卖券】立减20", "couponType": "PHONE_REWARD"}),
        serde_json::json!({
            "couponId": "6a5f1a3df34ee33e0d7d9979",
            "couponName": "【5折外卖券】立减25", "couponType": "PHONE_REWARD"}),
    ]
}

#[derive(Debug, Clone)]
pub struct Config {
    // --- 业务目标 ---
    pub brand_keyword: String,
    pub fixed_brand_id: String,
    pub fixed_coupons: Vec<serde_json::Value>,
    pub snipe_keyword: String,
    pub single_run_snipe_only: bool,
    pub skip_types: Vec<String>,
    pub soldout_stop_after: usize,

    // --- 节奏参数（实测值）---
    pub refresh_every: f64,
    pub first_wave_gap: f64,
    pub sustained_gap: f64,
    pub first_wave_inflight: usize,
    pub sustained_inflight: usize,
    pub rate_limit_backoff: f64,

    // --- 超时与网络 ---
    pub api_timeout: f64,
    pub refresh_timeout: f64,
    pub ping_timeout: f64,
    pub user_agent: String,
    pub base_url: String,
    pub info_path: String,
    pub grant_path: String,
    pub grant_status_path: String,
    /// 用户信息（只读 GET，无副作用）：登录态探针，比 grant-status 探针好——
    /// 后者在探针券当天未领时会实际领掉一张；userInfo 同样返回 873 识别过期。
    pub userinfo_path: String,

    // --- 文件与凭据 ---
    pub auth_files: Vec<String>,
    pub session_cookie_names: Vec<String>,
    pub persist_rotated_cookies: bool,
    pub keepalive_log: String,
    pub run_log_dir: String,

    // --- 消息通知 ---
    pub notify_targets: Vec<String>,
    pub notify_enabled: bool,
    pub notify_events: Vec<String>,
    pub notify_timeout: f64,
    pub notify_mask_labels: bool,
    pub notify_html: bool,
    pub notify_subject: String,
    pub telegram_bot_token: String,
    pub telegram_chat_id: String,
    pub feishu_webhook: String,
    pub dingtalk_webhook: String,
    pub dingtalk_secret: String,
    pub serverchan_send_key: String,
    pub notify_webhook_url: String,
    pub notify_to_mails: Vec<String>,
    pub email_smtp_host: String,
    pub email_smtp_port: u16,
    pub email_use_ssl: bool,
    pub email_use_tls: bool,
    pub email_user: String,
    pub email_password: String,
    pub email_from: String,
    pub email_subject_prefix: String,
    pub resend_api_key: String,
    pub resend_from: String,
    pub resend_from_name: String,

    // --- 运行参数（CLI/环境变量可覆盖）---
    pub loop_minutes: f64,
    pub loop_interval: f64,
    pub fire_at: Option<String>,
    pub fire_lead: f64,
    pub adaptive_lead: bool,
    /// 开火时刻下限（2026-10-14 用户定版）：fire_at - lead 若早于此时刻，
    /// 按此时刻开火。宁可晚到排队（安全），不早到撞旧库存（致命）。
    pub fire_floor: Option<String>,
    pub early_stop_all_soldout: bool,
    pub burst_test: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            brand_keyword: s!("霸王茶姬"),
            fixed_brand_id: s!("6a5f1884bde244285e958847"),
            fixed_coupons: default_fixed_coupons(),
            snipe_keyword: s!("5折"),
            single_run_snipe_only: false,
            skip_types: vec![s!("PLACEHOLDER"), s!("DIRECT_LINK")],
            soldout_stop_after: 3,

            refresh_every: 30.0,
            first_wave_gap: 0.0,
            sustained_gap: 0.5,
            first_wave_inflight: 6,
            sustained_inflight: 2,
            rate_limit_backoff: 60.0,

            api_timeout: 20.0,
            refresh_timeout: 8.0,
            ping_timeout: 15.0,
            user_agent: s!(DEFAULT_USER_AGENT),
            base_url: s!("https://inf.ds.163.com"),
            info_path: s!("/v1/web/exp-vip/external/super-coupon/info"),
            grant_path: s!("/v1/web/exp-vip/external/super-coupon/grant"),
            grant_status_path: s!("/v1/web/exp-vip/external/super-coupon/grant-status"),
            userinfo_path: s!("/v1/web/base/mine/userInfo"),

            auth_files: vec![s!("cookies.json"), s!("cookies-new.json")],
            session_cookie_names: vec![s!("JSESSIONID")],
            persist_rotated_cookies: true,
            keepalive_log: default_hidden_dir()
                .join("keepalive.log")
                .to_string_lossy()
                .to_string(),
            run_log_dir: default_hidden_dir().to_string_lossy().to_string(),

            notify_targets: vec![],
            notify_enabled: true,
            notify_events: vec![
                s!("result"),
                s!("account_result"),
                s!("auth_expired"),
                s!("health"),
            ],
            notify_timeout: 5.0,
            notify_mask_labels: true,
            notify_html: true,
            notify_subject: s!("美团大额券抢券通知"),
            telegram_bot_token: String::new(),
            telegram_chat_id: String::new(),
            feishu_webhook: String::new(),
            dingtalk_webhook: String::new(),
            dingtalk_secret: String::new(),
            serverchan_send_key: String::new(),
            notify_webhook_url: String::new(),
            notify_to_mails: vec![],
            email_smtp_host: String::new(),
            email_smtp_port: 465,
            email_use_ssl: true,
            email_use_tls: false,
            email_user: String::new(),
            email_password: String::new(),
            email_from: String::new(),
            email_subject_prefix: String::new(),
            resend_api_key: String::new(),
            resend_from: String::new(),
            resend_from_name: s!("美团大额券"),

            loop_minutes: 10.0,
            loop_interval: 2.0,
            fire_at: None,
            fire_lead: 0.0,
            adaptive_lead: true,
            fire_floor: Some(s!("23:59:59.7")),
            early_stop_all_soldout: true,
            burst_test: false,
        }
    }
}

impl Config {
    /// 抢券目标：只取含 `snipe_keyword` 的固定券。
    pub fn snipe_coupons(&self) -> Vec<&serde_json::Value> {
        self.fixed_coupons
            .iter()
            .filter(|c| {
                c.get("couponName")
                    .and_then(|v| v.as_str())
                    .map(|n| n.contains(&self.snipe_keyword))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// 只读探针券：固定券里不含 `snipe_keyword` 的那张（满28减10）。
    ///
    /// 仅供 `--ping` 的 grant-status 只读探针使用；`--verify-session` 已改走
    /// `userinfo`（无副作用），不再需要探针券。
    pub fn probe_coupon(&self) -> Option<&serde_json::Value> {
        self.fixed_coupons.iter().find(|c| {
            c.get("couponName")
                .and_then(|v| v.as_str())
                .map(|n| !n.contains(&self.snipe_keyword))
                .unwrap_or(false)
        })
    }
}

// ---------------------------------------------------------------------------
// 层 2：JSON 配置文件
// ---------------------------------------------------------------------------

/// 配置文件的可选字段。全部 `Option<T>`，缺失即为「不覆盖默认值」。
/// `deny_unknown_fields` 让手滑拼错的键名立刻报错。
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    brand_keyword: Option<String>,
    fixed_brand_id: Option<String>,
    fixed_coupons: Option<Vec<serde_json::Value>>,
    snipe_keyword: Option<String>,
    single_run_snipe_only: Option<bool>,
    skip_types: Option<Vec<String>>,
    soldout_stop_after: Option<usize>,
    refresh_every: Option<f64>,
    first_wave_gap: Option<f64>,
    sustained_gap: Option<f64>,
    first_wave_inflight: Option<usize>,
    sustained_inflight: Option<usize>,
    rate_limit_backoff: Option<f64>,
    api_timeout: Option<f64>,
    refresh_timeout: Option<f64>,
    ping_timeout: Option<f64>,
    user_agent: Option<String>,
    base_url: Option<String>,
    info_path: Option<String>,
    grant_path: Option<String>,
    grant_status_path: Option<String>,
    userinfo_path: Option<String>,
    auth_files: Option<Vec<String>>,
    session_cookie_names: Option<Vec<String>>,
    persist_rotated_cookies: Option<bool>,
    keepalive_log: Option<String>,
    run_log_dir: Option<String>,
    notify_targets: Option<Vec<String>>,
    notify_enabled: Option<bool>,
    notify_events: Option<Vec<String>>,
    notify_timeout: Option<f64>,
    notify_mask_labels: Option<bool>,
    notify_html: Option<bool>,
    notify_subject: Option<String>,
    telegram_bot_token: Option<String>,
    telegram_chat_id: Option<String>,
    feishu_webhook: Option<String>,
    dingtalk_webhook: Option<String>,
    dingtalk_secret: Option<String>,
    serverchan_send_key: Option<String>,
    notify_webhook_url: Option<String>,
    notify_to_mails: Option<Vec<String>>,
    email_smtp_host: Option<String>,
    email_smtp_port: Option<u16>,
    email_use_ssl: Option<bool>,
    email_use_tls: Option<bool>,
    email_user: Option<String>,
    email_password: Option<String>,
    email_from: Option<String>,
    email_subject_prefix: Option<String>,
    resend_api_key: Option<String>,
    resend_from: Option<String>,
    resend_from_name: Option<String>,
    loop_minutes: Option<f64>,
    loop_interval: Option<f64>,
    fire_at: Option<String>,
    fire_lead: Option<f64>,
    adaptive_lead: Option<bool>,
    fire_floor: Option<String>,
    early_stop_all_soldout: Option<bool>,
    burst_test: Option<bool>,
}

impl Config {
    /// 用配置文件覆盖（只覆盖出现的键）。
    fn apply_file(&mut self, file: ConfigFile) {
        macro_rules! set {
            ($f:ident) => {
                if let Some(v) = file.$f {
                    self.$f = v;
                }
            };
        }
        // fire_at 在 Config 里是 Option<String>，需要再包一层
        macro_rules! opt_set {
            ($f:ident) => {
                if let Some(v) = file.$f {
                    self.$f = Some(v);
                }
            };
        }
        set!(brand_keyword);
        set!(fixed_brand_id);
        set!(fixed_coupons);
        set!(snipe_keyword);
        set!(single_run_snipe_only);
        set!(skip_types);
        set!(soldout_stop_after);
        set!(refresh_every);
        set!(first_wave_gap);
        set!(sustained_gap);
        set!(first_wave_inflight);
        set!(sustained_inflight);
        set!(rate_limit_backoff);
        set!(api_timeout);
        set!(refresh_timeout);
        set!(ping_timeout);
        set!(user_agent);
        set!(base_url);
        set!(info_path);
        set!(grant_path);
        set!(grant_status_path);
        set!(userinfo_path);
        set!(auth_files);
        set!(session_cookie_names);
        set!(persist_rotated_cookies);
        set!(keepalive_log);
        set!(run_log_dir);
        set!(notify_targets);
        set!(notify_enabled);
        set!(notify_events);
        set!(notify_timeout);
        set!(notify_mask_labels);
        set!(notify_html);
        set!(notify_subject);
        set!(telegram_bot_token);
        set!(telegram_chat_id);
        set!(feishu_webhook);
        set!(dingtalk_webhook);
        set!(dingtalk_secret);
        set!(serverchan_send_key);
        set!(notify_webhook_url);
        set!(notify_to_mails);
        set!(email_smtp_host);
        set!(email_smtp_port);
        set!(email_use_ssl);
        set!(email_use_tls);
        set!(email_user);
        set!(email_password);
        set!(email_from);
        set!(email_subject_prefix);
        set!(resend_api_key);
        set!(resend_from);
        set!(resend_from_name);
        set!(loop_minutes);
        set!(loop_interval);
        opt_set!(fire_at);
        opt_set!(fire_floor);
        set!(fire_lead);
        set!(adaptive_lead);
        set!(early_stop_all_soldout);
        set!(burst_test);
    }
}

// ---------------------------------------------------------------------------
// 层 3：环境变量
// ---------------------------------------------------------------------------

fn parse_bool(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!(
            "布尔值无法识别: {:?}（可用 true/false/1/0/yes/no/on/off）",
            other
        )),
    }
}

fn parse_f64(raw: &str) -> Result<f64, String> {
    raw.trim()
        .parse::<f64>()
        .map_err(|_| format!("数值无法解析: {:?}", raw))
}

fn parse_usize(raw: &str) -> Result<usize, String> {
    raw.trim()
        .parse::<usize>()
        .map_err(|_| format!("整数无法解析: {:?}", raw))
}

fn parse_u16(raw: &str) -> Result<u16, String> {
    raw.trim()
        .parse::<u16>()
        .map_err(|_| format!("整数无法解析: {:?}", raw))
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

impl Config {
    /// 用 `MEITUAN_<字段名大写>` 环境变量覆盖（只表达标量与逗号分隔列表）。
    fn apply_env(&mut self, env: &HashMap<String, String>) -> Result<(), String> {
        macro_rules! get {
            ($f:ident) => {
                env.get(&format!("{}{}", ENV_PREFIX, stringify!($f).to_uppercase()))
            };
        }
        macro_rules! s_ {
            ($f:ident) => {
                if let Some(r) = get!($f) {
                    self.$f = r.clone();
                }
            };
        }
        macro_rules! b_ {
            ($f:ident) => {
                if let Some(r) = get!($f) {
                    self.$f = parse_bool(r)?;
                }
            };
        }
        macro_rules! f_ {
            ($f:ident) => {
                if let Some(r) = get!($f) {
                    self.$f = parse_f64(r)?;
                }
            };
        }
        macro_rules! u_ {
            ($f:ident) => {
                if let Some(r) = get!($f) {
                    self.$f = parse_usize(r)?;
                }
            };
        }
        macro_rules! p_ {
            ($f:ident) => {
                if let Some(r) = get!($f) {
                    self.$f = parse_u16(r)?;
                }
            };
        }
        macro_rules! o_ {
            ($f:ident) => {
                if let Some(r) = get!($f) {
                    self.$f = if r.is_empty() { None } else { Some(r.clone()) };
                }
            };
        }
        macro_rules! v_ {
            ($f:ident) => {
                if let Some(r) = get!($f) {
                    self.$f = split_csv(r);
                }
            };
        }

        // 嵌套结构无法用环境变量表达，明确拒绝而不是塞进一个莫名其妙的字符串
        if env.contains_key(&format!("{}FIXED_COUPONS", ENV_PREFIX)) {
            return Err(format!(
                "字段 fixed_coupons 不支持环境变量覆盖（请改 {}）",
                DEFAULT_CONFIG_FILE
            ));
        }

        s_!(brand_keyword);
        s_!(fixed_brand_id);
        s_!(snipe_keyword);
        b_!(single_run_snipe_only);
        v_!(skip_types);
        u_!(soldout_stop_after);
        f_!(refresh_every);
        f_!(first_wave_gap);
        f_!(sustained_gap);
        u_!(first_wave_inflight);
        u_!(sustained_inflight);
        f_!(rate_limit_backoff);
        f_!(api_timeout);
        f_!(refresh_timeout);
        f_!(ping_timeout);
        s_!(user_agent);
        s_!(base_url);
        s_!(info_path);
        s_!(grant_path);
        s_!(grant_status_path);
        s_!(userinfo_path);
        v_!(auth_files);
        v_!(session_cookie_names);
        b_!(persist_rotated_cookies);
        s_!(keepalive_log);
        s_!(run_log_dir);
        v_!(notify_targets);
        b_!(notify_enabled);
        v_!(notify_events);
        f_!(notify_timeout);
        b_!(notify_mask_labels);
        b_!(notify_html);
        s_!(notify_subject);
        s_!(telegram_bot_token);
        s_!(telegram_chat_id);
        s_!(feishu_webhook);
        s_!(dingtalk_webhook);
        s_!(dingtalk_secret);
        s_!(serverchan_send_key);
        s_!(notify_webhook_url);
        v_!(notify_to_mails);
        s_!(email_smtp_host);
        p_!(email_smtp_port);
        b_!(email_use_ssl);
        b_!(email_use_tls);
        s_!(email_user);
        s_!(email_password);
        s_!(email_from);
        s_!(email_subject_prefix);
        s_!(resend_api_key);
        s_!(resend_from);
        s_!(resend_from_name);
        f_!(loop_minutes);
        f_!(loop_interval);
        o_!(fire_at);
        f_!(fire_lead);
        b_!(adaptive_lead);
        b_!(early_stop_all_soldout);
        b_!(burst_test);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 层 4：CLI 覆盖
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub loop_minutes: Option<f64>,
    pub loop_interval: Option<f64>,
    pub fire_at: Option<String>,
    pub fire_lead: Option<f64>,
    pub notify_enabled: Option<bool>,
}

impl Config {
    fn apply_overrides(&mut self, o: &Overrides) {
        if let Some(v) = o.loop_minutes {
            self.loop_minutes = v;
        }
        if let Some(v) = o.loop_interval {
            self.loop_interval = v;
        }
        if let Some(v) = &o.fire_at {
            self.fire_at = Some(v.clone());
        }
        if let Some(v) = o.fire_lead {
            self.fire_lead = v;
        }
        if let Some(v) = o.notify_enabled {
            self.notify_enabled = v;
        }
    }
}

/// 读取配置文件（层 2）。
pub fn read_config_file(path: &std::path::Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("配置文件读取失败: {}: {}", path.display(), e))?;
    let mut value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("配置文件不是合法 JSON: {}（{}）", path.display(), e))?;
    if !value.is_object() {
        return Err(format!(
            "配置文件格式错误（应为 JSON 对象）: {}",
            path.display()
        ));
    }
    // 下划线开头的键视为注释，忽略
    if let Some(obj) = value.as_object_mut() {
        obj.retain(|k, _| !k.starts_with('_'));
    }
    let file: ConfigFile = serde_json::from_value(value)
        .map_err(|e| format!("配置字段有误（{}）: {}", path.display(), e))?;
    let mut cfg = Config::default();
    cfg.apply_file(file);
    Ok(cfg)
}

/// 构建最终配置：默认值 < JSON 文件 < `MEITUAN_*` 环境变量 < CLI。
pub fn load_config(
    path: Option<&std::path::Path>,
    overrides: &Overrides,
) -> Result<Config, String> {
    let cfg_path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir().join(DEFAULT_CONFIG_FILE));
    let mut cfg = if cfg_path.exists() {
        read_config_file(&cfg_path)?
    } else {
        Config::default()
    };

    let env: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with(ENV_PREFIX))
        .collect();
    cfg.apply_env(&env)?;
    cfg.apply_overrides(overrides);
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn tmp(prefix: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "meituan-test-{}-{}.json",
            prefix,
            std::process::id()
        ));
        p
    }

    #[test]
    fn defaults_match_python_version() {
        let c = Config::default();
        assert_eq!(c.brand_keyword, "霸王茶姬");
        assert_eq!(c.snipe_keyword, "5折");
        assert_eq!(c.soldout_stop_after, 3);
        assert_eq!(c.first_wave_gap as f32, 0.0);
        assert_eq!(c.first_wave_inflight, 6);
        assert_eq!(c.sustained_inflight, 2);
        assert_eq!(c.rate_limit_backoff as f32, 60.0);
        assert_eq!(c.email_smtp_port, 465);
        assert!(c.email_use_ssl);
        assert!(c.adaptive_lead);
        assert!(c.early_stop_all_soldout);
        assert_eq!(c.snipe_coupons().len(), 2);
        assert_eq!(
            c.probe_coupon().unwrap()["couponName"],
            "【外卖券】满28减10"
        );
    }

    #[test]
    fn json_layer_overrides_and_comment_keys_ignored() {
        let p = tmp("cfg");
        std::fs::write(
            &p,
            r#"{
            "_说明": "注释键应被忽略",
            "loop_minutes": 5,
            "sustained_gap": 1.0,
            "single_run_snipe_only": true,
            "notify_targets": ["resend"],
            "skip_types": ["PLACEHOLDER", "DIRECT_LINK", "OTHER"]
        }"#,
        )
        .unwrap();
        let c = read_config_file(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(c.loop_minutes as f32, 5.0);
        assert_eq!(c.sustained_gap as f32, 1.0);
        assert!(c.single_run_snipe_only);
        assert_eq!(c.notify_targets, vec!["resend"]);
        assert_eq!(c.skip_types.len(), 3);
        assert_eq!(c.loop_interval as f32, 2.0, "未覆盖的保持默认");
    }

    #[test]
    fn unknown_key_is_an_error() {
        let p = tmp("bad");
        std::fs::write(&p, r#"{"loop_minute": 5}"#).unwrap();
        let err = read_config_file(&p).unwrap_err();
        let _ = std::fs::remove_file(&p);
        assert!(err.contains("loop_minute"), "错误应指出字段名: {}", err);
        assert!(err.contains("unknown field") || err.contains("无法识别"));
    }

    #[test]
    fn invalid_json_reports_position() {
        let p = tmp("broken");
        std::fs::write(&p, "{not json,,,").unwrap();
        let err = read_config_file(&p).unwrap_err();
        let _ = std::fs::remove_file(&p);
        assert!(err.contains("不是合法 JSON"));
    }

    #[test]
    fn env_layer_parses_scalars_and_csv() {
        let mut c = Config::default();
        let env: HashMap<String, String> = [
            ("MEITUAN_LOOP_MINUTES", "7"),
            ("MEITUAN_BURST_TEST", "1"),
            ("MEITUAN_SINGLE_RUN_SNIPE_ONLY", "false"),
            ("MEITUAN_NOTIFY_TARGETS", "telegram,feishu"),
            ("MEITUAN_EMAIL_SMTP_PORT", "587"),
            ("MEITUAN_FIRE_AT", "23:59:59.700"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        c.apply_env(&env).unwrap();
        assert_eq!(c.loop_minutes as f32, 7.0);
        assert!(c.burst_test);
        assert!(!c.single_run_snipe_only);
        assert_eq!(c.notify_targets, vec!["telegram", "feishu"]);
        assert_eq!(c.email_smtp_port, 587);
        assert_eq!(c.fire_at.as_deref(), Some("23:59:59.700"));
    }

    #[test]
    fn env_rejects_nested_structure_and_bad_bool() {
        let mut c = Config::default();
        let nested: HashMap<String, String> =
            [("MEITUAN_FIXED_COUPONS".to_string(), "[]".to_string())]
                .into_iter()
                .collect();
        let err = c.apply_env(&nested).unwrap_err();
        assert!(err.contains("fixed_coupons"));

        let bad: HashMap<String, String> =
            [("MEITUAN_BURST_TEST".to_string(), "maybe".to_string())]
                .into_iter()
                .collect();
        let err = c.apply_env(&bad).unwrap_err();
        assert!(err.contains("布尔值"));
    }

    #[test]
    fn cli_overrides_win_over_env_and_file() {
        let mut c = Config {
            loop_minutes: 5.0,
            ..Default::default()
        };
        c.apply_overrides(&Overrides {
            loop_minutes: Some(9.0),
            ..Default::default()
        });
        assert_eq!(c.loop_minutes as f32, 9.0);
        // None 不覆盖
        c.apply_overrides(&Overrides::default());
        assert_eq!(c.loop_minutes as f32, 9.0);
    }
}
