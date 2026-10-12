//! 消息通知：Telegram / 飞书 / 钉钉 / Server酱 / 邮件(SMTP) / Resend / 通用 webhook。
//!
//! 对应 Python 版 `notify.py`。三条边界：
//! 1. **best-effort**——通知是旁路，发送失败绝不影响抢券主流程；
//! 2. **通知凭据同等保密**——token / webhook / sendkey / SMTP 密码一律登记进脱敏表；
//! 3. **HTML 与纯文本同一口径脱敏**——动态字段先进 `redact()` 再进渲染，
//!    堵住「上游把凭据回显进 detail 时随邮件外泄」。
//!
//! 与 Python 版的差异：
//! - 脱敏表由调用方以 `Arc<SecretsRegistry>` 注入，不再是进程级全局；
//! - SMTP 明文连接下**拒绝发送凭据**（Python 版已修，这里直接内置）。

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use hmac::{Hmac, Mac};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::config::Config;
use crate::errors::ApiTransportError;
use crate::flows::beijing_ts;
use crate::report_html;
use crate::security::{Auth, SecretsRegistry};

pub const CHANNELS: [&str; 7] = [
    "telegram",
    "feishu",
    "dingtalk",
    "serverchan",
    "email",
    "resend",
    "webhook",
];

/// 每个通道必需的配置项（缺失时只报字段名，不报值）。
const REQUIRED: &[(&str, &[&str])] = &[
    ("telegram", &["telegram_bot_token", "telegram_chat_id"]),
    ("feishu", &["feishu_webhook"]),
    ("dingtalk", &["dingtalk_webhook"]),
    ("serverchan", &["serverchan_send_key"]),
    ("email", &["email_smtp_host", "notify_to_mails"]),
    (
        "resend",
        &["resend_api_key", "resend_from", "notify_to_mails"],
    ),
    ("webhook", &["notify_webhook_url"]),
];

/// 可由单次调用覆盖收件人的通道：字段 -> 覆盖入口。
fn recipient_field(channel: &str) -> Option<&'static str> {
    match channel {
        "email" | "resend" => Some("notify_to_mails"),
        _ => None,
    }
}

const EVENT_TITLES: &[(&str, &str)] = &[
    ("result", "美团大额券 · 抢券结果"),
    ("account_result", "美团大额券 · 账号领取详情"),
    ("auth_expired", "美团大额券 登录态失效"),
    ("rate_limited", "美团大额券 命中限流"),
    ("health", "美团大额券 健康检查"),
    ("error", "美团大额券 运行异常"),
    ("test", "美团大额券 通知测试"),
];

/// 把 label 里的长数字（多为手机号）掩成 `前3****后2`。
///
/// label 里已经带 `*` 的（用户自己打过码）原样返回——二次打码会让标识糊成一团。
pub fn mask_label(label: &str) -> String {
    if label.contains('*') {
        return label.to_string();
    }
    let mut out = String::new();
    for chunk in label.split_inclusive(|c: char| !c.is_ascii_digit()) {
        if chunk.len() >= 4 && chunk.chars().all(|c| c.is_ascii_digit()) {
            out.push_str(&chunk[..3]);
            out.push_str("****");
            out.push_str(&chunk[chunk.len() - 2..]);
        } else {
            out.push_str(chunk);
        }
    }
    out
}

/// 账号条目的通知路由：`(targets, to_mails)`，缺省项为 `None` = 沿用全局。
///
/// 通道凭据仍留在全局配置里，账号条目只决定「这个账号的详情走哪条通道、发给谁」。
pub fn account_routing(auth: &Auth) -> (Option<Vec<String>>, Option<Vec<String>>) {
    (auth.notify_targets.clone(), auth.notify_to.clone())
}

/// 钉钉自定义机器人「加签」：timestamp + HMAC-SHA256 拼进 query。
pub fn dingtalk_signed_url(webhook: &str, secret: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    let string_to_sign = format!("{}\n{}", ts, secret);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(string_to_sign.as_bytes());
    let sign = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    let sep = if webhook.contains('?') { "&" } else { "?" };
    format!(
        "{}{}timestamp={}&sign={}",
        webhook,
        sep,
        ts,
        percent_encoding::utf8_percent_encode(&sign, percent_encoding::NON_ALPHANUMERIC)
    )
}

/// 通知凭据字段清单（与业务凭据同等保密）。
const SECRET_FIELDS: [&str; 12] = [
    "telegram_bot_token",
    "telegram_chat_id",
    "feishu_webhook",
    "dingtalk_webhook",
    "dingtalk_secret",
    "serverchan_send_key",
    "notify_webhook_url",
    "email_password",
    "email_user",
    "email_from",
    "resend_api_key",
    "notify_to_mails",
];

/// 把配置里的通知凭据登记进脱敏表。
///
/// CLI 在 `load_config` 之后就该立刻调用——否则「构造 Notifier 之前」报出的
/// 配置错误可能把管理密码原样打出来。
pub fn register_secrets(cfg: &Config, secrets: &SecretsRegistry) {
    for name in SECRET_FIELDS {
        secrets.register(Some(&config_field(cfg, name)));
    }
    // webhook URL 里的 token 常以 query 参数出现，把参数值也登记
    for url in [
        &cfg.feishu_webhook,
        &cfg.dingtalk_webhook,
        &cfg.notify_webhook_url,
    ] {
        if url.is_empty() {
            continue;
        }
        if let Some(query) = url.split_once('?').map(|x| x.1) {
            for pair in query.split('&') {
                if let Some((_, v)) = pair.split_once('=') {
                    secrets.register(Some(v));
                }
            }
        }
    }
}

/// 按字段名读配置里的字符串值（用于脱敏登记与通道必需项检查）。
pub fn config_field(cfg: &Config, name: &str) -> String {
    macro_rules! g {
        ($f:ident) => {
            cfg.$f.clone()
        };
    }
    macro_rules! l {
        ($f:ident) => {
            cfg.$f.join(",")
        };
    }
    match name {
        "telegram_bot_token" => g!(telegram_bot_token),
        "telegram_chat_id" => g!(telegram_chat_id),
        "feishu_webhook" => g!(feishu_webhook),
        "dingtalk_webhook" => g!(dingtalk_webhook),
        "dingtalk_secret" => g!(dingtalk_secret),
        "serverchan_send_key" => g!(serverchan_send_key),
        "notify_webhook_url" => g!(notify_webhook_url),
        "email_smtp_host" => g!(email_smtp_host),
        "email_user" => g!(email_user),
        "email_password" => g!(email_password),
        "email_from" => g!(email_from),
        "resend_api_key" => g!(resend_api_key),
        "resend_from" => g!(resend_from),
        "resend_from_name" => g!(resend_from_name),
        "notify_to_mails" => l!(notify_to_mails),
        _ => String::new(),
    }
}

/// 一次待发送的事件内容。
pub struct NotifyContent {
    pub event: String,
    pub title: String,
    pub text: String,
    pub html: Option<String>,
}

/// 按配置把事件推给若干通道；未配置任何通道时整体禁用（零副作用）。
pub struct Notifier {
    cfg: Config,
    secrets: Arc<SecretsRegistry>,
    http: reqwest::blocking::Client,
}

impl Notifier {
    pub fn new(cfg: Config, secrets: Arc<SecretsRegistry>) -> Self {
        Self {
            cfg,
            secrets,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs_f64(Config::default().notify_timeout))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn new_with_timeout(cfg: Config, secrets: Arc<SecretsRegistry>) -> Self {
        Self {
            cfg,
            secrets,
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs_f64(Config::default().notify_timeout))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.notify_enabled && !self.cfg.notify_targets.is_empty()
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    // -- 对外入口 ---------------------------------------------------------

    /// 发送一个事件，返回 `[(channel, ok, detail)]`。本身永不返回错误。
    #[allow(clippy::too_many_arguments)]
    pub fn notify(
        &self,
        event: &str,
        text: &str,
        title: Option<&str>,
        force: bool,
        to_mails: Option<&[String]>,
        targets: Option<&[String]>,
        html: Option<String>,
    ) -> Vec<(String, bool, String)> {
        if !self.cfg.notify_enabled {
            return Vec::new();
        }
        if targets.is_none() && self.cfg.notify_targets.is_empty() {
            return Vec::new();
        }
        if !force && !self.cfg.notify_events.iter().any(|e| e == event) {
            return Vec::new();
        }
        let title = title
            .map(|s| s.to_string())
            .or_else(|| {
                EVENT_TITLES
                    .iter()
                    .find(|(k, _)| *k == event)
                    .map(|(_, v)| v.to_string())
            })
            .unwrap_or_else(|| "美团 通知".to_string());

        let channels: Vec<String> = match targets {
            Some(t) => t
                .iter()
                .filter(|c| CHANNELS.contains(&c.as_str()))
                .cloned()
                .collect(),
            None => self.cfg.notify_targets.clone(),
        };
        let unknown: Vec<&String> = match targets {
            Some(t) => t
                .iter()
                .filter(|c| !CHANNELS.contains(&c.as_str()))
                .collect(),
            None => Vec::new(),
        };
        if !unknown.is_empty() {
            self.log(&format!(
                "通知[{}] 账号指定了无法识别的通道，已忽略: {}",
                event,
                unknown
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        let content = NotifyContent {
            event: event.to_string(),
            title,
            text: text.to_string(),
            html,
        };
        let mut results = Vec::new();
        for channel in &channels {
            let ok = self.send_one(channel, &content, to_mails);
            results.push((
                channel.clone(),
                ok.is_ok(),
                ok.err().unwrap_or_else(|| "已发送".to_string()),
            ));
        }
        for (channel, ok, detail) in &results {
            self.log(&format!(
                "通知[{}] {}: {}",
                event,
                channel,
                if *ok {
                    detail.clone()
                } else {
                    format!("失败 {}", detail)
                }
            ));
        }
        results
    }

    /// 把 `{label: [item...]}` 形式的报告摘要发出去（label 默认掩码）。
    pub fn notify_report(
        &self,
        event: &str,
        report: &[(String, Vec<Value>)],
        extra_lines: &[String],
    ) -> Vec<(String, bool, String)> {
        let mut lines = Vec::new();
        let mut statuses: Vec<(String, usize)> = Vec::new();
        let mut masked: Vec<(String, Vec<Value>)> = Vec::new();
        for (label, items) in report {
            let who = if self.cfg.notify_mask_labels {
                mask_label(label)
            } else {
                label.clone()
            };
            let parts: Vec<String> = items
                .iter()
                .map(|it| {
                    let s = it
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("?")
                        .to_string();
                    match statuses.iter_mut().find(|(k, _)| *k == s) {
                        Some(e) => e.1 += 1,
                        None => statuses.push((s.clone(), 1)),
                    }
                    s
                })
                .collect();
            lines.push(format!(
                "{}: {}",
                who,
                if parts.is_empty() {
                    "无结果".to_string()
                } else {
                    parts.join(" ")
                }
            ));
            masked.push((self.safe_text(&who), self.safe_items(items)));
        }
        let mut body = lines.join("\n");
        if !statuses.is_empty() {
            let dist: Vec<String> = statuses
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            body = format!("状态分布 {}\n{}", dist.join(", "), body);
        }
        let html = if self.cfg.notify_html {
            Some(report_html::render_summary(
                &masked,
                &self.safe_lines(extra_lines),
                &self.safe_text(&self.stamp()),
            ))
        } else {
            None
        };
        self.notify(event, &body, None, false, None, None, html)
    }

    /// 单账号一条消息：每张券一行，可带发送时刻/耗时/服务端最终状态。
    pub fn notify_account(
        &self,
        label: &str,
        items: &[Value],
        timings: &[(String, String, f64)],
        extra_lines: &[String],
        to_mails: Option<&[String]>,
        targets: Option<&[String]>,
    ) -> Vec<(String, bool, String)> {
        let who = if self.cfg.notify_mask_labels {
            mask_label(label)
        } else {
            label.to_string()
        };
        let mut lines: Vec<String> = Vec::new();
        for item in items {
            let name = item
                .get("coupon")
                .and_then(Value::as_str)
                .unwrap_or("（无券名）");
            let status = item.get("status").and_then(Value::as_str).unwrap_or("?");
            let mut line = format!("{}: {}", name, status);
            if let Some((send_ts, _, elapsed)) = timings.iter().find(|(n, _, _)| n == name) {
                line.push_str(&format!("（发送 {}，耗时 {:.2}s）", send_ts, elapsed));
            }
            if let Some(gs) = item.get("grant_status").and_then(Value::as_str) {
                line.push_str(&format!(" 服务端 {}", gs));
            }
            let detail = item
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            // granted 的 detail 是奖品 JSON，噪音大；只在非成功时带上原因
            if !detail.is_empty() && status != "granted" {
                line.push_str(&format!(
                    " | {}",
                    self.secrets
                        .redact(Some(detail))
                        .chars()
                        .take(80)
                        .collect::<String>()
                ));
            }
            lines.push(line);
        }
        if lines.is_empty() {
            lines.push("无结果".into());
        }
        let body = std::iter::once(who.clone())
            .chain(lines)
            .chain(extra_lines.iter().cloned())
            .collect::<Vec<_>>()
            .join("\n");
        let html = if self.cfg.notify_html {
            Some(report_html::render_account(
                &self.safe_text(&who),
                &self.safe_items(items),
                timings,
                &self.safe_lines(extra_lines),
                &self.safe_text(&self.stamp()),
                // 顶部大卡只放 5 折主目标，满28减10 等进「其他券」
                Some(self.cfg.snipe_keyword.as_str()),
            ))
        } else {
            None
        };
        self.notify(
            "account_result",
            &body,
            None,
            false,
            to_mails,
            targets,
            html,
        )
    }

    // -- 脱敏辅助 ---------------------------------------------------------

    fn safe_text(&self, value: &str) -> String {
        self.secrets.redact(Some(value))
    }

    /// 给 HTML 渲染用的条目副本：动态文本字段先脱敏，不改动调用方数据。
    fn safe_items(&self, items: &[Value]) -> Vec<Value> {
        items
            .iter()
            .map(|item| {
                let mut out = item.clone();
                if let Some(obj) = out.as_object_mut() {
                    for key in ["coupon", "coupon_type", "status", "grant_status", "detail"] {
                        if let Some(v) = obj.get(key).and_then(Value::as_str) {
                            let red = self.secrets.redact(Some(v));
                            obj.insert(key.to_string(), Value::String(red));
                        }
                    }
                }
                out
            })
            .collect()
    }

    fn safe_lines(&self, lines: &[String]) -> Vec<String> {
        lines.iter().map(|l| self.secrets.redact(Some(l))).collect()
    }

    fn stamp(&self) -> String {
        format!("生成时间 {}（北京时间）", beijing_ts())
    }

    fn log(&self, msg: &str) {
        eprintln!("{} {}", beijing_ts(), self.secrets.redact(Some(msg)));
    }

    // -- 各通道实现 -------------------------------------------------------

    fn send_one(
        &self,
        channel: &str,
        content: &NotifyContent,
        to_mails: Option<&[String]>,
    ) -> Result<(), String> {
        // 收件人可由本次调用覆盖，覆盖时不再要求全局配置里有它
        let mut missing: Vec<&str> = Vec::new();
        for f in REQUIRED
            .iter()
            .find(|(c, _)| *c == channel)
            .map(|(_, f)| *f)
            .unwrap_or(&[])
        {
            if to_mails.is_some() && recipient_field(channel) == Some(*f) {
                continue;
            }
            if self.cfg_field(f).is_empty() {
                missing.push(f);
            }
        }
        if !missing.is_empty() {
            return Err(format!("缺少配置: {}", missing.join(", ")));
        }

        let body = format!("{}\n{}", content.title, content.text);
        match channel {
            "telegram" => self.post_json(
                &format!(
                    "https://api.telegram.org/bot{}/sendMessage",
                    self.cfg_field("telegram_bot_token")
                ),
                Some("telegram"),
                &json!({"chat_id": self.cfg_field("telegram_chat_id"),
                        "text": body, "disable_web_page_preview": true}),
            )?,
            "feishu" => self.post_json(
                &self.cfg_field("feishu_webhook"),
                Some("feishu"),
                &json!({"msg_type": "text",
                        "content": {"text": body}}),
            )?,
            "dingtalk" => {
                let mut url = self.cfg_field("dingtalk_webhook");
                if !self.cfg_field("dingtalk_secret").is_empty() {
                    url = dingtalk_signed_url(&url, &self.cfg_field("dingtalk_secret"));
                }
                self.post_json(
                    &url,
                    Some("dingtalk"),
                    &json!({"msgtype": "text", "text": {"content": body}}),
                )?
            }
            "serverchan" => self.post_form(
                &format!(
                    "https://sctapi.ftqq.com/{}.send",
                    self.cfg_field("serverchan_send_key")
                ),
                Some("serverchan"),
                &[
                    ("title", content.title.clone()),
                    ("desp", content.text.clone()),
                ],
            )?,
            "email" => self.send_email(content, to_mails)?,
            "resend" => self.send_resend(content, to_mails)?,
            "webhook" => self.post_json(
                &self.cfg_field("notify_webhook_url"),
                None,
                &json!({"event": content.event, "title": content.title,
                        "text": content.text}),
            )?,
            _ => return Err(format!("未知通知通道: {}", channel)),
        }
        Ok(())
    }

    fn cfg_field(&self, name: &str) -> String {
        macro_rules! g {
            ($f:ident) => {
                self.cfg.$f.clone()
            };
        }
        match name {
            "telegram_bot_token" => g!(telegram_bot_token),
            "telegram_chat_id" => g!(telegram_chat_id),
            "feishu_webhook" => g!(feishu_webhook),
            "dingtalk_webhook" => g!(dingtalk_webhook),
            "dingtalk_secret" => g!(dingtalk_secret),
            "serverchan_send_key" => g!(serverchan_send_key),
            "notify_webhook_url" => g!(notify_webhook_url),
            "email_smtp_host" => g!(email_smtp_host),
            "resend_api_key" => g!(resend_api_key),
            "resend_from" => g!(resend_from),
            "resend_from_name" => g!(resend_from_name),
            _ => String::new(),
        }
    }

    /// 发一次请求并做通用错误判定。这些 webhook 常见「HTTP 200 但业务失败」，
    /// 所以除了状态码还要看 body 里的成功标志。
    fn post_json(&self, url: &str, channel: Option<&str>, body: &Value) -> Result<(), String> {
        let resp = self
            .http
            .post(url)
            .json(body)
            .timeout(Duration::from_secs_f64(self.cfg.notify_timeout))
            .send()
            .map_err(|e| self.secrets.redact(Some(&e.to_string()))[..120].to_string())?;
        self.check_response(resp, channel)
    }

    fn post_form(
        &self,
        url: &str,
        channel: Option<&str>,
        form: &[(&str, String)],
    ) -> Result<(), String> {
        let resp = self
            .http
            .post(url)
            .form(form)
            .timeout(Duration::from_secs_f64(self.cfg.notify_timeout))
            .send()
            .map_err(|e| self.secrets.redact(Some(&e.to_string()))[..120].to_string())?;
        self.check_response(resp, channel)
    }

    fn check_response(
        &self,
        resp: reqwest::blocking::Response,
        channel: Option<&str>,
    ) -> Result<(), String> {
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        if status >= 400 {
            return Err(format!(
                "HTTP {}: {}",
                status,
                self.secrets
                    .redact(Some(&text))
                    .chars()
                    .take(120)
                    .collect::<String>()
            ));
        }
        let payload: Option<Value> = serde_json::from_str(&text).ok();
        if let (Some(ch), Some(Value::Object(map))) = (channel, &payload) {
            let field = match ch {
                "telegram" => "ok",
                "feishu" => "code",
                "dingtalk" => "errcode",
                "serverchan" => "code",
                _ => return Ok(()),
            };
            if let Some(v) = map.get(field) {
                let bad = match ch {
                    "telegram" => v.as_bool() != Some(true),
                    "serverchan" => !matches!(v.as_str(), Some("0")) && v.as_i64() != Some(0),
                    _ => v.as_i64() != Some(0),
                };
                if bad {
                    return Err(format!(
                        "通道返回失败 {}={}: {}",
                        field,
                        v,
                        self.secrets
                            .redact(Some(&text))
                            .chars()
                            .take(120)
                            .collect::<String>()
                    ));
                }
            }
        }
        Ok(())
    }

    fn resolve_recipients(&self, to_mails: Option<&[String]>) -> Result<Vec<String>, String> {
        let list: Vec<String> = match to_mails {
            Some(t) => t.to_vec(),
            None => self.cfg.notify_to_mails.clone(),
        };
        if list.is_empty() {
            return Err("缺少收件邮箱（notify_to_mails 或账号的 to）".into());
        }
        Ok(list)
    }

    fn build_message(
        &self,
        subject: &str,
        text: &str,
        html: Option<&str>,
        from: &str,
        to: &[String],
    ) -> Result<Message, String> {
        let from_mailbox: Mailbox = from
            .parse()
            .map_err(|_| format!("发件人地址无效: {}", from))?;
        let mut builder = Message::builder()
            .from(from_mailbox)
            .subject(subject.to_string());
        for rcpt in to {
            let mailbox: Mailbox = rcpt
                .parse()
                .map_err(|_| format!("收件人地址无效: {}", rcpt))?;
            builder = builder.to(mailbox);
        }
        match html {
            Some(h) => builder
                .multipart(MultiPart::alternative_plain_html(
                    text.to_string(),
                    h.to_string(),
                ))
                .map_err(|e| format!("构建邮件失败: {}", e)),
            None => builder
                .body(text.to_string())
                .map_err(|e| format!("构建邮件失败: {}", e)),
        }
    }

    fn send_email(
        &self,
        content: &NotifyContent,
        to_mails: Option<&[String]>,
    ) -> Result<(), String> {
        let (host, port) = split_smtp(&self.cfg_field("email_smtp_host"));
        let port = port.unwrap_or(self.cfg.email_smtp_port);
        if host.is_empty() {
            return Err("缺少 SMTP 主机配置".into());
        }
        let recipients = self.resolve_recipients(to_mails)?;
        // 明连接下拒绝发送凭据（Python 版修复项，这里直接内置）
        if !self.cfg.email_use_ssl && !self.cfg.email_use_tls && !self.cfg.email_user.is_empty() {
            return Err("SMTP 未启用 TLS（email_use_ssl/email_use_tls），拒绝发送凭据".into());
        }
        let from = if self.cfg.email_from.is_empty() {
            if self.cfg.email_user.is_empty() {
                "meituan@localhost".to_string()
            } else {
                self.cfg.email_user.clone()
            }
        } else {
            self.cfg.email_from.clone()
        };
        let subject = format!(
            "{}{}",
            self.cfg.email_subject_prefix,
            if self.cfg.notify_subject.is_empty() {
                content.title.clone()
            } else {
                self.cfg.notify_subject.clone()
            }
        );
        let message = self.build_message(
            &subject,
            &content.text,
            content.html.as_deref(),
            &from,
            &recipients,
        )?;
        let mut builder = if self.cfg.email_use_ssl {
            SmtpTransport::relay(&host)
                .map_err(|e| format!("SMTP relay 失败: {}", e))?
                .tls(lettre::transport::smtp::client::Tls::Wrapper(
                    lettre::transport::smtp::client::TlsParameters::new(host.clone())
                        .map_err(|e| format!("TLS 参数失败: {}", e))?,
                ))
        } else if self.cfg.email_use_tls {
            SmtpTransport::starttls_relay(&host)
                .map_err(|e| format!("SMTP STARTTLS 失败: {}", e))?
                .tls(lettre::transport::smtp::client::Tls::Required(
                    lettre::transport::smtp::client::TlsParameters::new(host.clone())
                        .map_err(|e| format!("TLS 参数失败: {}", e))?,
                ))
        } else {
            SmtpTransport::builder_dangerous(&host)
        };
        builder = builder.port(port);
        if !self.cfg.email_user.is_empty() {
            builder = builder.credentials(Credentials::new(
                self.cfg.email_user.clone(),
                self.cfg.email_password.clone(),
            ));
        }
        let transport = builder.build();
        transport.send(&message).map(|_| ()).map_err(|e| {
            self.secrets
                .redact(Some(&e.to_string()))
                .chars()
                .take(120)
                .collect::<String>()
                .to_string()
        })
    }

    fn send_resend(
        &self,
        content: &NotifyContent,
        to_mails: Option<&[String]>,
    ) -> Result<(), String> {
        let recipients = self.resolve_recipients(to_mails)?;
        let sender = self.cfg_field("resend_from");
        if sender.is_empty() {
            return Err("缺少 resend_from".into());
        }
        let sender = if sender.contains('<') {
            sender
        } else {
            let name = self.cfg_field("resend_from_name");
            if name.is_empty() {
                sender
            } else {
                format!("{} <{}>", name, sender)
            }
        };
        let subject = if self.cfg.notify_subject.is_empty() {
            content.title.clone()
        } else {
            self.cfg.notify_subject.clone()
        };
        let mut payload = json!({
            "from": sender, "to": recipients, "subject": subject,
            "text": content.text,
        });
        if let Some(html) = &content.html {
            payload["html"] = Value::String(html.clone());
        }
        let resp = self
            .http
            .post("https://api.resend.com/emails")
            .header(
                "Authorization",
                format!("Bearer {}", self.cfg_field("resend_api_key")),
            )
            .json(&payload)
            .timeout(Duration::from_secs_f64(self.cfg.notify_timeout))
            .send()
            .map_err(|e| {
                self.secrets
                    .redact(Some(&e.to_string()))
                    .chars()
                    .take(120)
                    .collect::<String>()
                    .to_string()
            })?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        if status >= 400 {
            return Err(format!(
                "HTTP {}: {}",
                status,
                self.secrets
                    .redact(Some(&text))
                    .chars()
                    .take(120)
                    .collect::<String>()
            ));
        }
        // 响应里有 id 才算受理，否则按失败处理
        let parsed: Option<Value> = serde_json::from_str(&text).ok();
        match parsed.as_ref().and_then(|v| v.get("id")) {
            Some(id) if !id.is_null() => Ok(()),
            _ => Err(format!(
                "Resend 未返回消息 id: {}",
                self.secrets
                    .redact(Some(&text))
                    .chars()
                    .take(120)
                    .collect::<String>()
            )),
        }
    }
}

/// `"smtp.qq.com:465"` -> `("smtp.qq.com", Some(465))`。
pub fn split_smtp(value: &str) -> (String, Option<u16>) {
    match value.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() =>
        {
            (host.to_string(), port.parse().ok())
        }
        _ => (value.to_string(), None),
    }
}

// 让 Map 导入不被视为未使用（部分通道构造 JSON 时会用到）
#[allow(dead_code)]
fn _use_map(_m: Map<String, Value>) {}

// ApiTransportError 目前未直接使用，保留导入以对齐 Python 错误分层
#[allow(dead_code)]
fn _use_transport(_e: ApiTransportError) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cookies::CookieBag;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn mask_label_masks_long_digits_but_keeps_existing_stars() {
        assert_eq!(mask_label("17718937689"), "177****89");
        assert_eq!(mask_label("老号"), "老号");
        // 已打过码的 label 原样返回，不再二次打码
        assert_eq!(mask_label("177****7689"), "177****7689");
        assert_eq!(mask_label("老号*1"), "老号*1");
    }

    #[test]
    fn split_smtp_handles_host_and_port() {
        assert_eq!(
            split_smtp("smtp.qq.com:465"),
            ("smtp.qq.com".to_string(), Some(465))
        );
        assert_eq!(split_smtp("smtp.qq.com"), ("smtp.qq.com".to_string(), None));
        // 非数字端口不当成端口
        assert_eq!(
            split_smtp("smtp.qq.com:abc"),
            ("smtp.qq.com:abc".to_string(), None)
        );
        assert_eq!(split_smtp(""), (String::new(), None));
    }

    #[test]
    fn dingtalk_signature_format() {
        let url = dingtalk_signed_url(
            "https://oapi.dingtalk.com/robot/send?access_token=xxx",
            "SECsecret",
        );
        assert!(url.contains("timestamp="));
        assert!(url.contains("&sign="), "已有 query 时用 & 连接");
        assert!(url.starts_with("https://oapi.dingtalk.com/robot/send?access_token=xxx"));
        let plain = dingtalk_signed_url("https://oapi.dingtalk.com/robot/send", "S");
        assert!(plain.contains("?timestamp="), "无 query 时用 ? 连接");
        // 签名是 base64 后 percent-encode，不含 + / =
        let sign = plain.split("sign=").nth(1).unwrap();
        assert!(!sign.contains('+'));
        assert!(!sign.contains('='));
    }

    #[test]
    fn safe_items_redacts_every_dynamic_field() {
        // 关键回归：纯文本脱敏了、HTML 没脱敏 -> 凭据随邮件外泄
        let secrets = SecretsRegistry::new();
        secrets.register(Some("SYNTHETIC_SECRET_LONG"));
        let cfg = Config {
            notify_targets: vec!["resend".into()],
            resend_api_key: "re_synthetic123456".into(),
            resend_from: "noreply@example.invalid".into(),
            notify_to_mails: vec!["me@example.invalid".into()],
            ..Default::default()
        };
        let n = Notifier::new(cfg, Arc::clone(&secrets));
        let raw = vec![json!({
            "coupon": "券A-SYNTHETIC_SECRET_LONG",
            "coupon_type": "PHONE_REWARD",
            "status": "failed",
            "grant_status": "NOT_GRANTED-SYNTHETIC_SECRET_LONG",
            "detail": "上游返回 SYNTHETIC_SECRET_LONG 出错",
        })];
        let safe = n.safe_items(&raw);
        let text = serde_json::to_string(&safe).unwrap();
        assert!(
            !text.contains("SYNTHETIC_SECRET_LONG"),
            "HTML 侧仍含秘密: {}",
            text
        );
        assert!(text.contains("券A-***"), "券名应被脱敏");
        // 不改动调用方数据
        assert!(raw[0]["detail"]
            .as_str()
            .unwrap()
            .contains("SYNTHETIC_SECRET_LONG"));
    }

    #[test]
    fn register_secrets_covers_credentials_and_webhook_query() {
        let cfg = Config {
            feishu_webhook: "https://open.feishu.cn/hook/abc?token=webhook-token-value".into(),
            dingtalk_secret: "SECddingtalk".into(),
            email_password: "auth-code-123456".into(),
            resend_api_key: "re_synthetic123456".into(),
            ..Default::default()
        };
        let secrets = SecretsRegistry::new();
        register_secrets(&cfg, &secrets);
        for leak in [
            "webhook-token-value",
            "SECddingtalk",
            "auth-code-123456",
            "re_synthetic123456",
        ] {
            assert_eq!(
                secrets.redact(Some(&format!("x {} y", leak))),
                "x *** y",
                "{} 未被登记脱敏",
                leak
            );
        }
    }

    #[test]
    fn notify_is_disabled_without_targets() {
        let secrets = SecretsRegistry::new();
        let n = Notifier::new(Config::default(), Arc::clone(&secrets));
        assert!(!n.enabled());
        let r = n.notify("result", "hello", None, false, None, None, None);
        assert!(r.is_empty(), "未配置通道时零副作用");
    }

    #[test]
    fn account_routing_comes_from_auth_entry() {
        let mut a = Auth {
            label: "A".into(),
            xsrf_token: "t-v".into(),
            god_uuid: "u-v".into(),
            device_id: "d-v".into(),
            cookies: CookieBag::new(),
            auth_file: None,
            auth_index: None,
            notify_targets: Some(vec!["email".into()]),
            notify_to: Some(vec!["a@x.com".into()]),
        };
        let (t, m) = account_routing(&a);
        assert_eq!(t.as_deref(), Some(&["email".to_string()][..]));
        assert_eq!(m.as_deref(), Some(&["a@x.com".to_string()][..]));
        a.notify_targets = None;
        a.notify_to = None;
        assert_eq!(account_routing(&a), (None, None));
    }
}
