//! API Client：签名、请求发送与错误分层转换。
//!
//! 对应 Python 版 `api_client.py`。业务层不接触 `reqwest` 细节，
//! 也不解析错误字符串。
//!
//! 注意：本机默认不带 cookie jar（`reqwest` 未启用 `cookies` feature），
//! Cookie 头完全由 [`crate::cookies::CookieStore`] 单点合成，
//! 与页面 axios 的行为对齐。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderValue, COOKIE, ORIGIN, REFERER, USER_AGENT};
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};

use crate::config::Config;
use crate::cookies::{CookieBag, CookieStore};
use crate::errors::{ApiError, ApiParseError, ApiTransportError, AUTH_EXPIRED_CODES};
use crate::models::Coupon;
use crate::security::{Auth, SecretsRegistry};

const CLIENT_TYPE: &str = "60";

/// 会话 Cookie 轮换回调：只传 Cookie 名，不传值。
pub type RotateCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// 三类错误的统一出口（Python 版用三个异常类，这里聚合成一个枚举便于 `?`）。
#[derive(Debug)]
pub enum ApiFailure {
    Business(ApiError),
    Transport(ApiTransportError),
    Parse(ApiParseError),
}

impl ApiFailure {
    /// 是否明确代表登录态失效（业务码 873）。
    pub fn is_auth_expired(&self) -> bool {
        matches!(self, ApiFailure::Business(e)
            if e.code.is_some_and(|c| AUTH_EXPIRED_CODES.contains(&c)))
    }

    /// 已脱敏、限长 200 的消息。
    pub fn message(&self, secrets: &SecretsRegistry) -> String {
        let raw = match self {
            ApiFailure::Business(e) => format!("code={:?}: {}", e.code, e.message),
            ApiFailure::Transport(e) => e.message.clone(),
            ApiFailure::Parse(e) => e.message.clone(),
        };
        secrets.redact(Some(&raw)).chars().take(200).collect()
    }

    pub fn detail(&self, secrets: &SecretsRegistry) -> String {
        match self {
            ApiFailure::Business(e) => format!(
                "code={}: {}",
                e.code.map(|c| c.to_string()).unwrap_or_default(),
                secrets
                    .redact(Some(&e.message))
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
            ApiFailure::Transport(e) => e.message.to_string(),
            ApiFailure::Parse(e) => e.message.to_string(),
        }
    }
}

impl std::fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiFailure::Business(e) => write!(f, "{}", e),
            ApiFailure::Transport(e) => write!(f, "{}", e),
            ApiFailure::Parse(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ApiFailure {}

impl From<ApiError> for ApiFailure {
    fn from(e: ApiError) -> Self {
        ApiFailure::Business(e)
    }
}
impl From<ApiTransportError> for ApiFailure {
    fn from(e: ApiTransportError) -> Self {
        ApiFailure::Transport(e)
    }
}
impl From<ApiParseError> for ApiFailure {
    fn from(e: ApiParseError) -> Self {
        ApiFailure::Parse(e)
    }
}

/// 单账号 API 客户端。
pub struct ApiClient {
    label: String,
    xsrf_token: String,
    god_uuid: String,
    device_id: String,
    auth_file: Option<PathBuf>,
    auth_index: Option<usize>,
    cookies: CookieStore,
    secrets: Arc<SecretsRegistry>,
    client: Client,
    config: Config,
    on_rotate: Option<RotateCallback>,
}

impl ApiClient {
    /// 构造客户端。参数较多是因为要把账号身份、Cookie 种子、配置与回调
    /// 一次性装配好——这些字段都来自同一个归一化账号，拆成 builder 反而绕。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        xsrf_token: &str,
        god_uuid: &str,
        device_id: &str,
        cookie_seed: &CookieBag,
        config: &Config,
        secrets: Arc<SecretsRegistry>,
        auth_file: Option<PathBuf>,
        auth_index: Option<usize>,
        on_rotate: Option<RotateCallback>,
    ) -> Self {
        Self {
            label: label.to_string(),
            xsrf_token: xsrf_token.to_string(),
            god_uuid: god_uuid.to_string(),
            device_id: device_id.to_string(),
            auth_file,
            auth_index,
            cookies: CookieStore::new(
                cookie_seed,
                &config.session_cookie_names,
                Arc::clone(&secrets),
            ),
            secrets,
            client: Client::builder()
                .connect_timeout(Duration::from_secs_f64(config.api_timeout.clamp(3.0, 10.0)))
                .build()
                .unwrap_or_default(),
            config: config.clone(),
            on_rotate,
        }
    }

    /// 从归一化账号构造客户端（业务层入口）。
    pub fn from_auth(
        auth: &Auth,
        config: &Config,
        secrets: Arc<SecretsRegistry>,
        on_rotate: Option<RotateCallback>,
    ) -> Result<Self, String> {
        Ok(Self::new(
            &auth.label,
            &auth.xsrf_token,
            &auth.god_uuid,
            &auth.device_id,
            &auth.cookie_seed(),
            config,
            secrets,
            auth.auth_file.clone(),
            auth.auth_index,
            on_rotate,
        ))
    }

    pub fn secrets(&self) -> &Arc<SecretsRegistry> {
        &self.secrets
    }

    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn cookies(&self) -> &CookieStore {
        &self.cookies
    }
    pub fn auth_file(&self) -> Option<&PathBuf> {
        self.auth_file.as_ref()
    }
    pub fn auth_index(&self) -> Option<usize> {
        self.auth_index
    }

    // -- 底层 POST --------------------------------------------------------

    /// 手动序列化 JSON（保证签名用的字节与发送一致）。
    fn post(
        &self,
        path: &str,
        body: &Value,
        timeout: Option<Duration>,
    ) -> Result<Value, ApiFailure> {
        // 对齐 JS 的 JSON.stringify：无空格、键按插入顺序、不转义 Unicode
        let raw = serde_json::to_string(body)
            .map_err(|e| ApiParseError::new(format!("请求体序列化失败: {}", e), None))?;
        let checksum = self.sign(&raw);
        let cookie_header = self.cookies.header();

        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.config.user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&cookie_header).unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        headers.insert(
            "GL-DeviceId",
            HeaderValue::from_str(&self.device_id).unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        headers.insert(
            "GL-X-XSRF-TOKEN",
            HeaderValue::from_str(&self.xsrf_token)
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        headers.insert(
            "GL-Uid",
            HeaderValue::from_str(&self.god_uuid).unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        headers.insert("GL-ClientType", HeaderValue::from_static(CLIENT_TYPE));
        headers.insert(
            "GL-CheckSum",
            HeaderValue::from_str(&checksum).unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        headers.insert(ORIGIN, HeaderValue::from_static("https://vip.ds.163.com"));
        headers.insert(REFERER, HeaderValue::from_static(
            "https://vip.ds.163.com/partner-perks?wvFullScreen=true&wvStatusBarStyle=white&utm_source=hy.myicon"));

        let url = format!("{}{}", self.config.base_url, path);
        let timeout = timeout.unwrap_or_else(|| Duration::from_secs_f64(self.config.api_timeout));
        let resp = self
            .client
            .post(&url)
            .body(raw)
            .headers(headers)
            .timeout(timeout)
            .send()
            .map_err(|e| {
                ApiTransportError::new(
                    format!(
                        "网络请求失败: {}",
                        self.secrets.redact(Some(&e.to_string()))
                    ),
                    None,
                )
            })?;

        // 轮换跟踪先于错误处理：Set-Cookie 可能随任意状态码（含 4xx/5xx）下发
        self.follow_cookie_rotation(&resp);

        let status = resp.status().as_u16();
        if status >= 400 {
            let text = resp.text().unwrap_or_default();
            return Err(ApiTransportError::new(
                format!("HTTP {}: {}", status, self.secrets.redact(Some(&text))),
                Some(status),
            )
            .into());
        }
        let text = resp.text().unwrap_or_default();
        let data: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => {
                return Err(ApiFailure::Parse(ApiParseError::new(
                    format!("响应不是合法 JSON（HTTP {}）", status),
                    Some(status),
                )))
            }
        };
        if !data.is_object() {
            return Err(ApiFailure::Parse(ApiParseError::new(
                "响应结构异常（非 JSON 对象）",
                Some(status),
            )));
        }
        let code = data.get("code").and_then(Value::as_i64);
        if code != Some(200) {
            let msg = data.get("errmsg").and_then(Value::as_str).unwrap_or("");
            return Err(ApiFailure::Business(ApiError::new(
                code,
                self.secrets.redact(Some(msg)),
                Some(status),
            )));
        }
        Ok(data.get("result").cloned().unwrap_or(Value::Null))
    }

    /// `GL-CheckSum = SHA1(body + GL-XSRF-TOKEN)`。
    fn sign(&self, raw: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(raw.as_bytes());
        hasher.update(self.xsrf_token.as_bytes());
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// 响应 `Set-Cookie` -> CookieStore 按跟踪名单跟随 -> 可选原子回写 ->
    /// `on_rotate` 回调（只传 Cookie 名，不传值）。纯 best-effort。
    fn follow_cookie_rotation(&self, resp: &Response) {
        let raw_headers: Vec<String> = resp
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(String::from))
            .collect();
        if raw_headers.is_empty() {
            return;
        }
        let changed = self.cookies.apply_set_cookie_headers(&raw_headers);
        if changed.is_empty() {
            return;
        }
        if self.config.persist_rotated_cookies {
            if let Some(auth_file) = &self.auth_file {
                let bag = self.cookies.to_bag();
                let index = self.auth_index;
                let file = auth_file.clone();
                // 回写失败不影响本次请求；下次轮换再试
                let _ = crate::security::update_auth_cookies(&bag, &file, index);
            }
        }
        if let Some(cb) = &self.on_rotate {
            for name in changed {
                cb(&name);
            }
        }
    }

    // -- 业务端点 ---------------------------------------------------------

    pub fn coupon_info(&self, timeout: Option<Duration>) -> Result<Value, ApiFailure> {
        self.post(&self.config.info_path, &json!({}), timeout)
    }

    /// 拉取目标品牌及券列表，返回 `(brand, Vec<Coupon>)`。
    pub fn find_brand_coupons(
        &self,
        timeout: Option<Duration>,
    ) -> Result<(Option<Value>, Vec<Coupon>), ApiFailure> {
        let result = self.coupon_info(timeout)?;
        let brands = result
            .get("brands")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let brand = brands.into_iter().find(|b| {
            b.get("brandName")
                .and_then(Value::as_str)
                .map(|n| n.contains(&self.config.brand_keyword))
                .unwrap_or(false)
        });
        match brand {
            None => Ok((None, Vec::new())),
            Some(brand) => {
                let coupons = brand
                    .get("superCoupons")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter()
                            .filter(|c| c.is_object())
                            .map(Coupon::from_api)
                            .collect()
                    })
                    .unwrap_or_default();
                Ok((Some(brand), coupons))
            }
        }
    }

    pub fn grant(&self, brand_id: &str, coupon: &Coupon) -> Result<Value, ApiFailure> {
        let mut body = Map::new();
        body.insert("brandId".into(), json!(brand_id));
        body.insert("superCouponId".into(), json!(coupon.coupon_id));
        if coupon.is_phone_reward() {
            body.insert("phoneBizType".into(), json!("VIP"));
        }
        self.post(&self.config.grant_path, &Value::Object(body), None)
    }

    /// 查询券状态（只读）。失败抛异常——调用方可区分「成功且为空」与「失败」。
    pub fn grant_status(
        &self,
        coupon_ids: &[String],
        timeout: Option<Duration>,
    ) -> Result<Map<String, Value>, ApiFailure> {
        let ids: Vec<&String> = coupon_ids.iter().filter(|c| !c.is_empty()).collect();
        if ids.is_empty() {
            return Ok(Map::new());
        }
        let result = self.post(
            &self.config.grant_status_path,
            &json!({"superCouponIds": ids}),
            timeout,
        )?;
        let mut out = Map::new();
        if let Some(items) = result.get("grantItems").and_then(Value::as_array) {
            for g in items {
                let id = g.get("couponId").or_else(|| g.get("superCouponId"));
                if let Some(id) = id.and_then(Value::as_str) {
                    let status = g.get("status").cloned().unwrap_or(Value::Null);
                    out.insert(id.to_string(), status);
                }
            }
        }
        Ok(out)
    }
}
