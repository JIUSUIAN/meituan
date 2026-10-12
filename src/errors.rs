//! 错误模型：传输/解析/业务三层分离 + 集中式业务码映射。
//!
//! 对应 Python 版 `errors.py`。业务层不许解析错误字符串，只按结构化 `code` 分类。

/// API 业务错误：HTTP 层成功，但响应 `code` 非 200。
#[derive(Debug, Clone)]
pub struct ApiError {
    pub code: Option<i64>,
    pub message: String,
    pub http_status: Option<u16>,
}

impl ApiError {
    pub fn new(code: Option<i64>, message: impl Into<String>, http_status: Option<u16>) -> Self {
        Self {
            code,
            message: message.into(),
            http_status,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.code {
            Some(c) => write!(f, "code={}: {}", c, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for ApiError {}

/// 传输/HTTP 层失败：连接异常、超时、非 2xx 状态、TLS 失败等。
#[derive(Debug, Clone)]
pub struct ApiTransportError {
    pub message: String,
    pub http_status: Option<u16>,
}

impl ApiTransportError {
    pub fn new(message: impl Into<String>, http_status: Option<u16>) -> Self {
        Self {
            message: message.into(),
            http_status,
        }
    }
}

impl std::fmt::Display for ApiTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiTransportError {}

/// HTTP 成功但响应体不是合法 JSON。是传输层的子类（Python 版同构）。
#[derive(Debug, Clone)]
pub struct ApiParseError {
    pub message: String,
    pub http_status: Option<u16>,
}

impl ApiParseError {
    pub fn new(message: impl Into<String>, http_status: Option<u16>) -> Self {
        Self {
            message: message.into(),
            http_status,
        }
    }
}

impl std::fmt::Display for ApiParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiParseError {}

/// 集中式业务码 -> 领域状态映射（唯一真源）。
///
/// 返回 `None` 表示「不是已知业务码」，调用方记 `failed` 并保留原码。
pub fn grant_code_status(code: i64) -> Option<&'static str> {
    match code {
        803 => Some("already_claimed"),
        40007 => Some("rate_limited"),
        873 => Some("auth_expired"),
        60001 => Some("out_of_stock"),
        _ => None,
    }
}

/// 只读接口上明确代表登录态失效的业务码。
pub const AUTH_EXPIRED_CODES: [i64; 1] = [873];

/// 把领取路径的 [`ApiError`] 映射为领域状态；未知 code 一律 `failed`，不误分类。
pub fn classify_grant_error(err: &ApiError) -> String {
    match err.code {
        Some(c) => grant_code_status(c).unwrap_or("failed").to_string(),
        None => "failed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_client::ApiFailure;

    #[test]
    fn business_code_mapping_is_single_source() {
        assert_eq!(grant_code_status(803), Some("already_claimed"));
        assert_eq!(grant_code_status(40007), Some("rate_limited"));
        assert_eq!(grant_code_status(873), Some("auth_expired"));
        assert_eq!(grant_code_status(60001), Some("out_of_stock"));
        assert_eq!(grant_code_status(99999), None);
    }

    #[test]
    fn unknown_code_is_failed_without_guessing() {
        let e = ApiError::new(Some(99999), "活动未开始", None);
        assert_eq!(classify_grant_error(&e), "failed");
        assert!(e.to_string().contains("99999"));
    }

    #[test]
    fn auth_expired_detection() {
        let ok = ApiError::new(Some(200), "", None);
        let bad = ApiError::new(Some(873), "重新登录", None);
        assert!(!ApiFailure::Business(ok).is_auth_expired());
        assert!(ApiFailure::Business(bad).is_auth_expired());
    }
}
