//! 领域模型：券与领取事件。API 边界即转换，业务层一律属性访问。
//!
//! 对应 Python 版 `models.py`。`raw` 保留服务端原始字段，未知字段透传不丢。

use serde_json::Value;

fn as_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// 一张超级券。
#[derive(Debug, Clone)]
pub struct Coupon {
    pub coupon_id: String,
    pub coupon_name: String,
    pub coupon_type: String,
    pub left_stock: Option<i64>,
    pub direct_link: Option<String>,
    /// 服务端原始字段，透传未知信息。
    pub raw: Value,
}

impl Coupon {
    /// 从 API 响应条目构造（API 边界转换）。
    pub fn from_api(d: &Value) -> Self {
        Self {
            coupon_id: as_string(d.get("couponId")),
            coupon_name: as_string(d.get("couponName")),
            coupon_type: as_string(d.get("couponType")),
            left_stock: d.get("leftStock").and_then(Value::as_i64),
            direct_link: d
                .get("directLink")
                .and_then(Value::as_str)
                .map(String::from),
            raw: d.clone(),
        }
    }

    /// `leftStock == 0` 才算抢光；未知按未抢光（与历史行为一致）。
    pub fn sold_out(&self) -> bool {
        self.left_stock == Some(0)
    }

    pub fn is_phone_reward(&self) -> bool {
        self.coupon_type == "PHONE_REWARD"
    }
}

/// 一次 grant 尝试的事件记录，用于收尾统计与 JSONL。
#[derive(Debug, Clone)]
pub struct GrantEvent {
    pub send_ts: String,
    pub label: String,
    pub coupon_name: String,
    pub status: String,
    pub elapsed: f64,
}

impl GrantEvent {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "send_ts": self.send_ts,
            "label": self.label,
            "coupon_name": self.coupon_name,
            "status": self.status,
            "elapsed": self.elapsed,
        })
    }
}
