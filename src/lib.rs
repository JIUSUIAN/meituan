//! meituan：网易大神 partner-perks 美团外卖券领券自动化包（Rust 实现）。
//!
//! 模块地图与 Python 版一致，便于逐模块对照迁移：
//!
//! ```text
//! errors.rs        ApiError / ApiTransportError / ApiParseError + 业务码集中映射
//! config.rs        Config + 四层配置合并（默认 < JSON < MEITUAN_* 环境变量 < CLI）
//! security.rs      凭据加载/归一化/按条目回写/脱敏登记/跨进程锁
//! cookies.rs       CookieStore：Cookie 头唯一出口 + 服务端更新跟踪名单
//! models.rs        领域模型 Coupon / GrantEvent（API 边界转换，raw 透传）
//! api_client.rs    签名、POST、错误分层、JSESSIONID 轮换跟随
//! pacing.rs        RateLimiter + InflightGate（容量可运行时调整）
//! notify.rs        Notifier：7 通道 + 账号级路由
//! report_html.rs   邮件报告页（账号详情双券卡 + 汇总页全部券列表）
//! flows.rs         RunLogger、ping / verify_session / single_run / LoopRunner
//! ```
//!
//! 与 Python 版的差异（有意为之）：
//! - 不再有进程级可变全局（如 `GLOBAL_SECRETS`）。脱敏表是
//!   [`security::SecretsRegistry`] 实例，由调用方以 `Arc` 显式传递。
//! - 凭据与配置的查找基准默认为**当前工作目录**，可用 `MEITUAN_BASE_DIR` 覆盖
//!   （Python 版按包目录的上一级解析，二进制分发时该路径不再稳定）。

pub mod api_client;
pub mod config;
pub mod cookies;
pub mod errors;
pub mod flows;
pub mod models;
pub mod notify;
pub mod pacing;
pub mod report_html;
pub mod security;

pub use errors::{ApiError, ApiParseError, ApiTransportError};
pub use flows::{beijing_ts, loop_run, ping, single_run, verify_session, LoopRunner};

/// 版本真源：来自 `CARGO_PKG_VERSION`（即 `Cargo.toml` 的 `version`）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
