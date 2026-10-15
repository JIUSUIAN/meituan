//! 业务流程：只读健康检查、会话验证、单次执行、循环抢券。
//!
//! 对应 Python 版 `flows.py`。差异：
//! - 用 `std::thread` + `Arc<Mutex<State>>` 替代 Python 的 `ThreadPoolExecutor`
//!   （线程池规模由账号数与目标券数推导）；
//! - 日志统一走 [`RunLogger`]，输出前脱敏；
//! - 传输/解析失败记 `error` 并进入退出码判定（不含在业务状态里）。

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::api_client::{ApiClient, ApiFailure};
use crate::config::Config;
use crate::errors::{classify_grant_error, AUTH_EXPIRED_CODES};
use crate::models::{Coupon, GrantEvent};
use crate::notify::{account_routing, Notifier};
use crate::pacing::GrantPacing;
use crate::security::{Auth, SecretsRegistry};

/// 北京时间戳（精确到百分之一秒）：`2026-10-12 14:02:39.45`。
pub fn beijing_ts() -> String {
    let now = chrono::Utc::now().with_timezone(&chrono_tz::Asia::Shanghai);
    format!(
        "{}.{:02}",
        now.format("%Y-%m-%d %H:%M:%S"),
        now.timestamp_subsec_millis() / 10
    )
}

/// 当前单调时钟秒数（用于 deadline，不受系统时钟调整影响）。
fn now_mono() -> f64 {
    START.with(|s| s.elapsed().as_secs_f64())
}

thread_local! {
    static START: Instant = Instant::now();
}

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------

/// 控制台 + 可选文件的日志器；所有消息输出前统一脱敏。
pub struct RunLogger {
    file: Option<std::fs::File>,
    secrets: Arc<SecretsRegistry>,
}

impl RunLogger {
    pub fn new(path: Option<&Path>, secrets: Arc<SecretsRegistry>) -> Self {
        let file = path.and_then(|p| {
            std::fs::create_dir_all(p.parent().unwrap_or_else(|| Path::new("."))).ok()?;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
        });
        Self { file, secrets }
    }

    pub fn log(&self, msg: &str) {
        let line = format!("{} {}", beijing_ts(), self.secrets.redact(Some(msg)));
        // 日志走 stderr：stdout 只留给最终 JSON 报告
        eprintln!("{}", line);
        if let Some(f) = &self.file {
            let mut f = f;
            let _ = writeln!(f, "{}", line);
        }
    }
}

fn write_keepalive(log_path: Option<&str>, lines: &[String]) {
    let path = match log_path {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        for l in lines {
            let _ = writeln!(f, "{}", l);
        }
    }
}

/// 只读接口失败时的健康状态：明确鉴权失败记 `expired`，其余记 `unknown`。
fn failure_health(err: &ApiFailure) -> String {
    if err.is_auth_expired() {
        "expired".into()
    } else {
        "unknown".into()
    }
}

fn notify_health(
    notifier: Option<&Notifier>,
    kind: &str,
    report: &[(String, String)],
    good: &[&str],
) {
    let n = match notifier {
        Some(n) => n,
        None => return,
    };
    if report.is_empty() {
        return;
    }
    let bad: Vec<&(String, String)> = report
        .iter()
        .filter(|(_, v)| !good.contains(&v.as_str()))
        .collect();
    if bad.is_empty() {
        return;
    }
    let lines: Vec<String> = bad
        .iter()
        .map(|(k, v)| format!("{}: {}", crate::notify::mask_label(k), v))
        .collect();
    n.notify(
        "health",
        &format!("{}：存在异常账号\n{}", kind, lines.join("\n")),
        None,
        false,
        None,
        None,
        None,
    );
}

// ---------------------------------------------------------------------------
// 只读健康检查与会话验证
// ---------------------------------------------------------------------------

/// 只读健康检查：仅调用 info + grant-status 两个只读接口，绝不领取。
pub fn ping(
    auths: &[Auth],
    config: &Config,
    log_path: Option<&str>,
    secrets: Arc<SecretsRegistry>,
    notifier: Option<&Notifier>,
) -> Vec<(String, String)> {
    let probe = match config.probe_coupon() {
        Some(p) => p,
        None => {
            eprintln!("配置里没有可用作探针的券（probe_coupon 为空）");
            return Vec::new();
        }
    };
    let probe_id = probe
        .get("couponId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut report = Vec::new();
    let mut log_lines = Vec::new();
    for auth in auths {
        let label = &auth.label;
        let t0 = Instant::now();
        let status = match ApiClient::from_auth(auth, config, Arc::clone(&secrets), None) {
            Ok(client) => {
                match client.coupon_info(Some(Duration::from_secs_f64(config.ping_timeout))) {
                    Ok(_) => match client.grant_status(
                        std::slice::from_ref(&probe_id),
                        Some(Duration::from_secs_f64(config.ping_timeout)),
                    ) {
                        Ok(_) => "reachable".to_string(),
                        Err(e) => failure_health(&e),
                    },
                    Err(e) => failure_health(&e),
                }
            }
            Err(e) => format!("error: {}", e),
        };
        log_lines.push(format!(
            "{} [{}] {} ({:.2}s)",
            beijing_ts(),
            label,
            status,
            t0.elapsed().as_secs_f64()
        ));
        report.push((label.clone(), status));
    }
    let redacted: Vec<String> = log_lines.iter().map(|l| secrets.redact(Some(l))).collect();
    write_keepalive(log_path, &redacted);
    notify_health(notifier, "只读健康检查", &report, &["reachable"]);
    report
}

/// 会话验证（**只读，无副作用**）：调 `userInfo` 接口验证登录态。
///
/// 每账号返回：`authenticated` / `expired` / `unknown` / `error: ...`。
/// 873 -> `expired`；200 -> `authenticated`；限流等其他业务码 -> `unknown`；
/// 网络/解析失败 -> `error`。`userInfo` 同样返回 873 识别过期（2026-10-12 实测），
/// 且不触碰任何券——旧的 grant 探针在探针券当天未领时会实际领掉一张，已不再使用。
pub fn verify_session(
    auths: &[Auth],
    config: &Config,
    log_path: Option<&str>,
    secrets: Arc<SecretsRegistry>,
    notifier: Option<&Notifier>,
) -> Vec<(String, String)> {
    let mut report = Vec::new();
    let mut log_lines = Vec::new();
    for auth in auths {
        let label = &auth.label;
        let t0 = Instant::now();
        let status = match ApiClient::from_auth(auth, config, Arc::clone(&secrets), None) {
            Ok(client) => match client.userinfo(None) {
                Ok(_) => "authenticated".to_string(),
                Err(ApiFailure::Business(e)) => {
                    if e.code.is_some_and(|c| AUTH_EXPIRED_CODES.contains(&c)) {
                        "expired".into()
                    } else {
                        // 40007 被限流挡在门外，无法判断登录态；其他业务码同样不确定
                        "unknown".into()
                    }
                }
                // 传输层/解析失败与其他意外一律归为 error，消息已脱敏限长
                Err(e) => format!(
                    "error: {}",
                    e.message(&secrets).chars().take(120).collect::<String>()
                ),
            },
            Err(e) => format!("error: {}", e.chars().take(120).collect::<String>()),
        };
        log_lines.push(format!(
            "{} [{}] {} ({:.2}s)",
            beijing_ts(),
            label,
            status,
            t0.elapsed().as_secs_f64()
        ));
        report.push((label.clone(), status));
    }
    let redacted: Vec<String> = log_lines.iter().map(|l| secrets.redact(Some(l))).collect();
    write_keepalive(log_path, &redacted);
    notify_health(notifier, "会话验证", &report, &["authenticated"]);
    report
}

// ---------------------------------------------------------------------------
// 领取尝试
// ---------------------------------------------------------------------------

/// 尝试领取一张券，返回 `(status, detail, send_ts)`。
///
/// `send_ts` 是**实际发出 POST 前**的时刻（限速与闸门都等到之后才取），
/// 未发请求时为 `None`。未知 code 保留原码记 `failed`，不误分类；
/// 传输/解析失败记 `error`（会进退出码判定）。
pub fn try_grant(
    client: &ApiClient,
    brand_id: &str,
    coupon: &Coupon,
    pacing: Option<&GrantPacing>,
    config: &Config,
) -> (String, String, Option<String>) {
    if coupon.sold_out() {
        return ("out_of_stock".into(), "已抢光".into(), None);
    }
    if config.skip_types.iter().any(|t| t == &coupon.coupon_type) {
        if coupon.coupon_type == "PLACEHOLDER" {
            return ("skipped".into(), "占位券（敬请期待）".into(), None);
        }
        return (
            "direct_link".into(),
            format!(
                "需跳转领取：{}",
                coupon.direct_link.clone().unwrap_or_default()
            ),
            None,
        );
    }

    let _guard = pacing.map(|p| p.slot());
    let send_ts = Some(beijing_ts());
    match client.grant(brand_id, coupon) {
        Ok(result) => {
            let prize = result.get("winPrizeInfo").cloned().unwrap_or(result);
            let detail = client.secrets().redact(Some(&prize.to_string()));
            (
                "granted".into(),
                detail.chars().take(200).collect(),
                send_ts,
            )
        }
        Err(ApiFailure::Business(e)) => {
            let detail = client.secrets().redact(Some(&e.message));
            (
                classify_grant_error(&e),
                format!(
                    "code={}: {}",
                    e.code.map(|c| c.to_string()).unwrap_or_default(),
                    detail.chars().take(200).collect::<String>()
                ),
                send_ts,
            )
        }
        Err(ApiFailure::Transport(e)) => (
            "error".into(),
            format!(
                "传输错误: {}",
                client
                    .secrets()
                    .redact(Some(&e.message))
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
            send_ts,
        ),
        Err(ApiFailure::Parse(e)) => (
            "error".into(),
            format!(
                "响应解析失败: {}",
                client
                    .secrets()
                    .redact(Some(&e.message))
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
            send_ts,
        ),
    }
}

// ---------------------------------------------------------------------------
// 单次执行
// ---------------------------------------------------------------------------

/// 单次执行：每个账号尝试一次，返回 `(报告, 是否有错误)`。
pub fn single_run(
    auths: &[Auth],
    config: &Config,
    run_log: Option<&Path>,
    secrets: Arc<SecretsRegistry>,
    notifier: Option<&Notifier>,
) -> (Vec<(String, Vec<Value>)>, bool) {
    let logger = Arc::new(RunLogger::new(run_log, Arc::clone(&secrets)));
    let mut report: Vec<(String, Vec<Value>)> = Vec::new();
    let mut any_error = false;

    for auth in auths {
        let label = &auth.label;
        let mut outcomes: Vec<Value> = Vec::new();
        logger.log(&format!("[{}] 单次执行开始", label));
        let logger_cb = Arc::clone(&logger);
        let label_cb = label.clone();
        let on_rotate = move |name: &str| {
            logger_cb.log(&format!(
                "[{}] 服务端轮换会话 Cookie: {}（本地已跟随）",
                label_cb, name
            ));
        };
        match ApiClient::from_auth(
            auth,
            config,
            Arc::clone(&secrets),
            Some(Arc::new(on_rotate)),
        ) {
            Ok(client) => {
                let t0 = Instant::now();
                match client.find_brand_coupons(None) {
                    Ok((brand, coupons)) => {
                        logger.log(&format!(
                            "[{}] 拉取列表成功，耗时 {:.2}s，品牌: {:?}，券数: {}",
                            label,
                            t0.elapsed().as_secs_f64(),
                            brand
                                .as_ref()
                                .and_then(|b| b.get("brandName"))
                                .and_then(Value::as_str),
                            coupons.len()
                        ));
                        match brand {
                            None => outcomes.push(json!({"coupon": null,
                                "status": "no_brand",
                                "detail": format!("列表中未找到{}品牌", config.brand_keyword)})),
                            Some(_) if coupons.is_empty() => outcomes.push(json!(
                                {"coupon": null, "status": "no_coupon",
                                 "detail": "品牌下暂无券"})),
                            Some(b) => {
                                let ids: Vec<String> =
                                    coupons.iter().map(|c| c.coupon_id.clone()).collect();
                                let statuses = match client.grant_status(&ids, None) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        logger.log(&format!(
                                            "[{}] 状态校验失败（将无法跳过已领取券）: {}",
                                            label,
                                            e.message(&secrets)
                                        ));
                                        Default::default()
                                    }
                                };
                                let brand_id = b
                                    .get("brandId")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                for c in &coupons {
                                    let name = c.coupon_name.clone();
                                    if config.single_run_snipe_only
                                        && !name.contains(&config.snipe_keyword)
                                    {
                                        logger.log(&format!(
                                            "[{}] {} -> 跳过（非 {} 目标券）",
                                            label, name, config.snipe_keyword
                                        ));
                                        continue;
                                    }
                                    if statuses.get(&c.coupon_id).and_then(Value::as_str)
                                        == Some("GRANTED")
                                    {
                                        outcomes.push(json!({
                                            "coupon": name, "status": "already_claimed",
                                            "detail": "已领取", "grant_status": "GRANTED"}));
                                        logger.log(&format!(
                                            "[{}] {} -> already_claimed（已领取，跳过）",
                                            label, name
                                        ));
                                        continue;
                                    }
                                    let t1 = Instant::now();
                                    let (status, detail, _) =
                                        try_grant(&client, &brand_id, c, None, config);
                                    logger.log(&format!(
                                        "[{}] {} -> {} ({:.2}s): {}",
                                        label,
                                        name,
                                        status,
                                        t1.elapsed().as_secs_f64(),
                                        detail.chars().take(200).collect::<String>()
                                    ));
                                    let mut item = json!({"coupon": name,
                                                          "status": status,
                                                          "detail": detail});
                                    if let Some(gs) = statuses.get(&c.coupon_id) {
                                        item["grant_status"] = gs.clone();
                                    }
                                    outcomes.push(item);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        logger.log(&format!("[{}] 执行异常: {}", label, e.message(&secrets)));
                        outcomes.push(json!({"coupon": null, "status": "error",
                            "detail": e.message(&secrets).chars().take(200)
                                .collect::<String>()}));
                        any_error = true;
                    }
                }
            }
            Err(e) => {
                logger.log(&format!("[{}] 执行异常: {}", label, e));
                outcomes.push(json!({"coupon": null, "status": "error",
                    "detail": e.chars().take(200).collect::<String>()}));
                any_error = true;
            }
        }
        logger.log(&format!("[{}] 单次执行结束", label));
        // 传输/解析失败（error）意味着这一轮没有真正抢成，退出码必须反映
        if outcomes
            .iter()
            .any(|o| o.get("status").and_then(Value::as_str) == Some("error"))
        {
            any_error = true;
        }
        report.push((label.clone(), outcomes));
    }

    if let Some(n) = notifier {
        n.notify_report("result", &report, &[]);
        for (auth, (label, items)) in auths.iter().zip(report.iter()) {
            let (targets, to_mails) = account_routing(auth);
            n.notify_account(
                label,
                items,
                &[],
                &[],
                to_mails.as_deref(),
                targets.as_deref(),
            );
        }
    }
    (report, any_error)
}

// ---------------------------------------------------------------------------
// 等待与自适应提前量
// ---------------------------------------------------------------------------

/// 计算开火下限对应的最大允许 lead：fire_at - lead >= fire_floor。
///
/// 例如 fire_at=23:59:59.9、fire_floor=23:59:59.7 时返回 0.2。
/// fire_at 不晚于 fire_floor 时返回 INFINITY（下限不生效）。
fn lead_cap_for_floor(fire_at: &str, fire_floor: &str) -> f64 {
    fn secs(s: &str) -> Option<f64> {
        let p: Vec<&str> = s.split(':').collect();
        if p.len() < 3 {
            return None;
        }
        Some(p[0].parse::<f64>().ok()? * 3600.0
            + p[1].parse::<f64>().ok()? * 60.0
            + p[2].parse::<f64>().ok()?)
    }
    match (secs(fire_at), secs(fire_floor)) {
        (Some(a), Some(b)) if a > b => a - b,
        _ => f64::INFINITY,
    }
}

/// 等到目标时刻（北京时间，格式 `HH:MM[:SS[.毫秒]]`）再返回。
///
/// `lead > 0` 表示提前 `lead` 秒开火。跨零点保护：若目标已过 30 分钟内
/// 则立即开火，而不是再等 ~24 小时。
pub fn wait_until(target_str: &str, lead: f64) {
    let tz = chrono_tz::Asia::Shanghai;
    let now = chrono::Utc::now().with_timezone(&tz);
    let parts: Vec<&str> = target_str.split(':').collect();
    if parts.len() < 2 {
        eprintln!("开火时刻格式应为 HH:MM[:SS[.毫秒]]: {}", target_str);
        return;
    }
    let (h, m) = match (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
        (Ok(h), Ok(m)) => (h, m),
        _ => {
            eprintln!("开火时刻格式应为 HH:MM[:SS[.毫秒]]: {}", target_str);
            return;
        }
    };
    let sec = if parts.len() > 2 {
        parts[2].parse::<f64>().unwrap_or(0.0)
    } else {
        0.0
    };
    // 越界值直接拒绝：钳位会把 25:99 变成 23:59 于是一直等到第二天
    if h > 23 || m > 59 || sec < 0.0 || sec >= 60.0 {
        eprintln!(
            "开火时刻超出合法范围: {}（应 0-23 时 / 0-59 分 / 0-59.999 秒）",
            target_str
        );
        return;
    }
    let sec_floor = sec.floor() as u32;
    let micros = ((sec - sec.floor()) * 1e6).round() as u32;
    let time = chrono::NaiveTime::from_hms_micro_opt(h, m, sec_floor, micros);
    let target = match time {
        Some(t) => now.date_naive().and_time(t).and_local_timezone(tz).unwrap(),
        None => return,
    };
    // 必须用微秒精度：timestamp() 只到整秒，会丢掉亚秒部分，导致开火
    // 时刻最多偏晚 ~1s（实测偏晚 0.25~0.75s）；午夜场景下这可能是
    // granted 与 60001 的区别。Python 版用 time.time() 无此问题。
    let target_ts = target.timestamp_micros() as f64 / 1_000_000.0 - lead.max(0.0);
    let now_ts = chrono::Utc::now().timestamp_micros() as f64 / 1_000_000.0;
    let delta = target_ts - now_ts;
    if delta <= 0.0 {
        return;
    }
    // 跨零点保护（12h/30min 阈值下整秒精度足够，复用上面的 now_ts）
    if delta > 12.0 * 3600.0 && now_ts - (target_ts - 24.0 * 3600.0) < 30.0 * 60.0
    {
        eprintln!("开火时刻已过（跨零点），立即开抢");
        return;
    }
    eprintln!(
        "等待 {:.1}s 至 {}（北京时间）准时开抢{}...",
        delta,
        target_str,
        if lead > 0.0 {
            format!("，提前 {:.2}s 补偿网络往返", lead)
        } else {
            String::new()
        }
    );
    // sleep 段用单调钟锚定，最后 5ms 忙等
    let deadline = Instant::now() + Duration::from_secs_f64(delta);
    if delta > 0.005 {
        std::thread::sleep(Duration::from_secs_f64(delta - 0.005));
    }
    while Instant::now() < deadline {}
}

// ---------------------------------------------------------------------------
// 循环抢券
// ---------------------------------------------------------------------------

struct LoopState {
    /// 每账号已搞定的 couponId。
    done: Vec<HashSet<String>>,
    /// 每账号 couponName -> 最终条目。
    final_: Vec<HashMap<String, Value>>,
    events: Vec<GrantEvent>,
    backoff_until: Vec<f64>,
    soldout_streak: Vec<HashMap<String, usize>>,
    /// 每账号的 (brandId, Coupon) 目标列表，可增量合并。
    targets: Vec<Vec<(String, Coupon)>>,
}

/// 循环抢券：多账号并发尝试，请求错峰 + 限流退避，直到全部到手或超时。
///
/// 全部运行状态都在 `state` 里，由 `Mutex` 保护；不再有模块级可变全局。
pub struct LoopRunner {
    auths: Vec<Auth>,
    cfg: Config,
    minutes: f64,
    interval: f64,
    fire_at: Option<String>,
    logger: Arc<RunLogger>,
    secrets: Arc<SecretsRegistry>,
    notifier: Option<Arc<Notifier>>,
    clients: Vec<Arc<ApiClient>>,
    pacing: GrantPacing,
    state: Mutex<LoopState>,
    events_path: Option<PathBuf>,
    /// 线程池规模 = 账号数 × (目标券数 + 1) + 1，仅用于日志与容量参考；
    /// 实际派发用 `std::thread::scope` 按波次起线程（每波任务数远小于账号数×券数）。
    pool_workers: usize,
}

impl LoopRunner {
    /// 构造 Runner。参数多是因为运行参数（时长/间隔/开火时刻/日志/通知）
    /// 都是彼此独立的装配项，与 Python 版 `LoopRunner.__init__` 一一对应。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auths: Vec<Auth>,
        cfg: Config,
        minutes: f64,
        interval: f64,
        fire_at: Option<String>,
        run_log: Option<&Path>,
        secrets: Arc<SecretsRegistry>,
        notifier: Option<Arc<Notifier>>,
    ) -> Result<Self, String> {
        if cfg.snipe_coupons().is_empty() {
            return Err(format!(
                "抢券目标为空：关键词 {} 未匹配到任何固定券，请检查 snipe_keyword / fixed_coupons",
                cfg.snipe_keyword
            ));
        }
        let logger = Arc::new(RunLogger::new(run_log, Arc::clone(&secrets)));
        let events_path = run_log.map(|p| p.with_extension("jsonl"));

        let mut clients = Vec::new();
        for auth in &auths {
            clients.push(Arc::new(ApiClient::from_auth(
                auth,
                &cfg,
                Arc::clone(&secrets),
                None,
            )?));
        }
        let pacing = GrantPacing::new(
            cfg.first_wave_gap,
            cfg.first_wave_inflight,
            cfg.sustained_gap,
            cfg.sustained_inflight,
        );

        // 固定券直接就位：两张 5 折第一波极限开抢；满28减10 不参与秒杀，
        // 从第二波开始跟进（全天可领，无需极限速度；第一波保持冻结的
        // 0.05s 错峰 + 6 并发，不给限流桶增加负担）
        let snipe = &cfg.fixed_coupons;
        let mut targets: Vec<Vec<(String, Coupon)>> = Vec::new();
        for _ in &auths {
            let list = snipe
                .iter()
                .map(|c| (cfg.fixed_brand_id.clone(), Coupon::from_api(c)))
                .collect();
            targets.push(list);
        }
        let per_account = targets.iter().map(|t| t.len()).max().unwrap_or(0);
        // 线程池规模 = 账号数 × (目标券数 + 1) + 1
        let pool_workers = auths.len() * (per_account + 1) + 1;

        Ok(Self {
            auths,
            cfg,
            minutes,
            interval,
            fire_at,
            logger,
            secrets,
            notifier,
            clients,
            pacing,
            events_path,
            pool_workers,
            state: Mutex::new(LoopState {
                done: targets.iter().map(|_| HashSet::new()).collect(),
                final_: targets.iter().map(|_| HashMap::new()).collect(),
                events: Vec::new(),
                backoff_until: targets.iter().map(|_| 0.0).collect(),
                soldout_streak: targets.iter().map(|_| HashMap::new()).collect(),
                targets,
            }),
        })
    }

    pub fn run(&self) -> Vec<(String, Vec<Value>)> {
        let log = |m: &str| self.logger.log(m);
        log(&format!(
            "并发抢券开始，持续 {} 分钟，间隔 {}s（第一波{}秒极限{}并发只抢{}，\
                      后续{}秒安全模式，线程池规模 {}）",
            self.minutes,
            self.interval,
            self.cfg.first_wave_gap,
            self.cfg.first_wave_inflight,
            self.cfg.snipe_keyword,
            self.cfg.sustained_gap,
            self.pool_workers
        ));
        let mut wave_count = 0usize;
        let mut wave1_all_soldout = false;

        if self.fire_at.is_some() {
            self.preheat_and_wait();
        }
        let deadline = Instant::now() + Duration::from_secs_f64(self.minutes * 60.0);

        // 单层波次循环（与 Python 版同构）：任一 break 都直接结束抢券。
        // 曾误写成「外层 while + 内层 loop」，内层 break 只跳出内层，
        // 外层会带着空任务继续空转到 deadline。
        let mut last_refresh = Instant::now();
        loop {
            if Instant::now() >= deadline {
                break;
            }
            // 第一波结束后、以及每 refresh_every 秒提交一次列表刷新
            if wave_count == 1 || last_refresh.elapsed().as_secs_f64() >= self.cfg.refresh_every {
                std::thread::scope(|s| {
                    for (i, client) in self.clients.iter().enumerate() {
                        let this = &self;
                        s.spawn(move || this.refresh_one(i, client));
                    }
                });
                last_refresh = Instant::now();
            }
            let mut tasks = self.build_wave_tasks();
            if wave_count == 0 {
                // 第一波只打 5 折：冻结的最优策略（0.05s 错峰 + 6 并发），
                // 行为与之前逐字节一致；满28减10 不争抢，从第二波开始跟进
                tasks.retain(|(_, _, c)| self.is_priority(c));
            }
            let events_before = {
                let st = self.state.lock().unwrap();
                st.events.len()
            };
            log(&format!(
                "第 {} 波开始，共 {} 个任务",
                wave_count + 1,
                tasks.len()
            ));
            std::thread::scope(|s| {
                for (i, brand_id, coupon) in tasks {
                    let this = &self;
                    s.spawn(move || this.grant_one(i, &brand_id, &coupon));
                }
            });
            wave_count += 1;

            let wave_events = {
                let st = self.state.lock().unwrap();
                st.events[events_before..].to_vec()
            };

            if wave_count == 1 && !self.cfg.burst_test {
                self.pacing.enter_sustained_mode();
                log(&format!(
                    "第一波结束，已切换到安全模式（{}秒间隔、最多{}并发）",
                    self.cfg.sustained_gap, self.cfg.sustained_inflight
                ));
            }

            // 首波全抢光提前收工
            if self.cfg.early_stop_all_soldout
                && wave_count == 1
                && !wave_events.is_empty()
                && wave_events.iter().all(|e| e.status == "out_of_stock")
            {
                wave1_all_soldout = true;
                log("首波全抢光，下一波确认后若仍全抢光则提前收工");
            } else if self.cfg.early_stop_all_soldout && wave_count == 2 && wave1_all_soldout {
                if !wave_events.is_empty() && wave_events.iter().all(|e| e.status == "out_of_stock")
                {
                    log("确认波全抢光，提前收工（券已抢完，不再消耗配额）");
                    break;
                }
                wave1_all_soldout = false;
            }

            if self.all_settled() {
                log("所有券已有结论（已领/抢光停止），提前结束");
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let sleep_secs = self.interval.min(remaining.as_secs_f64()).max(0.0);
            std::thread::sleep(Duration::from_secs_f64(sleep_secs));
        }

        self.log_summary(wave_count);
        self.dump_events();
        let report = self.finalize();
        self.notify(&report, wave_count);
        report
    }

    // -- 子任务 -----------------------------------------------------------

    fn refresh_one(&self, index: usize, client: &ApiClient) {
        let label = &self.auths[index].label;
        match client.find_brand_coupons(Some(Duration::from_secs_f64(self.cfg.refresh_timeout))) {
            Ok((brand, coupons)) => {
                let mut added = 0usize;
                let mut st = self.state.lock().unwrap();
                let known: HashSet<String> = st.targets[index]
                    .iter()
                    .map(|(_, c)| c.coupon_id.clone())
                    .collect();
                let brand_id = brand
                    .as_ref()
                    .and_then(|b| b.get("brandId"))
                    .and_then(Value::as_str)
                    .map(String::from)
                    .unwrap_or_else(|| self.cfg.fixed_brand_id.clone());
                for c in coupons {
                    if self.cfg.skip_types.contains(&c.coupon_type) || c.coupon_id.is_empty() {
                        continue;
                    }
                    if !c.coupon_name.contains(&self.cfg.snipe_keyword) {
                        continue;
                    }
                    if !known.contains(&c.coupon_id) {
                        st.targets[index].push((brand_id.clone(), c));
                        added += 1;
                    }
                }
                drop(st);
                if added > 0 {
                    self.logger
                        .log(&format!("[{}] 发现 {} 张新券，已加入抢券", label, added));
                }
            }
            Err(e) => {
                self.logger.log(&format!(
                    "[{}] 列表拉取失败: {}",
                    label,
                    e.message(&self.secrets)
                ));
            }
        }
    }

    fn grant_one(&self, index: usize, brand_id: &str, coupon: &Coupon) {
        let label = &self.auths[index].label;
        let cid = &coupon.coupon_id;
        let name = coupon.coupon_name.clone();
        {
            let st = self.state.lock().unwrap();
            if st.done[index].contains(cid)
                || Instant::now().elapsed().as_secs_f64() < st.backoff_until[index]
            {
                return;
            }
        }
        let client = &self.clients[index];
        let t0 = Instant::now();
        let (status, detail, send_ts) =
            try_grant(client, brand_id, coupon, Some(&self.pacing), &self.cfg);
        let elapsed = t0.elapsed().as_secs_f64();
        let send_ts = send_ts.unwrap_or_else(beijing_ts);

        let mut st = self.state.lock().unwrap();
        st.events.push(GrantEvent {
            send_ts: send_ts.clone(),
            label: label.clone(),
            coupon_name: name.clone(),
            status: status.clone(),
            elapsed,
        });
        match status.as_str() {
            "granted" | "already_claimed" => {
                st.done[index].insert(cid.clone());
                st.final_[index].insert(
                    name.clone(),
                    json!({"coupon": name, "status": status, "detail": detail}),
                );
                self.logger.log(&format!(
                    "[{}] {} -> {} (发送{}, 耗时{:.2}s)",
                    label, name, status, send_ts, elapsed
                ));
            }
            "rate_limited" => {
                st.backoff_until[index] = now_mono() + self.cfg.rate_limit_backoff;
                // 注意：限流不重置抢光计数——40007 只说明"慢点"，不说明"券回来了"。
                // 2026-10-14：Python 版同位置 bug 导致 177 的立减20 在
                // 60001/40007 交替中跑满 10 分钟，streak 永远到不了 3。
                st.final_[index].insert(
                    name.clone(),
                    json!({"coupon": name, "status": status, "detail": detail}),
                );
                self.logger.log(&format!(
                    "[{}] 命中限流，退避 {}s (发送{}, 耗时{:.2}s)",
                    label, self.cfg.rate_limit_backoff, send_ts, elapsed
                ));
            }
            "auth_expired" => {
                st.soldout_streak[index].remove(cid);
                st.done[index].insert(cid.clone());
                st.final_[index].insert(
                    name.clone(),
                    json!({"coupon": name, "status": status, "detail": detail}),
                );
                self.logger.log(&format!(
                    "[{}] {} -> 登录态失效，停止重试 (发送{}, 耗时{:.2}s)",
                    label, name, send_ts, elapsed
                ));
            }
            "out_of_stock" => {
                let streak = st.soldout_streak[index].get(cid).copied().unwrap_or(0) + 1;
                st.soldout_streak[index].insert(cid.clone(), streak);
                st.final_[index].insert(
                    name.clone(),
                    json!({"coupon": name, "status": status, "detail": detail}),
                );
                if streak >= self.cfg.soldout_stop_after {
                    st.done[index].insert(cid.clone());
                    self.logger.log(&format!(
                        "[{}] {} 连续{}次抢光，停止重试 (发送{}, 耗时{:.2}s)",
                        label, name, streak, send_ts, elapsed
                    ));
                } else {
                    self.logger.log(&format!(
                        "[{}] {} -> 抢光第{}次 (发送{}, 耗时{:.2}s)",
                        label, name, streak, send_ts, elapsed
                    ));
                }
            }
            _ => {
                st.soldout_streak[index].remove(cid);
                st.final_[index].insert(
                    name.clone(),
                    json!({"coupon": name, "status": status, "detail": detail}),
                );
                if detail.contains("不存在")
                    || detail.contains("已下架")
                    || detail.contains("已失效")
                    || detail.contains("not exist")
                    || detail.contains("invalid")
                {
                    st.done[index].insert(cid.clone());
                    self.logger.log(&format!(
                        "[{}] {} 已失效，停止重试 (发送{}, 耗时{:.2}s)",
                        label, name, send_ts, elapsed
                    ));
                } else {
                    self.logger.log(&format!(
                        "[{}] {} -> {} (发送{}, 耗时{:.2}s): {}",
                        label,
                        name,
                        status,
                        send_ts,
                        elapsed,
                        detail.chars().take(150).collect::<String>()
                    ));
                }
            }
        }
    }

    // -- 主流程步骤 -------------------------------------------------------

    /// 时钟校验：开火精度依赖系统时钟。Linux 查 `timedatectl`，其他平台记录跳过。
    fn check_clock(&self) {
        if !cfg!(target_os = "linux") {
            self.logger
                .log("时钟校验: 非 Linux 平台跳过（精度依赖系统时钟）");
            return;
        }
        match std::process::Command::new("timedatectl")
            .args(["show", "-p", "NTPSynchronized"])
            .output()
        {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if text.is_empty() {
                    self.logger.log(&format!(
                        "时钟校验: 无输出（rc={:?}{}）",
                        out.status.code(),
                        if out.stderr.is_empty() {
                            String::new()
                        } else {
                            format!(
                                "，{}",
                                String::from_utf8_lossy(&out.stderr)
                                    .trim()
                                    .chars()
                                    .take(80)
                                    .collect::<String>()
                            )
                        }
                    ));
                } else {
                    self.logger.log(&format!("时钟校验: {}", text));
                }
            }
            Err(e) => self.logger.log(&format!("时钟校验跳过: {}", e)),
        }
    }

    /// 预热连接后精确等待开火时刻。预热并行：各账号只读查询并发打。
    fn preheat_and_wait(&self) {
        self.check_clock();
        self.logger.log("预热连接...");
        let rtts: Mutex<Vec<(usize, f64)>> = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for (i, client) in self.clients.iter().enumerate() {
                let this = &self;
                let rtts = &rtts;
                s.spawn(move || {
                    let t0 = Instant::now();
                    let target = this.state.lock().unwrap().targets[i]
                        .first()
                        .map(|(_, c)| c.coupon_id.clone())
                        .unwrap_or_default();
                    match client.grant_status(
                        std::slice::from_ref(&target),
                        Some(Duration::from_secs_f64(this.cfg.ping_timeout)),
                    ) {
                        Ok(_) => {
                            let rtt = t0.elapsed().as_secs_f64();
                            rtts.lock().unwrap().push((i, rtt));
                            this.logger.log(&format!(
                                "[{}] 预热完成 (RTT {:.2}s)",
                                this.auths[i].label, rtt
                            ));
                        }
                        Err(e) => this.logger.log(&format!(
                            "[{}] 预热失败: {}",
                            this.auths[i].label,
                            e.message(&this.secrets)
                        )),
                    }
                });
            }
        });
        let mut lead = adaptive_lead(
            self.cfg.adaptive_lead,
            self.cfg.fire_lead,
            &rtts.into_inner().unwrap(),
        );
        // 开火下限（2026-10-14 定版）：实际开火时刻不早于 fire_floor（默认 59.7）。
        // 宁可晚到排队，不早到撞旧库存。
        if let (Some(fire_at), Some(floor)) = (&self.fire_at, &self.cfg.fire_floor) {
            lead = lead.min(lead_cap_for_floor(fire_at, floor));
        }
        if let Some(fire_at) = &self.fire_at {
            wait_until(fire_at, lead);
        }
        self.logger.log(&format!("开火！(lead={:.2}s)", lead));
    }

    /// 两张 5 折券优先并发。
    fn is_priority(&self, coupon: &Coupon) -> bool {
        coupon.coupon_name.contains(&self.cfg.snipe_keyword)
    }

    /// 本轮任务：优先券排前面，其余（满28减10）跟在其后。
    fn build_wave_tasks(&self) -> Vec<(usize, String, Coupon)> {
        let mut tasks = Vec::new();
        let st = self.state.lock().unwrap();
        for i in 0..self.auths.len() {
            let pending: Vec<&(String, Coupon)> = st.targets[i]
                .iter()
                .filter(|(_, c)| !st.done[i].contains(&c.coupon_id))
                .collect();
            let pri: Vec<_> = pending
                .iter()
                .filter(|(_, c)| self.is_priority(c))
                .collect();
            let rest: Vec<_> = pending
                .iter()
                .filter(|(_, c)| !self.is_priority(c))
                .collect();
            for (brand_id, c) in pri.into_iter().chain(rest) {
                tasks.push((i, brand_id.clone(), c.clone()));
            }
        }
        tasks
    }

    fn all_settled(&self) -> bool {
        let st = self.state.lock().unwrap();
        let pending = st
            .targets
            .iter()
            .enumerate()
            .any(|(i, list)| list.iter().any(|(_, c)| !st.done[i].contains(&c.coupon_id)));
        !pending && st.targets.iter().any(|t| !t.is_empty())
    }

    fn log_summary(&self, wave_count: usize) {
        let st = self.state.lock().unwrap();
        if st.events.is_empty() {
            return;
        }
        let mut counts: Vec<(String, usize)> = Vec::new();
        for e in &st.events {
            match counts.iter_mut().find(|(k, _)| *k == e.status) {
                Some(x) => x.1 += 1,
                None => counts.push((e.status.clone(), 1)),
            }
        }
        let elapseds: Vec<f64> = st.events.iter().map(|e| e.elapsed).collect();
        self.logger.log("=== 收尾统计 ===");
        self.logger.log(&format!(
            "总波次: {}, 总请求: {}",
            wave_count,
            st.events.len()
        ));
        self.logger.log(&format!("状态分布: {:?}", counts));
        self.logger.log(&format!(
            "耗时: 最小{:.2}s 最大{:.2}s 平均{:.2}s",
            elapseds.iter().cloned().fold(f64::INFINITY, f64::min),
            elapseds.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            elapseds.iter().sum::<f64>() / elapseds.len() as f64
        ));
        // 第一波 = 发送时刻最小的一批事件（不硬编码前 N 个）
        let first_ts = st
            .events
            .iter()
            .map(|e| e.send_ts.clone())
            .min()
            .unwrap_or_default();
        let first_wave: Vec<&str> = st
            .events
            .iter()
            .filter(|e| e.send_ts == first_ts)
            .map(|e| e.send_ts.as_str())
            .collect();
        if !first_wave.is_empty() {
            self.logger
                .log(&format!("第一波发送时刻: {}", first_wave.join(" | ")));
        }
    }

    fn dump_events(&self) {
        let path = match &self.events_path {
            Some(p) => p,
            None => return,
        };
        let st = self.state.lock().unwrap();
        if st.events.is_empty() {
            return;
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            for e in &st.events {
                let _ = writeln!(f, "{}", e.to_json());
            }
            self.logger
                .log(&format!("事件明细已写入: {}", path.display()));
        }
    }

    /// 收尾：用 grant-status 补一次状态校验。
    fn finalize(&self) -> Vec<(String, Vec<Value>)> {
        let mut report = Vec::new();
        for i in 0..self.auths.len() {
            let label = &self.auths[i].label;
            let all_coupons: Vec<Coupon> = {
                let st = self.state.lock().unwrap();
                st.targets[i].iter().map(|(_, c)| c.clone()).collect()
            };
            match self.clients[i].grant_status(
                &all_coupons
                    .iter()
                    .map(|c| c.coupon_id.clone())
                    .collect::<Vec<_>>(),
                None,
            ) {
                Ok(statuses) => {
                    let mut st = self.state.lock().unwrap();
                    for c in &all_coupons {
                        let name = c.coupon_name.clone();
                        if !st.final_[i].contains_key(&name) {
                            st.final_[i].insert(name.clone(), json!({"coupon": name}));
                        }
                        if let Some(s) = statuses.get(&c.coupon_id) {
                            st.final_[i].get_mut(&name).unwrap()["grant_status"] = s.clone();
                        }
                    }
                }
                Err(e) => {
                    self.logger.log(&format!(
                        "[{}] 收尾校验失败: {}",
                        label,
                        e.message(&self.secrets)
                    ));
                }
            }
            let items = {
                let st = self.state.lock().unwrap();
                st.final_[i].values().cloned().collect::<Vec<_>>()
            };
            report.push((label.clone(), items));
        }
        report
    }

    fn notify(&self, report: &[(String, Vec<Value>)], wave_count: usize) {
        let n = match &self.notifier {
            Some(n) => n,
            None => return,
        };
        let extra: Vec<String> = vec![
            format!(
                "波次 {}, 请求 {}",
                wave_count,
                self.state.lock().unwrap().events.len()
            ),
            format!(
                "事件明细 {}",
                self.events_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "未落盘".to_string())
            ),
        ];
        n.notify_report("result", report, &extra);

        // 同一张券多次尝试时取最后一次的时刻
        let last_try: Vec<(String, String, String, f64)> = {
            let st = self.state.lock().unwrap();
            let mut out: Vec<(String, String, String, f64)> = Vec::new();
            for e in &st.events {
                if let Some(x) = out
                    .iter_mut()
                    .find(|(l, n, _, _)| *l == e.label && *n == e.coupon_name)
                {
                    x.2 = e.send_ts.split(' ').next_back().unwrap_or("").to_string();
                    x.3 = e.elapsed;
                } else {
                    out.push((
                        e.label.clone(),
                        e.coupon_name.clone(),
                        e.send_ts.split(' ').next_back().unwrap_or("").to_string(),
                        e.elapsed,
                    ));
                }
            }
            out
        };
        for (i, (label, items)) in report.iter().enumerate() {
            let timings: Vec<(String, String, f64)> = last_try
                .iter()
                .filter(|(l, _, _, _)| l == label)
                .map(|(_, name, ts, e)| (name.clone(), ts.clone(), *e))
                .collect();
            let (targets, to_mails) = account_routing(&self.auths[i]);
            n.notify_account(
                label,
                items,
                &timings,
                &[],
                to_mails.as_deref(),
                targets.as_deref(),
            );
        }

        let expired: Vec<String> = report
            .iter()
            .flat_map(|(_, items)| items.iter())
            .filter(|it| it.get("status").and_then(Value::as_str) == Some("auth_expired"))
            .filter_map(|it| it.get("coupon").and_then(Value::as_str).map(String::from))
            .collect();
        if !expired.is_empty() {
            let _ = self.minutes; // 保持字段使用
            n.notify(
                "auth_expired",
                "账号的会话已失效（873）。\n请重新登录 -> 扩展导出 cookie -> \
                          tools/import_cookie_export.py --merge --label <该账号>，\
                          再用 --verify-session 确认。",
                None,
                false,
                None,
                None,
                None,
            );
        }
    }
}

/// 循环抢券入口（薄封装）。参数与 [`LoopRunner::new`] 一致，透传即可。
#[allow(clippy::too_many_arguments)]
pub fn loop_run(
    auths: Vec<Auth>,
    config: Config,
    minutes: f64,
    interval: f64,
    fire_at: Option<String>,
    run_log: Option<&Path>,
    secrets: Arc<SecretsRegistry>,
    notifier: Option<Arc<Notifier>>,
) -> Result<Vec<(String, Vec<Value>)>, String> {
    let runner = LoopRunner::new(
        auths, config, minutes, interval, fire_at, run_log, secrets, notifier,
    )?;
    Ok(runner.run())
}

/// 用预热 RTT 自适应开火提前量，让请求落在整点附近。
///
/// 取 RTT 中位数 × 0.2（保守系数，RTT=1.5s 时恰为已验证的 0.3s），
/// 钳制在 [0.1, 0.299]。关闭开关或无预热数据时回退固定 `fire_lead`。
/// 2026-10-13：下限从 0.2 降到 0.1——177 的立减20 因网络波动提前到达，
/// 撞上旧库存 60001；提前到达比晚到更致命。
/// 2026-10-15：上限从 0.6 降到 0.299——开火基准 59.999，lead 上限 0.299
/// 时最早开火 59.700（= 旧 fire_floor 下限），把下限内建到 lead 上限里。
pub fn adaptive_lead(enabled: bool, fire_lead: f64, rtts: &[(usize, f64)]) -> f64 {
    if !enabled || rtts.is_empty() {
        return fire_lead;
    }
    let mut values: Vec<f64> = rtts.iter().map(|(_, r)| *r).collect();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    // 真中位数：奇数个取中间，偶数个取中间两数的平均
    // （2026-10-15 修正：之前偶数个时直接取偏大的那个）
    let n = values.len();
    let median = if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    };
    (0.299f64).min((0.1f64).max(median * 0.2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beijing_ts_format() {
        let ts = beijing_ts();
        // 2026-10-12 14:02:39.45
        assert_eq!(ts.len(), 22, "时间戳长度: {}", ts);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], " ");
        assert_eq!(&ts[19..20], ".");
    }

    #[test]
    fn adaptive_lead_uses_median_times_coefficient() {
        let rtts = vec![(0usize, 1.5), (1, 2.0), (2, 1.0)];
        // 中位数 1.5 × 0.2 = 0.3（实测验证过的那个点）
        assert!((adaptive_lead(true, 0.0, &rtts) - 0.299).abs() < 1e-9);
    }

    #[test]
    fn adaptive_lead_even_count_uses_average() {
        // 2026-10-15：偶数个时取中间两数的平均：(0.68+1.46)/2=1.07 → 0.214
        let rtts = vec![(0usize, 0.68), (1, 1.46)];
        assert!((adaptive_lead(true, 0.0, &rtts) - 0.214).abs() < 1e-9);
    }

    #[test]
    #[test]
    fn lead_cap_for_floor_caps_at_point_two() {
        // 59.9 基准、59.7 下限：lead 上限 0.2
        assert!((lead_cap_for_floor("23:59:59.9", "23:59:59.7") - 0.2).abs() < 1e-9);
        // fire_at 不晚于下限：不设限
        assert!(lead_cap_for_floor("23:59:59", "23:59:59.7").is_infinite());
        assert!(lead_cap_for_floor("23:59:59.7", "23:59:59.7").is_infinite());
    }

    fn adaptive_lead_is_clamped() {
        // 网络很慢：钳在上界 0.6
        let slow = vec![(0usize, 10.0)];
        assert!((adaptive_lead(true, 0.0, &slow) - 0.6).abs() < 1e-9);
        // 网络很快：钳在下界 0.1，不会提前过头
        let fast = vec![(0usize, 0.1)];
        assert!((adaptive_lead(true, 0.0, &fast) - 0.1).abs() < 1e-9);
    }

    #[test]
    fn adaptive_lead_falls_back_when_disabled_or_no_data() {
        assert!((adaptive_lead(false, 0.3, &[(0, 1.5)]) - 0.3).abs() < 1e-9);
        assert!((adaptive_lead(true, 0.25, &[]) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn wait_until_past_target_returns_immediately() {
        let t0 = Instant::now();
        wait_until("00:00", 0.0);
        assert!(t0.elapsed().as_secs_f64() < 0.5, "已过的目标应立即返回");
    }

    #[test]
    fn wait_until_waits_for_near_future_target() {
        // 取当前北京时间 +1s 作为目标
        let tz = chrono_tz::Asia::Shanghai;
        let target = chrono::Utc::now().with_timezone(&tz) + chrono::Duration::seconds(1);
        let s = target.format("%H:%M:%S").to_string();
        let t0 = Instant::now();
        wait_until(&s, 0.0);
        assert!(
            t0.elapsed().as_secs_f64() >= 0.4,
            "应至少等到目标附近，实际 {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }

    #[test]
    fn wait_until_rejects_bad_format_without_panicking() {
        let t0 = Instant::now();
        wait_until("not-a-time", 0.0);
        wait_until("25:99", 0.0);
        wait_until("", 0.0);
        assert!(t0.elapsed().as_secs_f64() < 0.5, "非法格式应立即返回");
    }
}
