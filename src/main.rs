//! 命令行入口：参数解析、配置装配、账号筛选、分发到 flows、退出码。
//!
//! 与 Python 版 `claim.py` / `meituan/cli.py` 的参数与语义保持一致。

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use meituan::config::{base_dir, load_config, Overrides};
use meituan::flows;
use meituan::notify::Notifier;
use meituan::security::{load_auths, SecretsRegistry};

/// 开火时刻：`HH:MM[:SS[.毫秒]]`，秒可省略。
fn valid_fire_at(v: &str) -> Result<String, String> {
    let parts: Vec<&str> = v.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(fmt_err(v));
    }
    let h: u32 = parts[0].parse().map_err(|_| fmt_err(v))?;
    let m: u32 = parts[1].parse().map_err(|_| fmt_err(v))?;
    let s: f64 = if parts.len() > 2 {
        parts[2].parse().map_err(|_| fmt_err(v))?
    } else {
        0.0
    };
    if h > 23 || m > 59 || s < 0.0 || s >= 60.0 {
        return Err(fmt_err(v));
    }
    Ok(v.to_string())
}

fn fmt_err(v: &str) -> String {
    format!(
        "开火时刻格式应为 HH:MM[:SS[.毫秒]]，例如 14:00:00.000，收到: {}",
        v
    )
}

#[derive(Parser, Debug)]
#[command(
    name = "meituan",
    version,
    about = "网易大神 partner-perks 美团外卖券自动领取（多账号并发、请求签名直调）"
)]
struct Cli {
    /// 循环抢券模式（并发 + 错峰）
    #[arg(long)]
    r#loop: bool,

    /// 循环持续分钟数（默认 10，可被配置/环境变量覆盖）
    #[arg(long)]
    minutes: Option<f64>,

    /// 每轮间隔秒数（默认 2.0）
    #[arg(long)]
    interval: Option<f64>,

    /// 开火时刻 HH:MM[:SS[.毫秒]]，到点才打第一波（已过则立即开火）
    #[arg(long, value_parser = valid_fire_at)]
    fire_at: Option<String>,

    /// 开火提前量秒数（补偿首波网络往返）
    #[arg(long)]
    fire_lead: Option<f64>,

    /// JSON 配置文件路径（默认当前目录 claim.config.json，存在才读）
    #[arg(long)]
    config: Option<PathBuf>,

    /// 只运行指定账号（逗号分隔，按 label 或认证文件名匹配）
    #[arg(long)]
    accounts: Option<String>,

    /// 强制开启通知
    #[arg(long, conflicts_with = "no_notify")]
    notify: bool,

    /// 本次运行不发送通知
    #[arg(long)]
    no_notify: bool,

    /// 按配置的通道发一条测试消息后退出（校验通道可用性）
    #[arg(long)]
    notify_test: bool,

    /// 只读健康检查：仅调用 info/grant-status 只读接口，无业务副作用；
    /// 无法证明登录态时返回 reachable
    #[arg(long, conflicts_with = "verify_session")]
    ping: bool,

    /// 会话验证：只读无副作用，调 userInfo 接口验证登录态（873=过期）
    #[arg(long)]
    verify_session: bool,
}

fn filter_accounts(
    mut auths: Vec<meituan::security::Auth>,
    spec: &str,
) -> Vec<meituan::security::Auth> {
    let wanted: Vec<&str> = spec
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    auths.retain(|a| {
        if wanted.contains(&a.label.as_str()) {
            return true;
        }
        match &a.auth_file {
            Some(p) => {
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let stem = p
                    .file_stem()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                wanted.contains(&name.as_str()) || wanted.contains(&stem.as_str())
            }
            None => false,
        }
    });
    auths
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let notify_enabled = if cli.notify {
        Some(true)
    } else if cli.no_notify {
        Some(false)
    } else {
        None
    };
    let overrides = Overrides {
        loop_minutes: cli.minutes,
        loop_interval: cli.interval,
        fire_at: cli.fire_at.clone(),
        fire_lead: cli.fire_lead,
        notify_enabled,
    };

    let cfg = match load_config(cli.config.as_deref(), &overrides) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("配置错误: {}", e);
            return std::process::ExitCode::from(2);
        }
    };

    let secrets = SecretsRegistry::new();
    // 通知凭据（token/webhook/SMTP 密码）立刻登记脱敏
    meituan::notify::register_secrets(&cfg, &secrets);

    if cli.r#loop && cfg.snipe_coupons().is_empty() {
        eprintln!(
            "抢券目标为空（关键词 '{}' 未匹配到任何固定券），loop 会空转到超时——\
                   请检查 snipe_keyword / fixed_coupons",
            cfg.snipe_keyword
        );
        return std::process::ExitCode::from(2);
    }

    let notifier = || Arc::new(Notifier::new(cfg.clone(), Arc::clone(&secrets)));

    // 通知自检不需要凭据文件，先于账号加载
    if cli.notify_test {
        let n = notifier();
        let mut out = Vec::new();
        if n.enabled() {
            let r = n.notify(
                "test",
                "这是一条 meituan 通知测试消息（全局通道）。",
                None,
                true,
                Some(&cfg.notify_to_mails),
                None,
                None,
            );
            out.push(("__global__".to_string(), r));
        }
        let auths = load_auths(&cfg.auth_files, &base_dir(), &secrets).unwrap_or_default();
        for auth in &auths {
            let (targets, to_mails) = meituan::notify::account_routing(auth);
            if targets.is_none() && to_mails.is_none() {
                continue;
            }
            let r = n.notify(
                "test",
                "这是一条 meituan 账号路由测试消息。",
                None,
                true,
                to_mails.as_deref(),
                targets.as_deref(),
                None,
            );
            out.push((auth.label.clone(), r));
        }
        if out.is_empty() {
            eprintln!(
                "没有可发的测试：notify_targets 为空，且账号条目没写 \
                       notify / notify_mail"
            );
            return std::process::ExitCode::from(2);
        }
        for (who, results) in &out {
            for (ch, ok, detail) in results {
                println!("{} {} {}", who, ch, if *ok { "OK" } else { "FAIL" });
                if !ok {
                    eprintln!("  {}", detail);
                }
            }
        }
        let all_ok = out.iter().flat_map(|(_, r)| r.iter()).all(|(_, ok, _)| *ok);
        return if all_ok {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::FAILURE
        };
    }

    let mut auths = match load_auths(&cfg.auth_files, &base_dir(), &secrets) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("凭据加载失败: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };
    if auths.is_empty() {
        eprintln!("没有任何账号 Cookie 文件（{}）", cfg.auth_files.join(" / "));
        return std::process::ExitCode::FAILURE;
    }
    if let Some(spec) = &cli.accounts {
        auths = filter_accounts(auths, spec);
        if auths.is_empty() {
            eprintln!("--accounts 未匹配到任何账号: {}", spec);
            return std::process::ExitCode::from(2);
        }
    }

    let n = notifier();
    let run_log = |prefix: &str| -> Option<PathBuf> {
        let dir = PathBuf::from(&cfg.run_log_dir);
        let name = format!(
            "{}-{}.log",
            prefix,
            flows::beijing_ts().replace(' ', "_").replace(':', "")
        );
        let _ = std::fs::create_dir_all(&dir);
        Some(dir.join(name))
    };

    if cli.ping {
        let report = flows::ping(
            &auths,
            &cfg,
            Some(&cfg.keepalive_log),
            Arc::clone(&secrets),
            Some(&n),
        );
        let map: std::collections::HashMap<String, String> = report.into_iter().collect();
        println!("{}", serde_json::to_string_pretty(&map).unwrap_or_default());
        return exit_code(&map, &|v: &str| v == "expired" || v.starts_with("error"));
    }

    if cli.verify_session {
        let report = flows::verify_session(
            &auths,
            &cfg,
            Some(&cfg.keepalive_log),
            Arc::clone(&secrets),
            Some(&n),
        );
        for (auth, pair) in auths.iter().zip(report.iter()) {
            if pair.1.starts_with("authenticated") {
                if let Some(f) = &auth.auth_file {
                    eprintln!("认证文件已可用: {}", f.display());
                }
            }
        }
        let map: std::collections::HashMap<String, String> = report.into_iter().collect();
        println!("{}", serde_json::to_string_pretty(&map).unwrap_or_default());
        return exit_code(&map, &|v: &str| !v.starts_with("authenticated"));
    }

    let (report, any_error) = if cli.r#loop {
        let log = run_log("claim");
        match flows::loop_run(
            auths,
            cfg.clone(),
            cfg.loop_minutes,
            cfg.loop_interval,
            cfg.fire_at.clone(),
            log.as_deref(),
            Arc::clone(&secrets),
            Some(Arc::clone(&n)),
        ) {
            Ok(r) => {
                let bad = r.iter().flat_map(|(_, items)| items.iter()).any(|it| {
                    matches!(
                        it.get("status").and_then(|v| v.as_str()),
                        Some("auth_expired") | Some("error")
                    )
                });
                (r, bad)
            }
            Err(e) => {
                eprintln!("循环抢券启动失败: {}", e);
                return std::process::ExitCode::from(2);
            }
        }
    } else {
        let log = run_log("claim-single");
        flows::single_run(&auths, &cfg, log.as_deref(), Arc::clone(&secrets), Some(&n))
    };

    let obj: std::collections::HashMap<&str, &Vec<serde_json::Value>> =
        report.iter().map(|(l, i)| (l.as_str(), i)).collect();
    println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
    if any_error {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}

/// 把报告里健康状态判定转成退出码：任一账号命中 `bad` 即失败。
fn exit_code(
    report: &std::collections::HashMap<String, String>,
    bad: &dyn Fn(&str) -> bool,
) -> std::process::ExitCode {
    if report.values().any(|v| bad(v)) {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
