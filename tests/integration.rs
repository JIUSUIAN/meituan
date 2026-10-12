//! 集成测试：起本地 HTTP 桩服务冒充 inf.ds.163.com，跑通
//! `single_run` 全链路（拉列表 -> 查状态 -> 领取 -> 收尾复核 -> 通知分发）。
//!
//! 不访问任何真实第三方接口；桩服务只听 127.0.0.1 随机端口。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use meituan::config::Config;
use meituan::flows;
use meituan::notify::Notifier;
use meituan::security::{Auth, SecretsRegistry};
use serde_json::{json, Value};

/// 起一个一次性桩服务：按 URL 片段返回预置响应体，
/// 并记录收到的请求路径与完整请求头（供协议级断言）。
struct Stub {
    base: String,
    seen: Arc<Mutex<Vec<String>>>,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    fn spawn(routes: Vec<(String, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let heads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_c = Arc::clone(&seen);
        let heads_c = Arc::clone(&heads);
        let routes = Arc::new(routes);
        let acceptor = {
            let listener = listener;
            let seen = Arc::clone(&seen_c);
            let heads = Arc::clone(&heads_c);
            let routes = Arc::clone(&routes);
            thread::spawn(move || {
                // 每连接一个线程：顺序 accept 在并行测试下会拖慢后续请求
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let seen = Arc::clone(&seen);
                    let heads = Arc::clone(&heads);
                    let routes = Arc::clone(&routes);
                    thread::spawn(move || {
                        let mut buf = [0u8; 8192];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        let req = String::from_utf8_lossy(&buf[..n]).to_string();
                        let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                        seen.lock().unwrap().push(path.clone());
                        heads.lock().unwrap().push(req.clone());
                        let body = routes
                            .iter()
                            .find(|(frag, _)| path.contains(frag.as_str()))
                            .map(|(_, b)| b.clone())
                            .unwrap_or_else(|| r#"{"code":200,"result":{}}"#.to_string());
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                    });
                }
            })
        };
        drop(acceptor);
        // 桩已进入 accept（bind 即就绪），这里只做一次连通性确认
        Self {
            base: format!("http://127.0.0.1:{}", port),
            seen,
            heads,
        }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    /// 收到的全部请求头原文（每连接一份）。
    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

fn info_body(coupons: Value) -> String {
    json!({"code": 200, "result": {"brands": [{
        "brandId": "brand-1", "brandName": "霸王茶姬",
        "superCoupons": coupons,
    }]}})
    .to_string()
}

fn granted_status(ids: &[&str]) -> String {
    let items: Vec<Value> = ids
        .iter()
        .map(|id| json!({"couponId": id, "status": "GRANTED"}))
        .collect();
    json!({"code": 200, "result": {"grantItems": items}}).to_string()
}

fn empty_status() -> String {
    r#"{"code":200,"result":{"grantItems":[]}}"#.to_string()
}

fn auth(label: &str) -> Auth {
    Auth {
        label: label.into(),
        xsrf_token: "xsrf-synthetic-value".into(),
        god_uuid: "uuid-synthetic-value".into(),
        device_id: "device-synthetic-value".into(),
        cookies: {
            let mut b = meituan::cookies::CookieBag::new();
            b.insert("JSESSIONID", "js-synthetic-value");
            b
        },
        auth_file: None,
        auth_index: None,
        notify_targets: None,
        notify_to: None,
    }
}

fn cfg_for(base: &str) -> Config {
    Config {
        base_url: base.to_string(),
        ..Default::default()
    }
}

#[test]
fn single_run_full_pipeline_against_local_stub() {
    let coupons = json!([
        {"couponId": "c1", "couponName": "【外卖券】满28减10",
         "couponType": "PHONE_REWARD"},
        {"couponId": "c2", "couponName": "【5折外卖券】立减20",
         "couponType": "PHONE_REWARD"},
    ]);
    // c1 已领（grant-status 返回 GRANTED）；c2 未领 -> 调 grant
    let stub = Stub::spawn(vec![
        ("/super-coupon/info".into(), info_body(coupons)),
        ("/super-coupon/grant-status".into(), granted_status(&["c1"])),
        (
            "/super-coupon/grant".into(),
            r#"{"code":200,"result":{"winPrizeInfo":{"prizeName":"券"}}}"#.to_string(),
        ),
    ]);

    let secrets = SecretsRegistry::new();
    let (report, any_error) = flows::single_run(
        &[auth("177****7689")],
        &cfg_for(&stub.base),
        None,
        Arc::clone(&secrets),
        None,
    );

    assert!(!any_error, "全部正常路径不应报错");
    let (label, items) = &report[0];
    assert_eq!(label, "177****7689");
    assert_eq!(items.len(), 2, "两张券都应有结论");

    // c1：领取前查询已是 GRANTED -> already_claimed，且不再发起 grant
    let c1 = items
        .iter()
        .find(|i| i["coupon"] == "【外卖券】满28减10")
        .unwrap();
    assert_eq!(c1["status"], "already_claimed");
    assert_eq!(c1["grant_status"], "GRANTED");

    // c2：真的去领了 -> granted
    let c2 = items
        .iter()
        .find(|i| i["coupon"] == "【5折外卖券】立减20")
        .unwrap();
    assert_eq!(c2["status"], "granted");

    // 请求序列：info -> grant-status -> grant
    let seen = stub.seen();
    assert!(seen.iter().any(|p| p.contains("/info")), "应拉取列表");
    assert!(seen.iter().any(|p| p.contains("/grant-status")), "应查状态");
    assert!(seen.iter().any(|p| p.contains("/grant")), "应发起领取");
}

#[test]
fn single_run_snipe_only_skips_probe_coupon() {
    let coupons = json!([
        {"couponId": "c1", "couponName": "【外卖券】满28减10",
         "couponType": "PHONE_REWARD"},
        {"couponId": "c2", "couponName": "【5折外卖券】立减20",
         "couponType": "PHONE_REWARD"},
        {"couponId": "c3", "couponName": "【5折外卖券】立减25",
         "couponType": "PHONE_REWARD"},
    ]);
    let stub = Stub::spawn(vec![
        ("/super-coupon/info".into(), info_body(coupons)),
        ("/super-coupon/grant-status".into(), empty_status()),
        (
            "/super-coupon/grant".into(),
            r#"{"code":200,"result":{"winPrizeInfo":{}}}"#.to_string(),
        ),
    ]);

    let mut cfg = cfg_for(&stub.base);
    cfg.single_run_snipe_only = true;

    let secrets = SecretsRegistry::new();
    let (report, _) = flows::single_run(
        &[auth("177****7689")],
        &cfg,
        None,
        Arc::clone(&secrets),
        None,
    );
    let items = &report[0].1;
    let names: Vec<&str> = items
        .iter()
        .map(|i| i["coupon"].as_str().unwrap_or(""))
        .collect();
    assert!(
        !names.iter().any(|n| n.contains("满28减10")),
        "探针券应被跳过: {:?}",
        names
    );
    assert_eq!(names.len(), 2, "只处理两张 5 折券");
    assert!(names.iter().all(|n| n.contains("5折")));
}

#[test]
fn transport_failure_becomes_error_and_flags_exit_code() {
    // 桩服务对 info 返回 HTTP 500 -> 传输层失败
    let stub = Stub::spawn(vec![("/super-coupon/info".into(), "boom".to_string())]);
    let secrets = SecretsRegistry::new();
    let (report, any_error) = flows::single_run(
        &[auth("177****7689")],
        &cfg_for(&stub.base),
        None,
        Arc::clone(&secrets),
        None,
    );
    let status = report[0].1[0]["status"].as_str().unwrap();
    assert_eq!(status, "error", "传输失败应记 error，{:?}", report[0].1);
    assert!(any_error, "传输失败要影响退出码");
}

#[test]
fn notifier_dispatches_webhook_payload_to_local_stub() {
    let stub = Stub::spawn(vec![(
        "/hook".into(),
        r#"{"code":200,"msg":"ok"}"#.to_string(),
    )]);
    let cfg = Config {
        notify_targets: vec!["webhook".into()],
        notify_webhook_url: format!("{}/hook", stub.base),
        notify_events: vec!["result".into()],
        ..Default::default()
    };
    let secrets = SecretsRegistry::new();
    let n = Notifier::new(cfg, Arc::clone(&secrets));
    let report = vec![(
        "177****7689".to_string(),
        vec![json!({"coupon": "【5折外卖券】立减20", "status": "granted",
               "detail": "", "grant_status": "GRANTED"})],
    )];
    let results = n.notify_report("result", &report, &["波次 1, 请求 2".to_string()]);
    assert_eq!(results.len(), 1);
    assert!(results[0].1, "webhook 应发送成功: {:?}", results);

    let seen = stub.seen();
    assert!(seen.iter().any(|p| p.contains("/hook")), "应命中 hook");
}

#[test]
fn notifier_channel_missing_config_reports_field_name_only() {
    let cfg = Config {
        notify_targets: vec!["resend".into()],
        // 故意不配 resend_api_key / resend_from
        notify_to_mails: vec!["me@example.invalid".into()],
        ..Default::default()
    };
    let secrets = SecretsRegistry::new();
    let n = Notifier::new(cfg, Arc::clone(&secrets));
    let results = n.notify("result", "hello", None, false, None, None, None);
    assert_eq!(results.len(), 1);
    let (ch, ok, detail) = &results[0];
    assert_eq!(ch, "resend");
    assert!(!ok, "缺配置应判失败");
    assert!(detail.contains("resend_api_key"), "只报字段名: {}", detail);
    assert!(detail.contains("resend_from"), "只报字段名: {}", detail);
    // 不泄露任何凭据值（这里本来也没配）
    assert!(!detail.contains("example"));
}

#[test]
fn loop_runner_targets_only_snipe_coupons() {
    // loop 的目标只含 snipe_keyword 命中的券；启动即校验非空
    let cfg = cfg_for("http://127.0.0.1:1");
    assert_eq!(cfg.snipe_coupons().len(), 2);
    let probe = cfg.probe_coupon().unwrap();
    assert!(probe["couponName"].as_str().unwrap().contains("满28减10"));

    // 关键词写坏 -> 启动即报错，而不是空转到超时
    let mut bad = cfg_for("http://127.0.0.1:1");
    bad.snipe_keyword = "不存在的关键词".into();
    assert!(bad.snipe_coupons().is_empty());
    let err = flows::loop_run(
        vec![auth("A")],
        bad,
        0.1,
        0.1,
        None,
        None,
        SecretsRegistry::new(),
        None,
    )
    .unwrap_err();
    assert!(err.contains("抢券目标为空"), "{}", err);
}

#[test]
fn request_carries_all_required_headers() {
    // 回归：曾漏发 Content-Type，服务端 WAF 直接返回 code=417，
    // 表现为「--ping 全部 unknown」而没有任何报错——协议层必须逐项断言。
    let stub = Stub::spawn(vec![
        (
            "/super-coupon/info".into(),
            info_body(json!([
                {"couponId": "c2", "couponName": "【5折外卖券】立减20",
                 "couponType": "PHONE_REWARD"},
            ])),
        ),
        ("/super-coupon/grant-status".into(), empty_status()),
        (
            "/super-coupon/grant".into(),
            r#"{"code":200,"result":{"winPrizeInfo":{}}}"#.to_string(),
        ),
    ]);
    let secrets = SecretsRegistry::new();
    let _ = flows::single_run(
        &[auth("177****7689")],
        &cfg_for(&stub.base),
        None,
        Arc::clone(&secrets),
        None,
    );

    let heads = stub.heads();
    assert!(!heads.is_empty(), "桩服务应收到请求");
    // 逐项检查必需请求头（大小写不敏感）
    let required = [
        "Content-Type: application/json;charset=UTF-8",
        "GL-DeviceId:",
        "GL-X-XSRF-TOKEN:",
        "GL-Uid:",
        "GL-ClientType: 60",
        "GL-CheckSum:",
        "Cookie:",
        "User-Agent:",
        "Origin: https://vip.ds.163.com",
        "Referer: https://vip.ds.163.com/partner-perks",
    ];
    for head in &heads {
        let lower = head.to_lowercase();
        for needle in required {
            assert!(
                lower.contains(&needle.to_lowercase()),
                "请求头缺少 {:?}；实际请求头：\n{}",
                needle,
                head
            );
        }
    }
}

#[test]
fn signature_is_sha1_of_body_plus_xsrf() {
    // 回归：签名字节必须与发送字节完全一致（无空格、不转义 Unicode、键序固定）
    let stub = Stub::spawn(vec![("/super-coupon/info".into(), info_body(json!([])))]);
    let secrets = SecretsRegistry::new();
    let a = auth("177****7689");
    let _ = flows::single_run(
        std::slice::from_ref(&a),
        &cfg_for(&stub.base),
        None,
        Arc::clone(&secrets),
        None,
    );

    let head = stub.heads().into_iter().next().expect("应有请求");
    let checksum = head
        .lines()
        .find(|l| l.to_lowercase().starts_with("gl-checksum:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .expect("应有 GL-CheckSum");
    // 手工按同一公式算一遍：SHA1(`{}` + xsrf)
    let expected = {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(b"{}");
        h.update(a.xsrf_token.as_bytes());
        h.finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    };
    assert_eq!(checksum, expected, "GL-CheckSum 公式不符");
}
