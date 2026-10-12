//! 抢券数据的 HTML 报告页（邮件正文与本地留档共用一份渲染）。
//!
//! 对应 Python 版 `report_html.py`。版式照「美团双券卡」：米黄底、左右两张票券、
//! 中间祝贺横幅。状态全部在生成时烘进 HTML——邮件客户端不执行 JS，
//! 也不允许远程图片，所以这里只用表格 + 内联样式。
//!
//! 三条边界：自包含（无外链/图片/脚本）、动态文本一律 `escape_html`
//! （券名与 detail 都来自远端响应，不能当标记解释）、不含任何凭据值
//! （调用方在传入前已统一 `redact`，见 `notify::_safe_items`）。

use regex::Regex;
use serde_json::Value;

/// 视为「到手」的状态（含此前已领）。
pub const LIT_STATUSES: [&str; 2] = ["granted", "already_claimed"];

pub const STATUS_TEXTS: &[(&str, &str)] = &[
    ("granted", "已到手"),
    ("already_claimed", "此前已领"),
    ("out_of_stock", "已抢光"),
    ("rate_limited", "被限流"),
    ("auth_expired", "登录态失效"),
    ("failed", "没抢到"),
    ("error", "出错了"),
    ("skipped", "跳过"),
    ("direct_link", "需跳转"),
    ("pending", "未参与"),
];

pub const STATUS_COLORS: &[(&str, &str)] = &[
    ("granted", "#0b8457"),
    ("already_claimed", "#1d5bd6"),
    ("out_of_stock", "#b76b00"),
    ("rate_limited", "#8a7200"),
    ("auth_expired", "#c0392b"),
    ("failed", "#c0392b"),
    ("error", "#c0392b"),
];

pub const FONT: &str = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,\
'PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif";

/// 页面品牌标题（邮件主题由 `Config.notify_subject` 决定，两者可各自调整）。
pub const BRAND: &str = "美团大额券";

pub fn status_text(status: &str) -> String {
    STATUS_TEXTS
        .iter()
        .find(|(k, _)| *k == status)
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| status.to_string())
}

pub fn status_color(status: &str) -> String {
    STATUS_COLORS
        .iter()
        .find(|(k, _)| *k == status)
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| "#6b7280".to_string())
}

/// HTML 转义（与 Python `html.escape` 等价的最小集合）。
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 券名解析
// ---------------------------------------------------------------------------

fn full_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"满\s*(\d+)\s*减\s*(\d+)").unwrap())
}

fn cut_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"立减\s*(\d+)").unwrap())
}

fn discount_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(\d+(?:\.\d+)?)\s*折").unwrap())
}

fn digits_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d+").unwrap())
}

/// 从券名里抽出票面大字：满40减20 / 立减20 / 5折，抽不到就用整名。
pub fn amount(name: &str) -> String {
    if let Some(m) = full_re().captures(name) {
        return format!("满{}减{}", &m[1], &m[2]);
    }
    if let Some(m) = cut_re().captures(name) {
        return format!("立减{}", &m[1]);
    }
    if let Some(m) = discount_re().captures(name) {
        return format!("{}折", &m[1]);
    }
    if name.is_empty() {
        "优惠券".to_string()
    } else {
        name.to_string()
    }
}

/// 卡片顶部小标签：外卖券 / 到店券 / 手机券。
pub fn tag(name: &str, coupon_type: &str) -> String {
    let text = format!("{} {}", name, coupon_type);
    if text.contains("外卖") {
        "外卖券".into()
    } else if text.contains("到店") || text.contains("堂食") {
        "到店券".into()
    } else if coupon_type.to_uppercase() == "PHONE_REWARD" {
        "手机券".into()
    } else {
        "优惠券".into()
    }
}

pub fn is_lit(item: Option<&Value>) -> bool {
    item.and_then(|i| i.get("status"))
        .and_then(Value::as_str)
        .map(|s| LIT_STATUSES.contains(&s))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// 卡片
// ---------------------------------------------------------------------------

/// 一张票券卡。亮=暖黄描边红字；灰=去饱和配色（不用 filter，邮件端不支持）。
fn card(item: Option<&Value>, timings: &[(String, String, f64)], compact: bool) -> String {
    let item = item.cloned().unwrap_or(Value::Null);
    let status = item
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("pending")
        .to_string();
    let lit = LIT_STATUSES.contains(&status.as_str());
    let name = item
        .get("coupon")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let (bg, border, amount_color, tag_color) = if lit {
        ("#fffdf6", "#ffd85e", "#ff3b30", "#8a6a1f")
    } else {
        ("#f1f2f4", "#d8dade", "#a3a7ae", "#9aa0a6")
    };
    let btn_bg = if lit {
        "background:#ffcfa0;background:linear-gradient(180deg,#ffe08a,#ffb300);\
         color:#7a4400;"
    } else {
        "background:#e3e5e8;color:#9aa0a6;"
    };
    let btn_text = status_text(&status);

    let mut notes: Vec<String> = Vec::new();
    if let Some((send_ts, _, elapsed)) = timings.iter().find(|(n, _, _)| *n == name) {
        notes.push(format!("发送 {} · 耗时 {:.2}s", send_ts, elapsed));
    }
    if let Some(gs) = item.get("grant_status").and_then(Value::as_str) {
        notes.push(format!("服务端 {}", gs));
    }
    let detail = item
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if !detail.is_empty() && !lit {
        notes.push(escape_html(&detail.chars().take(80).collect::<String>()));
    }

    let pad = if compact { "12px 10px" } else { "16px 12px" };
    let amount_size = if compact { "24px" } else { "30px" };
    let mut out = String::from("<td valign=\"top\" style=\"padding:0 6px\">");
    out.push_str(&format!(
        "<div style=\"background:{};border:2px solid {};border-radius:18px;\
         padding:{};text-align:center;box-shadow:0 4px 14px \
         rgba(180,130,20,{}\">",
        bg,
        border,
        pad,
        if lit { "0.14)" } else { "0.05)" }
    ));
    out.push_str(&format!(
        "<div style=\"font-size:13px;color:{};font-weight:600\">{}</div>",
        tag_color,
        escape_html(&tag(
            &name,
            item.get("coupon_type")
                .and_then(Value::as_str)
                .unwrap_or("")
        ))
    ));
    out.push_str(&format!(
        "<div style=\"font-size:{};font-weight:800;color:{};\
         letter-spacing:-0.5px;margin:6px 0 2px\">{}</div>",
        amount_size,
        amount_color,
        escape_html(&amount(&name))
    ));
    if !compact {
        out.push_str(&format!(
            "<div style=\"font-size:12px;color:{};margin-bottom:12px\">{}</div>",
            tag_color,
            escape_html(if name.is_empty() {
                "（无券名）"
            } else {
                &name
            })
        ));
    }
    out.push_str(&format!(
        "<div style=\"display:inline-block;padding:{};border-radius:20px;\
         font-size:14px;font-weight:700;{}\">{}</div>",
        if compact { "5px 16px" } else { "8px 22px" },
        btn_bg,
        escape_html(&btn_text)
    ));
    if !compact && !notes.is_empty() {
        out.push_str(&format!(
            "<div style=\"font-size:11px;color:#9aa0a6;margin-top:8px;\
             line-height:1.5\">{}</div>",
            notes.join("<br>")
        ));
    }
    out.push_str("</div></td>");
    out
}

/// 中间裂缝：一列错位排布的深色小块拼出撕裂口，纯表格实现（邮件端可画）。
fn crack() -> String {
    let offsets = [
        10, 16, 6, 13, 3, 9, 17, 8, 14, 4, 11, 18, 7, 13, 2, 10, 16, 5,
    ];
    let mut cells = String::new();
    for off in offsets {
        cells.push_str(&format!(
            "<tr><td style=\"height:11px;font-size:0;line-height:0;padding:0\">\
             <div style=\"width:9px;height:12px;margin-left:{}px;background:#4a3517;\
             border-radius:3px;box-shadow:0 0 7px rgba(255,70,50,.6)\"></div>\
             </td></tr>",
            off
        ));
    }
    format!(
        "<td width=\"36\" valign=\"middle\" align=\"center\" \
             style=\"padding:0\"><table style=\"border-collapse:collapse\">{}\
             </table></td>",
        cells
    )
}

pub fn headline(lit_count: usize, total: usize) -> (String, String) {
    if total > 0 && lit_count >= total {
        ("恭喜您 抢到券了！".into(), "#ff3b30".into())
    } else if lit_count > 0 {
        (format!("差一点，只抢到 {} 张", lit_count), "#b76b00".into())
    } else {
        ("这次没抢到".into(), "#8a8f98".into())
    }
}

/// 把结果摆进左右两个卡位：按票面数字小的放左边，凑不满就留空位。
fn ordered_items(items: &[Value]) -> Vec<Value> {
    let mut v: Vec<Value> = items.to_vec();
    v.sort_by_key(|item| {
        let name = item.get("coupon").and_then(Value::as_str).unwrap_or("");
        digits_re()
            .find_iter(name)
            .last()
            .and_then(|m| m.as_str().parse::<i64>().ok())
            .unwrap_or(999)
    });
    v
}

// ---------------------------------------------------------------------------
// 页面骨架
// ---------------------------------------------------------------------------

fn page(headline: &str, headline_color: &str, kind: &str, body: &str, footer: &str) -> String {
    format!(
        "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title}</title></head>\
         <body bgcolor=\"#fdf3dd\" style=\"margin:0;padding:18px;\
         background:#fdf3dd;background:linear-gradient(180deg,#fff9e8,#fbeccb);\
         color:#1f2329;font-family:{font};font-size:14px;line-height:1.6\">\
         <div style=\"max-width:620px;margin:0 auto\">\
         <div style=\"text-align:center;margin-bottom:12px\">\
         <div style=\"font-size:18px;font-weight:900;color:#1f2329;\
         letter-spacing:2px\">{brand}</div>\
         <div style=\"font-size:26px;font-weight:900;color:{hc};\
         letter-spacing:1px;margin-top:4px\">{headline}</div>\
         <div style=\"font-size:12px;color:#8a6a1f;margin-top:2px\">{kind}</div>\
         </div>\
         <div style=\"background:#fffdf6;border:1px solid #f0e0b8;\
         border-radius:20px;padding:18px 16px;\
         box-shadow:0 10px 26px rgba(180,130,20,.12)\">{body}</div>\
         <div style=\"font-size:11px;color:#8a6a1f;text-align:center;\
         margin-top:10px\">{footer}</div></div></body></html>",
        title = escape_html(BRAND),
        font = FONT,
        brand = escape_html(BRAND),
        hc = headline_color,
        headline = escape_html(headline),
        kind = escape_html(kind),
        body = body,
        footer = escape_html(footer)
    )
}

fn cards_block(
    items: &[Value],
    timings: &[(String, String, f64)],
    compact: bool,
) -> (String, usize) {
    let ordered = ordered_items(items);
    let left = ordered.first();
    let right = ordered.get(1);
    let lit = [left, right].into_iter().filter(|it| is_lit(*it)).count();
    let mut cells = card(left, timings, compact);
    if lit < 2 {
        cells.push_str(&crack());
    } else {
        cells.push_str("<td width=\"12\" style=\"padding:0\"></td>");
    }
    cells.push_str(&card(right, timings, compact));
    (
        format!(
            "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" \
              cellpadding=\"0\" style=\"border-collapse:separate;margin:4px 0 14px\">\
              <tr>{}</tr></table>",
            cells
        ),
        lit,
    )
}

fn stat_chips(counts: &[(String, usize)]) -> String {
    if counts.is_empty() {
        return String::new();
    }
    let mut sorted = counts.to_vec();
    sorted.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let cells: Vec<String> = sorted
        .iter()
        .map(|(status, num)| {
            format!(
                "<td align=\"center\" style=\"padding:6px 10px;\
                 background:#fbf3dd;border-radius:10px\">\
                 <div style=\"font-size:18px;font-weight:800;color:{}\">{}</div>\
                 <div style=\"font-size:11px;color:#8a6a1f\">{}</div></td>",
                status_color(status),
                num,
                escape_html(&status_text(status))
            )
        })
        .collect();
    format!(
        "<table role=\"presentation\" cellspacing=\"6\" cellpadding=\"0\" \
             width=\"100%\" style=\"border-collapse:separate;margin-bottom:12px\">\
             <tr>{}</tr></table>",
        cells.join("")
    )
}

/// 账号内**全部**券的明细表：券名 + 状态（已领到的状态用亮色）。
fn coupon_list(items: &[Value]) -> String {
    if items.is_empty() {
        return "<div style=\"font-size:12px;color:#8a6a1f\">无券</div>".into();
    }
    let rows: Vec<String> = items
        .iter()
        .map(|item| {
            let status = item
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            let name = item
                .get("coupon")
                .and_then(Value::as_str)
                .unwrap_or("（无券名）");
            format!(
                "<tr><td style=\"padding:7px 8px;border-bottom:1px solid #f0e6cf;\
                 font-size:12px;color:#1f2329\">{}</td>\
                 <td align=\"right\" style=\"padding:7px 8px;\
                 border-bottom:1px solid #f0e6cf;font-size:12px;\
                 font-weight:700;color:{};white-space:nowrap\">{}</td></tr>",
                escape_html(name),
                status_color(&status),
                escape_html(&status_text(&status))
            )
        })
        .collect();
    format!(
        "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" \
             cellpadding=\"0\" style=\"border-collapse:collapse;margin:2px 0 4px\">\
             {}</table>",
        rows.join("")
    )
}

fn account_block(label: &str, items: &[Value]) -> String {
    let lit = items.iter().filter(|it| is_lit(Some(it))).count();
    let badge = if lit > 0 {
        format!("<span style=\"color:#0b8457\">领到 {} 张</span>", lit)
    } else {
        "<span style=\"color:#8a8f98\">未领到</span>".to_string()
    };
    format!(
        "<div style=\"margin:12px 0 2px;font-size:13px;color:#8a6a1f;\
             font-weight:700\">账号 {} · {}</div>{}",
        escape_html(label),
        badge,
        coupon_list(items)
    )
}

fn detail_rows(items: &[Value]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let rows: Vec<String> = items
        .iter()
        .map(|item| {
            let status = item
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            let name = item
                .get("coupon")
                .and_then(Value::as_str)
                .unwrap_or("（无券名）");
            format!(
                "<tr><td style=\"padding:6px 8px;border-bottom:1px solid #f0e6cf;\
                 font-size:12px\">{}</td>\
                 <td align=\"right\" style=\"padding:6px 8px;\
                 border-bottom:1px solid #f0e6cf;font-size:12px;\
                 font-weight:700;color:{};white-space:nowrap\">{}</td></tr>",
                escape_html(name),
                status_color(&status),
                escape_html(&status_text(&status))
            )
        })
        .collect();
    format!(
        "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" \
             cellpadding=\"0\" style=\"border-collapse:collapse;margin:6px 0 4px\">\
             {}</table>",
        rows.join("")
    )
}

fn list(extra_lines: &[String]) -> String {
    if extra_lines.is_empty() {
        return String::new();
    }
    let items: Vec<String> = extra_lines
        .iter()
        .map(|l| format!("<li>{}</li>", escape_html(l)))
        .collect();
    format!(
        "<ul style=\"margin:10px 0 0;padding-left:18px;font-size:12px;\
             color:#6b7280\">{}</ul>",
        items.join("")
    )
}

// ---------------------------------------------------------------------------
// 对外渲染入口
// ---------------------------------------------------------------------------

/// 单账号详情页：两张票券 + 溢出明细。
///
/// 卡位取排序后前两张，溢出来自同一份排序结果的剩余部分；横幅统计**全部**券——
/// 否则溢出券里的失败会让「只抢到一半」显示成「恭喜您 抢到券了」。
pub fn render_account(
    label: &str,
    items: &[Value],
    timings: &[(String, String, f64)],
    extra_lines: &[String],
    meta: &str,
) -> String {
    let items: Vec<Value> = items.to_vec();
    let ordered = ordered_items(&items);
    let (cards, _) = cards_block(&ordered, timings, false);
    let (headline, color) = headline(
        items.iter().filter(|it| is_lit(Some(it))).count(),
        items.len(),
    );
    let overflow: Vec<Value> = ordered.iter().skip(2).cloned().collect();
    let mut body = cards;
    if !overflow.is_empty() {
        body.push_str(&format!(
            "<div style=\"font-size:12px;color:#8a6a1f;font-weight:700;\
             margin-top:6px\">其他券</div>{}",
            detail_rows(&overflow)
        ));
    }
    body.push_str(&format!(
        "<div style=\"font-size:12px;color:#8a6a1f;margin-top:10px\">账号 {}</div>{}",
        escape_html(label),
        list(extra_lines)
    ));
    page(
        &headline,
        &color,
        &format!("账号领取详情 · {}", label),
        &body,
        meta,
    )
}

/// 汇总页：全局状态分布 + 每账号「全部券 + 状态」明细。
pub fn render_summary(
    report: &[(String, Vec<Value>)],
    extra_lines: &[String],
    meta: &str,
) -> String {
    let mut counts: Vec<(String, usize)> = Vec::new();
    let mut blocks = String::new();
    let mut total = 0usize;
    let mut lit_total = 0usize;
    for (label, items) in report {
        for item in items {
            let status = item
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            match counts.iter_mut().find(|(s, _)| *s == status) {
                Some(entry) => entry.1 += 1,
                None => counts.push((status.clone(), 1)),
            }
            total += 1;
            if is_lit(Some(item)) {
                lit_total += 1;
            }
        }
        blocks.push_str(&account_block(label, items));
    }
    if report.is_empty() {
        blocks.push_str(
            "<div style=\"font-size:13px;color:#8a6a1f\">\
                         无账号结果</div>",
        );
    }
    let (headline, color) = headline(lit_total, total);
    let body = format!("{}{}{}", stat_chips(&counts), blocks, list(extra_lines));
    page(&headline, &color, "抢券结果汇总", &body, meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn item(name: &str, status: &str) -> Value {
        json!({"coupon": name, "status": status, "detail": ""})
    }

    #[test]
    fn escape_html_covers_the_dangerous_set() {
        assert_eq!(
            escape_html(r#"<script>alert(1)</script>"#),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(
            escape_html(r#"a & b "c" 'd'"#),
            "a &amp; b &quot;c&quot; &#x27;d&#x27;"
        );
    }

    #[test]
    fn amount_parsing() {
        assert_eq!(amount("美团外卖 满40减20"), "满40减20");
        assert_eq!(amount("【5折外卖券】立减20"), "立减20");
        assert_eq!(amount("【5折外卖券】"), "5折");
        assert_eq!(amount("到店通用券"), "到店通用券");
        assert_eq!(amount(""), "优惠券");
    }

    #[test]
    fn tag_detection() {
        assert_eq!(tag("【5折外卖券】立减20", "PHONE_REWARD"), "外卖券");
        assert_eq!(tag("到店堂食券", ""), "到店券");
        assert_eq!(tag("通用", "PHONE_REWARD"), "手机券");
        assert_eq!(tag("通用", ""), "优惠券");
    }

    #[test]
    fn three_coupons_none_lost_or_duplicated() {
        // 修复前：卡位用排序结果、溢出错用原始序 -> 券30 丢失、券20 重复
        let html = render_account(
            "老号",
            &[
                item("券30", "failed"),
                item("券10", "granted"),
                item("券20", "granted"),
            ],
            &[],
            &[],
            "meta",
        );
        for name in ["券10", "券20", "券30"] {
            assert!(html.contains(name), "{} 应出现", name);
        }
        // 券20 只作为卡位出现两次（面额大字 + 券名小字）
        assert_eq!(
            html.matches("券20").count(),
            2,
            "券20 重复出现，溢出错仍在用原始顺序"
        );
    }

    #[test]
    fn failed_overflow_is_not_celebrated() {
        let html = render_account(
            "老号",
            &[
                item("券30", "failed"),
                item("券10", "granted"),
                item("券20", "granted"),
            ],
            &[],
            &[],
            "meta",
        );
        assert!(!html.contains("恭喜您 抢到券了！"));
        assert!(html.contains("差一点"));
        assert!(html.contains("其他券"), "超出的券要有明细表");
    }

    #[test]
    fn all_three_granted_still_celebrates() {
        let html = render_account(
            "老号",
            &[
                item("券30", "granted"),
                item("券10", "granted"),
                item("券20", "granted"),
            ],
            &[],
            &[],
            "meta",
        );
        assert!(html.contains("恭喜您 抢到券了！"));
        assert!(html.contains("券30"));
    }

    #[test]
    fn single_item_leaves_right_slot_pending() {
        let html = render_account("老号", &[item("券10", "granted")], &[], &[], "meta");
        assert!(html.contains("恭喜您 抢到券了！"));
        assert!(html.contains("未参与"));
    }

    #[test]
    fn crack_appears_only_when_not_both_lit() {
        let both = render_account(
            "老号",
            &[item("券10", "granted"), item("券20", "granted")],
            &[],
            &[],
            "m",
        );
        assert!(!both.contains("#4a3517"), "全中不应有裂缝");
        let half = render_account(
            "老号",
            &[item("券10", "granted"), item("券20", "out_of_stock")],
            &[],
            &[],
            "m",
        );
        assert!(half.contains("#4a3517"), "没抢到那侧应有裂缝");
        assert!(half.contains("#f1f2f4"), "灰卡底色");
    }

    #[test]
    fn summary_lists_every_coupon_with_its_account() {
        let html = render_summary(
            &[
                (
                    "177****7689".to_string(),
                    vec![
                        item("券10", "granted"),
                        item("券20", "granted"),
                        item("券30", "granted"),
                    ],
                ),
                (
                    "193****6704".to_string(),
                    vec![item("券10", "out_of_stock")],
                ),
            ],
            &[],
            "meta",
        );
        assert!(html.contains("账号 177****7689"));
        assert!(html.contains("账号 193****6704"));
        assert!(html.contains("领到 3 张"));
        assert!(html.contains("未领到"));
        // 汇总页不截断：3 张券都要列出来
        for name in ["券10", "券20", "券30"] {
            assert!(html.contains(name), "{} 应出现在汇总页", name);
        }
        assert!(html.contains("抢券结果汇总"));
    }

    #[test]
    fn page_is_self_contained() {
        let html = render_account("老号", &[item("券10", "granted")], &[], &[], "m");
        assert!(html.starts_with("<!doctype html>"));
        assert!(!html.to_lowercase().contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("cid:"));
    }
}
