#!/usr/bin/env python3
"""抢券数据的 HTML 报告页（邮件正文与本地留档共用一份渲染）。

版式照「美团双券卡」那张图：米黄底、左右两张票券、中间祝贺横幅。
状态全部在生成时烘进 HTML——邮件客户端不执行 JS，也不允许远程图片，
所以这里只用表格 + 内联样式：

- 两张都到手 -> 两张卡都亮，横幅「恭喜您 抢到券了！」
- 有任一边没抢到 -> 没抢到的那张变灰，中间裂一条缝（锯齿表元画出来）

三条边界：自包含（无外链/图片/脚本）、动态文本一律 html.escape（券名与
detail 都来自远端响应，不能当标记解释）、不含任何凭据值。
"""
import re
from html import escape

LIT_STATUSES = ("granted", "already_claimed")

STATUS_TEXTS = {
    "granted": "已到手",
    "already_claimed": "此前已领",
    "out_of_stock": "已抢光",
    "rate_limited": "被限流",
    "auth_expired": "登录态失效",
    "failed": "没抢到",
    "error": "出错了",
    "skipped": "跳过",
    "direct_link": "需跳转",
    "pending": "未参与",
}
STATUS_COLORS = {
    "granted": "#0b8457",
    "already_claimed": "#1d5bd6",
    "out_of_stock": "#b76b00",
    "rate_limited": "#8a7200",
    "auth_expired": "#c0392b",
    "failed": "#c0392b",
    "error": "#c0392b",
}

FONT = ("-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'PingFang SC',"
        "'Hiragino Sans GB','Microsoft YaHei',sans-serif")

# 页面品牌标题（邮件主题由 Config.notify_subject 决定，两者可各自调整）
BRAND = "美团大额券"

_FULL_RE = re.compile(r"满\s*(\d+)\s*减\s*(\d+)")
_CUT_RE = re.compile(r"立减\s*(\d+)")
_DISCOUNT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*折")


def _amount(name):
    """从券名里抽出票面大字：满40减20 / 立减20 / 5折，抽不到就用整名。"""
    text = str(name or "")
    m = _FULL_RE.search(text)
    if m:
        return "满%s减%s" % (m.group(1), m.group(2))
    m = _CUT_RE.search(text)
    if m:
        return "立减%s" % m.group(1)
    m = _DISCOUNT_RE.search(text)
    if m:
        return "%s折" % m.group(1)
    return text or "优惠券"


def _tag(name, coupon_type):
    """卡片顶部小标签：外卖券 / 到店券 这类品类线索。"""
    text = "%s %s" % (name or "", coupon_type or "")
    if "外卖" in text:
        return "外卖券"
    if "到店" in text or "堂食" in text:
        return "到店券"
    if str(coupon_type or "").upper() == "PHONE_REWARD":
        return "手机券"
    return "优惠券"


def _is_lit(item):
    return bool(item) and str(item.get("status")) in LIT_STATUSES


def _card(item, timings, compact=False):
    """一张票券卡。亮=暖黄描边红字；灰=去饱和配色（不用 filter，邮件端不支持）。

    compact 用于汇总页：只留面额与状态，不铺开发送时刻等细节。"""
    status = str((item or {}).get("status") or "pending")
    lit = status in LIT_STATUSES
    name = str((item or {}).get("coupon") or "")
    bg = "#fffdf6" if lit else "#f1f2f4"
    border = "#ffd85e" if lit else "#d8dade"
    amount_color = "#ff3b30" if lit else "#a3a7ae"
    tag_color = "#8a6a1f" if lit else "#9aa0a6"
    btn_bg = ("background:#ffcfa0;background:linear-gradient(180deg,"
              "#ffe08a,#ffb300);color:#7a4400;" if lit
              else "background:#e3e5e8;color:#9aa0a6;")
    btn_text = STATUS_TEXTS.get(status, status)
    notes = []
    timing = (timings or {}).get(name)
    if timing:
        notes.append("发送 %s · 耗时 %.2fs" % (escape(str(timing[0])),
                                              timing[1]))
    if (item or {}).get("grant_status"):
        notes.append("服务端 %s" % escape(str(item["grant_status"])))
    detail = str((item or {}).get("detail") or "").strip()
    if detail and not lit:
        notes.append(escape(detail[:80]))
    return (
        '<td valign="top" style="padding:0 6px">'
        '<div style="background:' + bg + ';border:2px solid ' + border
        + ';border-radius:18px;padding:' + ('12px 10px' if compact
                                            else '16px 12px')
        + ';text-align:center;box-shadow:0 4px 14px rgba(180,130,20,'
        + ('0.14)' if lit else '0.05)') + '">'
        '<div style="font-size:13px;color:' + tag_color
        + ';font-weight:600">' + escape(_tag(name,
                                             (item or {}).get("coupon_type")))
        + '</div>'
        '<div style="font-size:' + ('24px' if compact else '30px')
        + ';font-weight:800;color:' + amount_color
        + ';letter-spacing:-0.5px;margin:6px 0 2px">'
        + escape(_amount(name)) + '</div>'
        + ('' if compact else
           '<div style="font-size:12px;color:' + tag_color
           + ';margin-bottom:12px">' + escape(name or "（无券名）") + '</div>')
        + '<div style="display:inline-block;padding:'
        + ('5px 16px' if compact else '8px 22px')
        + ';border-radius:20px;font-size:14px;font-weight:700;' + btn_bg
        + '">' + escape(btn_text) + '</div>'
        + ('' if compact or not notes else
           '<div style="font-size:11px;color:#9aa0a6;margin-top:8px;'
           'line-height:1.5">' + '<br>'.join(notes) + '</div>')
        + '</div></td>')


def _crack():
    """中间裂缝：一列错位排布的深色小块拼出撕裂口，纯表格实现（邮件端可画）。"""
    offsets = [10, 16, 6, 13, 3, 9, 17, 8, 14, 4, 11, 18, 7, 13, 2, 10, 16, 5]
    cells = "".join(
        '<tr><td style="height:11px;font-size:0;line-height:0;padding:0">'
        '<div style="width:9px;height:12px;margin-left:%dpx;background:#4a3517;'
        'border-radius:3px;box-shadow:0 0 7px rgba(255,70,50,.6)"></div>'
        '</td></tr>' % off for off in offsets)
    return ('<td width="36" valign="middle" align="center" style="padding:0">'
            '<table style="border-collapse:collapse">' + cells
            + '</table></td>')


def _headline(lit_count, total):
    if total and lit_count >= total:
        return "恭喜您 抢到券了！", "#ff3b30"
    if lit_count:
        return "差一点，只抢到 %d 张" % lit_count, "#b76b00"
    return "这次没抢到", "#8a8f98"


def _cards_block(items_by_slot, timings, compact=False):
    """两张卡 + 中间裂缝（有任一边没抢到才裂）。"""
    left, right = items_by_slot[0], items_by_slot[1]
    lit = sum(1 for it in (left, right) if _is_lit(it))
    cells = _card(left, timings, compact=compact)
    if lit < 2:
        cells += _crack()
    else:
        cells += '<td width="12" style="padding:0"></td>'
    cells += _card(right, timings, compact=compact)
    return ('<table role="presentation" width="100%" cellspacing="0" '
            'cellpadding="0" style="border-collapse:separate;margin:4px 0 14px">'
            '<tr>' + cells + '</tr></table>'), lit


def _stat_chips(counts):
    cells = []
    for status, num in sorted(counts.items(), key=lambda kv: -kv[1]):
        color = STATUS_COLORS.get(status, "#6b7280")
        cells.append(
            '<td align="center" style="padding:6px 10px;background:#fbf3dd;'
            'border-radius:10px"><div style="font-size:18px;font-weight:800;'
            'color:%s">%d</div><div style="font-size:11px;color:#8a6a1f">%s'
            '</div></td>' % (color, num, escape(STATUS_TEXTS.get(status, status))))
    if not cells:
        return ''
    return ('<table role="presentation" cellspacing="6" cellpadding="0" '
            'width="100%" style="border-collapse:separate;margin-bottom:12px">'
            '<tr>' + "".join(cells) + '</tr></table>')


def _detail_rows(items, timings):
    rows = []
    for item in items or []:
        status = str(item.get("status") or "?")
        color = STATUS_COLORS.get(status, "#6b7280")
        rows.append(
            '<tr><td style="padding:6px 8px;border-bottom:1px solid #f0e6cf;'
            'font-size:12px">%s</td>'
            '<td align="right" style="padding:6px 8px;'
            'border-bottom:1px solid #f0e6cf;font-size:12px;font-weight:700;'
            'color:%s;white-space:nowrap">%s</td></tr>'
            % (escape(str(item.get("coupon") or "（无券名）")), color,
               escape(STATUS_TEXTS.get(status, status))))
    if not rows:
        return ''
    return ('<table role="presentation" width="100%" cellspacing="0" '
            'cellpadding="0" style="border-collapse:collapse;margin:6px 0 4px">'
            + "".join(rows) + '</table>')


def _page(headline, headline_color, kind, body, footer):
    """页面骨架：品牌标题「美团大额券」在上，状态横幅居中，报告类型作副标题。"""
    return (
        '<!doctype html><html lang="zh"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>' + escape(BRAND) + '</title></head>'
        '<body bgcolor="#fdf3dd" style="margin:0;padding:18px;background:'
        '#fdf3dd;background:linear-gradient(180deg,#fff9e8,#fbeccb);color:'
        '#1f2329;font-family:' + FONT + ';font-size:14px;line-height:1.6">'
        '<div style="max-width:620px;margin:0 auto">'
        '<div style="text-align:center;margin-bottom:12px">'
        '<div style="font-size:18px;font-weight:900;color:#1f2329;'
        'letter-spacing:2px">' + escape(BRAND) + '</div>'
        '<div style="font-size:26px;font-weight:900;color:' + headline_color
        + ';letter-spacing:1px;margin-top:4px">' + escape(headline) + '</div>'
        '<div style="font-size:12px;color:#8a6a1f;margin-top:2px">'
        + escape(kind) + '</div></div>'
        '<div style="background:#fffdf6;border:1px solid #f0e0b8;'
        'border-radius:20px;padding:18px 16px;'
        'box-shadow:0 10px 26px rgba(180,130,20,.12)">' + body + '</div>'
        '<div style="font-size:11px;color:#8a6a1f;text-align:center;'
        'margin-top:10px">' + escape(footer) + '</div>'
        '</div></body></html>')


def _slots(items):
    """把结果摆进左右两个卡位：按票面数字小的放左边，凑不满就留空位。"""
    def key(item):
        digits = re.findall(r"\d+", str(item.get("coupon") or ""))
        return int(digits[-1]) if digits else 999
    ordered = sorted(items or [], key=key)
    slots = [None, None]
    for i in range(min(2, len(ordered))):
        slots[i] = ordered[i]
    return slots


def render_account(label, items, timings=None, extra_lines=(), meta="",
                   footer=None):
    """单账号详情页：两张票券 + 溢出明细。

    两张卡本身已说清每张券的状态，正好两张券时不再重复列状态分布与明细表；
    只有超出卡位的券才补一张「其他券」表。"""
    items = list(items or [])
    slots = _slots(items)
    cards, lit = _cards_block(slots, timings)
    headline, color = _headline(lit, sum(1 for s in slots if s))
    overflow = items[2:]
    body = cards
    if overflow:
        body += ('<div style="font-size:12px;color:#8a6a1f;font-weight:700;'
                 'margin-top:6px">其他券</div>'
                 + _detail_rows(overflow, timings))
    body += ('<div style="font-size:12px;color:#8a6a1f;margin-top:10px">账号 '
             + escape(str(label)) + '</div>' + _list(extra_lines))
    return _page(headline, color, "账号领取详情 · " + str(label), body,
                 footer or meta or "")


def render_summary(report, extra_lines=(), meta="", footer=None, title=None):
    """汇总页：全局状态分布 + 每账号一组紧凑双券卡。"""
    report = report or {}
    counts = {}
    blocks = []
    for label, items in report.items():
        for item in items or []:
            status = str(item.get("status") or "?")
            counts[status] = counts.get(status, 0) + 1
        slots = _slots(items)
        cards, lit = _cards_block(slots, None, compact=True)
        blocks.append(
            '<div style="font-size:12px;color:#8a6a1f;font-weight:700;'
            'margin:10px 0 2px">账号 ' + escape(str(label)) + '</div>' + cards)
    if not blocks:
        blocks.append('<div style="font-size:13px;color:#8a6a1f">'
                      '无账号结果</div>')
    total_items = sum(len(v or []) for v in report.values())
    lit_total = sum(1 for v in report.values() for it in (v or [])
                    if _is_lit(it))
    headline, color = _headline(lit_total, total_items)
    body = _stat_chips(counts) + "".join(blocks) + _list(extra_lines)
    return _page(headline, color, title or "抢券结果汇总", body,
                 footer or meta or "")


def _list(extra_lines):
    if not extra_lines:
        return ''
    return ('<ul style="margin:10px 0 0;padding-left:18px;font-size:12px;'
            'color:#6b7280">' + "".join(
                '<li>%s</li>' % escape(str(line))
                for line in extra_lines) + '</ul>')
