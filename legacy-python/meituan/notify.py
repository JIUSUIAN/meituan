#!/usr/bin/env python3
"""消息通知：Telegram / 飞书 / 钉钉 / Server酱 / 邮件(SMTP) / Resend / 通用 webhook。

三条边界：

1. **best-effort**——通知是旁路，发送失败绝不影响抢券主流程；失败只在 stderr
   记一行（脱敏、限长）。
2. **通知凭据同等保密**——bot token、webhook URL（token 常在 query 里）、
   sendkey、加签 secret、SMTP 密码/授权码全部登记进脱敏表。
3. **可注入**——session 与 smtp_factory 都能替换（与 ApiClient 同样的做法），
   测试全 mock，不发真实请求。

事件由 `notify_events` 过滤：result 整体结果 / account_result 单账号领取详情
（一账号一条）/ auth_expired 登录态失效 / health 健康检查异常 /
rate_limited 命中限流。
"""
import base64
import hashlib
import hmac
import re
import smtplib
import sys
import time
import urllib.parse
from email.message import EmailMessage

import requests

from .config import Config
from .security import GLOBAL_SECRETS
from . import report_html

CHANNELS = ("telegram", "feishu", "dingtalk", "serverchan", "email",
            "resend", "webhook")

# 每个通道必需的配置项（缺失时只报字段名，不报值）
REQUIRED = {
    "telegram": ("telegram_bot_token", "telegram_chat_id"),
    "feishu": ("feishu_webhook",),
    "dingtalk": ("dingtalk_webhook",),
    "serverchan": ("serverchan_send_key",),
    "email": ("email_smtp_host", "notify_to_mails"),
    "resend": ("resend_api_key", "resend_from", "notify_to_mails"),
    "webhook": ("notify_webhook_url",),
}

# 各通道「业务成功」的判定：响应 JSON 里表示成功的字段与取值
SUCCESS_RULES = {
    "telegram": ("ok", (True,)),
    "feishu": ("code", (0,)),
    "dingtalk": ("errcode", (0,)),
    "serverchan": ("code", (0, "0")),
}

# 可由单次调用覆盖收件人的通道：字段 -> 覆盖入口
RECIPIENT_FIELDS = {"email": "notify_to_mails", "resend": "notify_to_mails"}

EVENT_TITLES = {
    "result": "美团大额券 · 抢券结果",
    "account_result": "美团大额券 · 账号领取详情",
    "auth_expired": "美团大额券 登录态失效",
    "rate_limited": "美团大额券 命中限流",
    "health": "美团大额券 健康检查",
    "error": "美团大额券 运行异常",
    "test": "美团大额券 通知测试",
}

_SECRET_FIELDS = ("telegram_bot_token", "telegram_chat_id", "feishu_webhook",
                  "dingtalk_webhook", "dingtalk_secret", "serverchan_send_key",
                  "notify_webhook_url", "email_password", "email_user",
                  "email_from", "resend_api_key")


def mask_label(label):
    """把 label 里的长数字（多为手机号）掩成 前3****后2。

    通知会推给第三方服务，账号标识默认不带完整手机号。
    label 里已经带 * 的（用户自己打过码，如 177****7689）原样返回——
    二次打码会让标识糊成一团，认不出是哪个账号。"""
    text = str(label)
    if "*" in text:
        return text
    return re.sub(r"\d{4,}",
                  lambda m: m.group()[:3] + "****" + m.group()[-2:],
                  text)


def register_config_secrets(cfg, secrets=None):
    """把配置里的通知凭据登记进脱敏表。

    Notifier 构造时会调用，但 CLI 在 load_config 之后就该立刻调用一次——
    否则「构造 Notifier 之前」报出的配置错误可能把管理密码原样打出来。"""
    registry = secrets if secrets is not None else GLOBAL_SECRETS
    for key in _SECRET_FIELDS:
        registry.register(getattr(cfg, key, None))
    # webhook URL 里的 token 常以 query 参数出现，把参数值也登记
    for key in ("feishu_webhook", "dingtalk_webhook", "notify_webhook_url"):
        url = getattr(cfg, key, None) or ""
        for values in urllib.parse.parse_qs(
                urllib.parse.urlsplit(url).query).values():
            for item in values:
                registry.register(item)


def account_mails(auth):
    """认证条目里自带的通知邮箱（`notify_mail`，字符串或列表），没有则 None。

    收件邮箱放凭据文件而不是配置文件：一个账号一份收件箱，且天然不进版本库。"""
    value = auth.get("notify_mail") or auth.get("notify_mailbox")
    if not value:
        return None
    if isinstance(value, str):
        return (value,)
    return tuple(v for v in value if v)


def account_routing(auth, warn=None):
    """账号条目的通知路由，返回 (targets, to_mails)，缺省项为 None=沿用全局。

    两种写法：

        "notify": {"targets": ["email"], "to": ["a@x.com"]}   完整形式
        "notify_mail": "a@x.com"                               只换收件人的简写

    通道凭据仍留在全局配置里，账号条目只决定「这个账号的详情走哪条通道、
    发给谁」。spec 写错时通过 warn 回调报一行并回落全局路由——通知配置错误
    不该拖垮抢券。"""
    spec = auth.get("notify")
    if spec is None:
        return None, account_mails(auth)
    if not isinstance(spec, dict):
        if warn:
            warn("账号 %s 的 notify 应为对象（targets / to），已改用全局通道"
                 % auth.get("label"))
        return None, None
    targets = (spec.get("targets") or spec.get("channels")
               or spec.get("channel"))
    if isinstance(targets, str):
        targets = [targets]
    to = (spec.get("to") or spec.get("to_mail") or spec.get("to_mails")
          or account_mails(auth))
    if isinstance(to, str):
        to = [to]
    return (tuple(targets) if targets else None,
            tuple(v for v in (to or ()) if v) or None)


def dingtalk_signed_url(webhook, secret, timestamp=None):
    """钉钉自定义机器人「加签」：timestamp + HMAC-SHA256 拼进 query。"""
    ts = str(int(round((timestamp if timestamp is not None else time.time())
                       * 1000)))
    digest = hmac.new(secret.encode("utf-8"),
                      ("%s\n%s" % (ts, secret)).encode("utf-8"),
                      hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(digest))
    sep = "&" if "?" in webhook else "?"
    return "%s%stimestamp=%s&sign=%s" % (webhook, sep, ts, sign)


def _split_smtp(value):
    """'smtp.qq.com:465' -> ('smtp.qq.com', 465)；无端口返回 (host, None)。"""
    if ":" in value:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return value, None


class Notifier:
    """按配置把事件推给若干通道；未配置任何通道时整体禁用（零副作用）。"""

    def __init__(self, targets=None, config=None, secrets=None, session=None,
                 log=None, smtp_factory=None):
        self.cfg = config or Config()
        self.secrets = secrets if secrets is not None else GLOBAL_SECRETS
        # 未显式指定就跟着配置走（Notifier(config=cfg) 与 from_config 等价）
        requested = tuple(self.cfg.notify_targets if targets is None
                          else targets)
        self.targets = [t for t in requested if t in CHANNELS]
        unknown = [t for t in requested if t not in CHANNELS]
        self._owns_session = session is None
        self.session = session if session is not None else requests.Session()
        self.smtp_factory = smtp_factory
        self._log_line = log
        self.enabled = bool(self.cfg.notify_enabled and self.targets)
        self._register_secrets()
        if unknown:
            # 只报名字：拼错的通道名里可能正好含 token 片段
            self.log("通知通道名无法识别，已忽略: %s（可用: %s）"
                     % (", ".join(unknown), ", ".join(CHANNELS)))

    @classmethod
    def from_config(cls, config=None, secrets=None, session=None, log=None,
                    smtp_factory=None):
        return cls(config=config or Config(), secrets=secrets, session=session,
                   log=log, smtp_factory=smtp_factory)

    def _register_secrets(self):
        register_config_secrets(self.cfg, self.secrets)

    def close(self):
        if self._owns_session:
            try:
                self.session.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def log(self, msg):
        if self._log_line is not None:
            self._log_line(msg)
            return
        from .flows import beijing_ts  # 延迟导入：避免与 flows 循环依赖
        print("%s %s" % (beijing_ts(), msg), file=sys.stderr, flush=True)

    # -- 对外入口 ---------------------------------------------------------

    def notify(self, event, text, title=None, force=False, to_mails=None,
               targets=None, html=None):
        """发送一个事件，返回 [(channel, ok, detail)]；本身永不抛异常。

        force=True 时跳过 notify_events 过滤（自检用）。
        targets/to_mails 来自账号条目的路由。
        html 给定时，邮件类通道以它作为富文本正文（text 作纯文本替身）。"""
        if not self.cfg.notify_enabled:
            return []
        if targets is None and not self.targets:
            return []          # 全局没配通道：汇总/健康类事件没有去处
        if not force and event not in tuple(self.cfg.notify_events):
            return []
        title = title or EVENT_TITLES.get(event, "美团 通知")
        if targets is not None:
            unknown = [t for t in targets if t not in CHANNELS]
            if unknown:
                self.log("通知[%s] 账号指定了无法识别的通道，已忽略: %s"
                         % (event, ", ".join(unknown)))
            channels = tuple(t for t in targets if t in CHANNELS)
        else:
            channels = tuple(self.targets)
        results = []
        for channel in channels:
            # 收件人可由本次调用覆盖，覆盖时不再要求全局配置里有它
            fields = [f for f in REQUIRED[channel]
                      if not (to_mails and f == RECIPIENT_FIELDS.get(channel))]
            missing = [f for f in fields if not getattr(self.cfg, f, None)]
            if missing:
                results.append((channel, False, "缺少配置: " + ", ".join(missing)))
                continue
            try:
                self._send(channel, event, title, text, to_mails=to_mails,
                           html=html)
                results.append((channel, True, "已发送"))
            except Exception as e:                 # best-effort：异常不外泄
                results.append((channel, False,
                                self.secrets.redact(str(e))[:120]))
        for channel, ok, detail in results:
            self.log("通知[%s] %s: %s"
                     % (event, channel, detail if ok else "失败 " + detail))
        return results

    def _stamp(self):
        from .flows import beijing_ts      # 延迟导入：避免与 flows 循环依赖
        return "生成时间 " + beijing_ts() + "（北京时间）"

    def _render_html(self, renderer, *args, **kwargs):
        """按 notify_html 开关渲染报告页；关闭或渲染异常时返回 None（退回纯文本）。"""
        if not self.cfg.notify_html:
            return None
        try:
            return renderer(*args, **kwargs)
        except Exception:
            return None

    def _safe_text(self, value):
        """动态字段脱敏：HTML 侧与纯文本侧必须同一口径。

        券名 / detail / grant_status 都来自远端响应，服务端可能把已登记的凭据
        回显出来；纯文本侧早就有 redact，HTML 侧不能例外。"""
        if value is None:
            return ""
        return self.secrets.redact(str(value))

    def _safe_items(self, items):
        """给 HTML 渲染用的条目副本：动态文本字段先脱敏，不改动调用方数据。

        返回副本而不是原地改——同一份 items 还要用于纯文本与调用方统计。"""
        out = []
        for item in items or []:
            if not isinstance(item, dict):
                out.append(item)
                continue
            safe = dict(item)
            for key in ("coupon", "coupon_type", "status", "grant_status",
                        "detail"):
                if key in safe:
                    safe[key] = self._safe_text(safe[key])
            out.append(safe)
        return out

    def _safe_lines(self, lines):
        return [self._safe_text(x) for x in (lines or ())]

    def notify_report(self, event, report, extra_lines=()):
        """把 {label: [item...]} 形式的报告摘要发出去（label 默认掩码）。"""
        lines = []
        statuses = {}
        masked = {}
        for label, items in (report or {}).items():
            who = mask_label(label) if self.cfg.notify_mask_labels else label
            masked[self._safe_text(who)] = self._safe_items(items)
            parts = []
            for item in items or []:
                status = item.get("status") or "?"
                statuses[status] = statuses.get(status, 0) + 1
                parts.append(status)
            lines.append("%s: %s" % (who, " ".join(parts) if parts else "无结果"))
        body = "\n".join(list(lines) + list(extra_lines))
        if statuses:
            body = "状态分布 %s\n%s" % (statuses, body)
        html = self._render_html(report_html.render_summary, masked,
                                 extra_lines=self._safe_lines(extra_lines),
                                 meta=self._safe_text(self._stamp()))
        return self.notify(event, body, html=html)

    def notify_account(self, label, items, timings=None, extra_lines=(),
                       to_mails=None, targets=None):
        """单账号一条消息：每张券一行，可带发送时刻/耗时/服务端最终状态。

        targets/to_mails 给定时按该账号自己的路由发送（账号条目里的 notify）。"""
        who = (mask_label(label) if self.cfg.notify_mask_labels
               else str(label))
        lines = []
        for item in items or []:
            name = item.get("coupon") or "（无券名）"
            status = item.get("status") or "?"
            line = "%s: %s" % (name, status)
            timing = (timings or {}).get(name)
            if timing:
                line += "（发送 %s，耗时 %.2fs）" % (timing[0], timing[1])
            if item.get("grant_status"):
                line += " 服务端 %s" % item["grant_status"]
            detail = str(item.get("detail") or "").strip()
            # granted 的 detail 是奖品 JSON，噪音大；只在非成功时带上原因
            if detail and status != "granted":
                line += " | %s" % self.secrets.redact(detail)[:80]
            lines.append(line)
        if not lines:
            lines.append("无结果")
        body = "\n".join([who] + lines + list(extra_lines))
        html = self._render_html(
            report_html.render_account, self._safe_text(who),
            self._safe_items(items), timings=timings,
            extra_lines=self._safe_lines(extra_lines),
            meta=self._safe_text(self._stamp()))
        return self.notify("account_result", body, to_mails=to_mails,
                           targets=targets, html=html)

    # -- 各通道实现 -------------------------------------------------------

    def _send(self, channel, event, title, text, to_mails=None, html=None):
        cfg = self.cfg
        body = "%s\n%s" % (title, text)
        if channel == "telegram":
            self._post("https://api.telegram.org/bot%s/sendMessage"
                       % cfg.telegram_bot_token, channel,
                       json={"chat_id": cfg.telegram_chat_id, "text": body,
                             "disable_web_page_preview": True})
        elif channel == "feishu":
            self._post(cfg.feishu_webhook, channel,
                       json={"msg_type": "text", "content": {"text": body}})
        elif channel == "dingtalk":
            url = cfg.dingtalk_webhook
            if cfg.dingtalk_secret:
                url = dingtalk_signed_url(url, cfg.dingtalk_secret)
            self._post(url, channel,
                       json={"msgtype": "text", "text": {"content": body}})
        elif channel == "serverchan":
            self._post("https://sctapi.ftqq.com/%s.send"
                       % cfg.serverchan_send_key, channel,
                       data={"title": title, "desp": text})
        elif channel == "email":
            self._send_email(title, text, to_mails=to_mails, html=html)
        elif channel == "resend":
            self._send_resend(title, text, to_mails=to_mails, html=html)
        elif channel == "webhook":
            self._post(cfg.notify_webhook_url, None,
                       json={"event": event, "title": title, "text": text})
        else:
            raise ValueError("未知通知通道: %s" % channel)

    def _post(self, url, channel, json=None, data=None, headers=None):
        """发一次请求并做通用错误判定，返回解析后的 JSON（或 None）。

        这些 webhook 常见「HTTP 200 但业务失败」，所以除了状态码还要看 body
        里的成功标志（SUCCESS_RULES），否则会把没送达当成功。"""
        r = self.session.post(url, json=json, data=data, headers=headers,
                              timeout=self.cfg.notify_timeout)
        if getattr(r, "status_code", 200) >= 400:
            raise RuntimeError("HTTP %s: %s"
                               % (r.status_code,
                                  self.secrets.redact(r.text)[:120]))
        try:
            payload = r.json()
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        rule = SUCCESS_RULES.get(channel) if channel else None
        if rule:
            field, good = rule
            if field in payload and payload[field] not in good:
                raise RuntimeError("通道返回失败 %s=%s: %s"
                                   % (field, payload[field],
                                      self.secrets.redact(str(payload))[:120]))
        return payload

    def _open_smtp(self, host, port, use_ssl):
        if self.smtp_factory is not None:
            return self.smtp_factory(host, port, use_ssl)
        cls = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        return cls(host, port, timeout=self.cfg.notify_timeout)

    def _send_email(self, title, text, to_mails=None, html=None):
        cfg = self.cfg
        host, port = _split_smtp(cfg.email_smtp_host)
        port = port or cfg.email_smtp_port
        if not host:
            raise RuntimeError("缺少 SMTP 主机配置")
        recipients = tuple(to_mails or ()) or tuple(cfg.notify_to_mails or ())
        if not recipients:
            raise RuntimeError("缺少收件邮箱（notify_to_mails 或账号的 to）")
        message = EmailMessage()
        message["From"] = cfg.email_from or cfg.email_user or "meituan@localhost"
        message["To"] = ", ".join(recipients)
        message["Subject"] = "%s%s" % (cfg.email_subject_prefix,
                                       cfg.notify_subject or title)
        message.set_content(text)          # 纯文本替身，永远放在第一段
        if html:
            # multipart/alternative：不支持 HTML 的客户端退回上面的纯文本
            message.add_alternative(html, subtype="html")
        server = self._open_smtp(host, port, cfg.email_use_ssl)
        try:
            if not cfg.email_use_ssl and cfg.email_use_tls:
                server.starttls()
            if cfg.email_user:
                server.login(cfg.email_user, cfg.email_password)
            server.send_message(message)
        finally:
            try:
                server.quit()
            except Exception:
                pass

    def _send_resend(self, title, text, to_mails=None, html=None):
        """Resend API：POST https://api.resend.com/emails。

        域名在 Resend 验证过就能发，不需要 SMTP；收件人一次调用给一个列表。
        响应里有 id 才算受理，否则按失败处理。"""
        cfg = self.cfg
        recipients = tuple(to_mails or ()) or tuple(cfg.notify_to_mails or ())
        if not recipients:
            raise RuntimeError("缺少收件邮箱（notify_to_mails 或账号的 to）")
        sender = cfg.resend_from
        if "<" not in sender:
            sender = "%s <%s>" % (cfg.resend_from_name or "meituan", sender)
        payload = self._post(
            "https://api.resend.com/emails", None,
            json={"from": sender, "to": list(recipients),
                  "subject": cfg.notify_subject or title, "text": text,
                  **({"html": html} if html else {})},
            headers={"Authorization": "Bearer " + cfg.resend_api_key})
        if not (payload or {}).get("id"):
            raise RuntimeError("Resend 未返回消息 id: %s"
                               % self.secrets.redact(str(payload))[:120])
