#!/usr/bin/env python3
"""消息通知：Telegram / 飞书 / 钉钉 / Server酱 / 邮件 / 通用 webhook。

三条边界：

1. **best-effort**——通知是旁路，发送失败绝不影响抢券主流程；失败只在 stderr
   记一行（脱敏、限长）。
2. **通知凭据同等保密**——bot token、webhook URL（token 常在 query 里）、
   sendkey、加签 secret、SMTP 密码/授权码全部登记进脱敏表。
3. **可注入**——session 与 smtp_factory 都能替换（与 ApiClient 同样的做法），
   测试全 mock，不发真实请求。

事件由 `notify_events` 过滤：result 抢券结果 / auth_expired 登录态失效 /
health 健康检查异常 / rate_limited 命中限流 / error 运行异常。
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

CHANNELS = ("telegram", "feishu", "dingtalk", "serverchan", "email", "webhook")

# 每个通道必需的配置项（缺失时只报字段名，不报值）
REQUIRED = {
    "telegram": ("telegram_bot_token", "telegram_chat_id"),
    "feishu": ("feishu_webhook",),
    "dingtalk": ("dingtalk_webhook",),
    "serverchan": ("serverchan_send_key",),
    "email": ("email_smtp_host", "email_to"),
    "webhook": ("notify_webhook_url",),
}

# 各通道「业务成功」的判定：响应 JSON 里表示成功的字段与取值
SUCCESS_RULES = {
    "telegram": ("ok", (True,)),
    "feishu": ("code", (0,)),
    "dingtalk": ("errcode", (0,)),
    "serverchan": ("code", (0, "0")),
}

EVENT_TITLES = {
    "result": "CHAGEE 抢券结果",
    "auth_expired": "CHAGEE 登录态失效",
    "rate_limited": "CHAGEE 命中限流",
    "health": "CHAGEE 健康检查",
    "error": "CHAGEE 运行异常",
}

_SECRET_FIELDS = ("telegram_bot_token", "telegram_chat_id", "feishu_webhook",
                  "dingtalk_webhook", "dingtalk_secret", "serverchan_send_key",
                  "notify_webhook_url", "email_password", "email_user",
                  "email_from")


def mask_label(label):
    """把 label 里的长数字（多为手机号）掩成 前3****后2。

    通知会推给第三方服务，账号标识默认不带完整手机号。"""
    return re.sub(r"\d{4,}",
                  lambda m: m.group()[:3] + "****" + m.group()[-2:],
                  str(label))


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
        for key in _SECRET_FIELDS:
            self.secrets.register(getattr(self.cfg, key, None))
        # webhook URL 里的 token 常以 query 参数出现，把参数值也登记
        for key in ("feishu_webhook", "dingtalk_webhook", "notify_webhook_url"):
            url = getattr(self.cfg, key, None) or ""
            for _, v in urllib.parse.parse_qs(
                    urllib.parse.urlsplit(url).query).items():
                for item in v:
                    self.secrets.register(item)

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

    def notify(self, event, text, title=None):
        """发送一个事件，返回 [(channel, ok, detail)]；本身永不抛异常。"""
        if not self.enabled or event not in tuple(self.cfg.notify_events):
            return []
        title = title or EVENT_TITLES.get(event, "CHAGEE 通知")
        results = []
        for channel in self.targets:
            missing = [k for k in REQUIRED[channel]
                       if not getattr(self.cfg, k, None)]
            if missing:
                results.append((channel, False, "缺少配置: " + ", ".join(missing)))
                continue
            try:
                self._send(channel, event, title, text)
                results.append((channel, True, "已发送"))
            except Exception as e:                 # best-effort：异常不外泄
                results.append((channel, False,
                                self.secrets.redact(str(e))[:120]))
        for channel, ok, detail in results:
            self.log("通知[%s] %s: %s"
                     % (event, channel, detail if ok else "失败 " + detail))
        return results

    def notify_report(self, event, report, extra_lines=()):
        """把 {label: [item...]} 形式的报告摘要发出去（label 默认掩码）。"""
        lines = []
        statuses = {}
        for label, items in (report or {}).items():
            who = mask_label(label) if self.cfg.notify_mask_labels else label
            parts = []
            for item in items or []:
                status = item.get("status") or "?"
                statuses[status] = statuses.get(status, 0) + 1
                parts.append(status)
            lines.append("%s: %s" % (who, " ".join(parts) if parts else "无结果"))
        body = "\n".join(list(lines) + list(extra_lines))
        if statuses:
            body = "状态分布 %s\n%s" % (statuses, body)
        return self.notify(event, body)

    # -- 各通道实现 -------------------------------------------------------

    def _send(self, channel, event, title, text):
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
            self._send_email(title, text)
        elif channel == "webhook":
            self._post(cfg.notify_webhook_url, None,
                       json={"event": event, "title": title, "text": text})
        else:
            raise ValueError("未知通知通道: %s" % channel)

    def _post(self, url, channel, json=None, data=None):
        r = self.session.post(url, json=json, data=data,
                              timeout=self.cfg.notify_timeout)
        if getattr(r, "status_code", 200) >= 400:
            raise RuntimeError("HTTP %s: %s"
                               % (r.status_code,
                                  self.secrets.redact(r.text)[:120]))
        rule = SUCCESS_RULES.get(channel) if channel else None
        if not rule:
            return
        # 这些 webhook 常见「HTTP 200 但业务失败」，不看 body 会把失败当成功
        try:
            payload = r.json()
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        field, good = rule
        if field not in payload:
            return
        value = payload[field]
        if value not in good:
            raise RuntimeError("通道返回失败 %s=%s: %s"
                               % (field, value,
                                  self.secrets.redact(str(payload))[:120]))

    def _open_smtp(self, host, port, use_ssl):
        if self.smtp_factory is not None:
            return self.smtp_factory(host, port, use_ssl)
        cls = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        return cls(host, port, timeout=self.cfg.notify_timeout)

    def _send_email(self, title, text):
        cfg = self.cfg
        host, port = _split_smtp(cfg.email_smtp_host)
        port = port or cfg.email_smtp_port
        if not host:
            raise RuntimeError("缺少 SMTP 主机配置")
        message = EmailMessage()
        message["From"] = cfg.email_from or cfg.email_user or "chagee@localhost"
        message["To"] = ", ".join(cfg.email_to)
        message["Subject"] = "%s%s" % (cfg.email_subject_prefix, title)
        message.set_content(text)
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
