#!/usr/bin/env python3
"""通知模块测试（1.11.0）：各通道载荷形状、加签、脱敏、失败隔离、事件过滤。

全部 mock（注入假 session / 假 SMTP），不发真实请求。
运行：python -m unittest discover -s tests -t . -v
"""
import argparse
import contextlib
import io
import json
import unittest
from unittest import mock

import requests

from chagee import flows
from chagee.config import Config, load_config
from chagee.models import Coupon
from chagee.notify import (CHANNELS, REQUIRED, Notifier, account_mails,
                           account_routing, dingtalk_signed_url, mask_label,
                           register_config_secrets)
from chagee.security import GLOBAL_SECRETS

WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/abc123def456789"
DING = "https://oapi.dingtalk.com/robot/send?access_token=DTOKEN123456789"


class FakeResp:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload or {})

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    def __init__(self, resp=None, error=None, get_resp=None):
        self.calls = []
        self.gets = []
        self.resp = resp if resp is not None else FakeResp(200, {"code": 0})
        self.get_resp = get_resp if get_resp is not None else FakeResp(
            200, text="OK")
        self.error = error

    def post(self, url, json=None, data=None, headers=None, timeout=None):
        self.calls.append({"url": url, "json": json, "data": data,
                           "headers": headers, "timeout": timeout})
        if self.error is not None:
            raise self.error
        return self.resp

    def get(self, url, headers=None, timeout=None):
        self.gets.append({"url": url, "headers": headers, "timeout": timeout})
        if self.error is not None:
            raise self.error
        return self.get_resp

    def close(self):
        pass


class RecordingSMTP:
    """假 SMTP：只记调用与邮件对象，绝不记密码。"""

    def __init__(self, log, host, port, use_ssl):
        self.log = log
        self.log.append(("connect", host, port, use_ssl))
        self.sent = []

    def starttls(self):
        self.log.append("starttls")

    def login(self, user, password):
        self.log.append(("login", user))     # 故意不记 password

    def send_message(self, message):
        self.sent.append(message)
        self.log.append(("send", message["Subject"]))

    def quit(self):
        self.log.append("quit")


def cfg_with(**over):
    base = dict(notify_targets=("telegram",), notify_events=("result",),
                telegram_bot_token="BOT777SECRET", telegram_chat_id="44556677",
                feishu_webhook=WEBHOOK, dingtalk_webhook=DING,
                dingtalk_secret="SEC123SECRET",
                serverchan_send_key="SCT555SECRET",
                notify_webhook_url="https://example.com/hook?k=WQB666SECRET")
    return Config(**dict(base, **over))


class NotifyChannelShapeTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)

    def _notify_one(self, channel, resp=None, error=None, **over):
        session = FakeSession(resp=resp, error=error)
        notifier = Notifier(targets=(channel,), config=cfg_with(**over),
                            session=session, log=lambda msg: None)
        results = notifier.notify("result", "正文内容")
        return results, session

    def test_telegram_payload(self):
        results, session = self._notify_one(
            "telegram", resp=FakeResp(200, {"ok": True}))
        self.assertTrue(results[0][1])
        call = session.calls[0]
        self.assertEqual("https://api.telegram.org/botBOT777SECRET/sendMessage",
                         call["url"])
        self.assertEqual("44556677", call["json"]["chat_id"])
        self.assertIn("正文内容", call["json"]["text"])

    def test_feishu_payload(self):
        results, session = self._notify_one("feishu",
                                            resp=FakeResp(200, {"code": 0}))
        self.assertTrue(results[0][1])
        self.assertEqual(session.calls[0]["url"], WEBHOOK)
        self.assertEqual("text", session.calls[0]["json"]["msg_type"])
        self.assertIn("正文内容",
                      session.calls[0]["json"]["content"]["text"])

    def test_dingtalk_signs_url(self):
        results, session = self._notify_one("dingtalk",
                                            resp=FakeResp(200, {"errcode": 0}))
        self.assertTrue(results[0][1])
        url = session.calls[0]["url"]
        self.assertIn("timestamp=", url)
        self.assertIn("sign=", url)
        self.assertIn("access_token=DTOKEN123456789", url)

    def test_dingtalk_without_secret_is_unsigned(self):
        _, session = self._notify_one("dingtalk", dingtalk_secret="",
                                      resp=FakeResp(200, {"errcode": 0}))
        self.assertNotIn("sign=", session.calls[0]["url"])

    def test_serverchan_uses_form_data(self):
        results, session = self._notify_one("serverchan",
                                            resp=FakeResp(200, {"code": 0}))
        self.assertTrue(results[0][1])
        self.assertEqual("https://sctapi.ftqq.com/SCT555SECRET.send",
                         session.calls[0]["url"])
        self.assertEqual("正文内容", session.calls[0]["data"]["desp"])
        self.assertIsNone(session.calls[0]["json"])

    def test_generic_webhook_shape(self):
        results, session = self._notify_one("webhook",
                                            resp=FakeResp(200, {"ok": True}))
        self.assertTrue(results[0][1])
        self.assertEqual({"event", "title", "text"},
                         set(session.calls[0]["json"]))
        self.assertEqual("result", session.calls[0]["json"]["event"])


class SignedUrlTest(unittest.TestCase):
    def test_golden_signature(self):
        """固定输入的签名值钉住，防止公式被误改。"""
        url = dingtalk_signed_url(
            "https://oapi.dingtalk.com/robot/send?access_token=ABCDEFSECRET123",
            "sec123", timestamp=1700000000.0)
        self.assertEqual(
            "https://oapi.dingtalk.com/robot/send?access_token=ABCDEFSECRET123"
            "&timestamp=1700000000000"
            "&sign=amfC83c79uXxUW%2ByxwHnANQg5VhpHhnDvILAvl4GQvg%3D", url)

    def test_plain_webhook_gets_question_mark(self):
        url = dingtalk_signed_url("https://example.com/robot", "sec",
                                  timestamp=0.0)
        self.assertIn("?timestamp=0&sign=", url)


class NotifyGatingTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)

    def test_no_targets_means_disabled_and_no_calls(self):
        session = FakeSession()
        notifier = Notifier(config=cfg_with(notify_targets=()), session=session)
        self.assertFalse(notifier.enabled)
        self.assertEqual([], notifier.notify("result", "x"))
        self.assertEqual([], session.calls)
        notifier.close()

    def test_notify_enabled_false(self):
        session = FakeSession()
        notifier = Notifier(config=cfg_with(notify_enabled=False),
                            session=session)
        self.assertFalse(notifier.enabled)
        self.assertEqual([], notifier.notify("result", "x"))
        self.assertEqual([], session.calls)

    def test_event_filter(self):
        session = FakeSession()
        notifier = Notifier(config=cfg_with(notify_events=("auth_expired",)),
                            session=session, log=lambda msg: None)
        self.assertEqual([], notifier.notify("result", "x"))
        self.assertEqual(1, len(notifier.notify("auth_expired", "x")))
        self.assertEqual(1, len(session.calls))

    def test_unknown_channel_ignored_and_reported(self):
        lines = []
        session = FakeSession()
        notifier = Notifier(targets=("telegram", "飞书", "feishu"),
                            config=cfg_with(), session=session,
                            log=lines.append)
        self.assertEqual(["telegram", "feishu"], notifier.targets)
        notifier.notify("result", "x")
        self.assertTrue(any("无法识别" in line for line in lines))
        self.assertEqual(2, len(session.calls))

    def test_all_channels_covered_by_required_map(self):
        self.assertEqual(set(CHANNELS),
                         {"telegram", "feishu", "dingtalk", "serverchan",
                          "email", "resend", "webhook"})
        self.assertEqual(set(CHANNELS), set(REQUIRED))


class NotifyFailureTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)

    def test_http_5xx_reported_as_failure(self):
        session = FakeSession(resp=FakeResp(503, text="Service Unavailable"))
        notifier = Notifier(config=cfg_with(), session=session,
                            log=lambda msg: None)
        channel, ok, detail = notifier.notify("result", "x")[0]
        self.assertFalse(ok)
        self.assertIn("HTTP 503", detail)

    def test_http_200_business_failure_detected(self):
        """这些 webhook 常见 200 但业务失败，不能当成功。"""
        for channel, payload in (("telegram", {"ok": False,
                                               "description": "bad token"}),
                                 ("dingtalk", {"errcode": 310000,
                                               "errmsg": "sign not match"}),
                                 ("feishu", {"code": 19001})):
            session = FakeSession(resp=FakeResp(200, payload))
            notifier = Notifier(targets=(channel,), config=cfg_with(),
                                session=session, log=lambda msg: None)
            _, ok, detail = notifier.notify("result", "x")[0]
            self.assertFalse(ok, channel)
            self.assertIn("通道返回失败", detail)

    def test_send_exception_does_not_escape(self):
        session = FakeSession(error=requests.ConnectionError(
            "dial failed https://api.telegram.org/botBOT777SECRET/sendMessage"))
        notifier = Notifier(config=cfg_with(), session=session,
                            log=lambda msg: None)
        results = notifier.notify("result", "x")     # 不抛异常
        _, ok, detail = results[0]
        self.assertFalse(ok)
        self.assertNotIn("BOT777SECRET", detail)
        self.assertIn("***", detail)

    def test_missing_config_names_fields_not_values(self):
        notifier = Notifier(config=cfg_with(telegram_bot_token=""),
                            session=FakeSession(), log=lambda msg: None)
        _, ok, detail = notifier.notify("result", "x")[0]
        self.assertFalse(ok)
        self.assertIn("telegram_bot_token", detail)
        self.assertNotIn("BOT777SECRET", detail)
        notifier.close()


class NotifyRedactionTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)

    def test_tokens_and_webhook_secrets_never_logged(self):
        lines = []
        session = FakeSession(resp=FakeResp(200, {"code": 0}))
        notifier = Notifier(targets=("telegram", "feishu", "webhook"),
                            config=cfg_with(), session=session,
                            log=lines.append)
        notifier.notify("result", "正文")
        text = "\n".join(lines)
        for secret in ("BOT777SECRET", "abc123def456789", "SCT555SECRET",
                       "WQB666SECRET", "SEC123SECRET", "DTOKEN123456789"):
            self.assertNotIn(secret, text)
        self.assertIn("已发送", text)

    def test_failure_detail_is_redacted(self):
        lines = []
        session = FakeSession(resp=FakeResp(
            401, text={"detail": "invalid token BOT777SECRET"}))
        notifier = Notifier(config=cfg_with(), session=session,
                            log=lines.append)
        notifier.notify("result", "x")
        self.assertNotIn("BOT777SECRET", "\n".join(lines))
        self.assertIn("***", "\n".join(lines))


class EmailChannelTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)
        self.log = []
        self.smtp_cfg = dict(
            notify_targets=("email",),
            email_smtp_host="smtp.qq.com", email_smtp_port=465,
            email_use_ssl=True, email_user="sender@qq.com",
            email_password="AUTHCODE777SECRET",
            email_from="sender@qq.com", notify_to_mails=("me@example.com",),
            email_subject_prefix="[抢券] ",
        )

    def _factory(self):
        log = self.log

        def make(host, port, use_ssl):
            return RecordingSMTP(log, host, port, use_ssl)
        return make

    def test_ssl_login_and_send(self):
        notifier = Notifier(config=cfg_with(**self.smtp_cfg), session=FakeSession(),
                            smtp_factory=self._factory(), log=lambda m: None)
        results = notifier.notify("result", "抢到 2 张")
        self.assertTrue(results[0][1], results[0])
        self.assertEqual(("connect", "smtp.qq.com", 465, True), self.log[0])
        self.assertEqual(("login", "sender@qq.com"), self.log[1])
        self.assertEqual("quit", self.log[-1])
        subject = [entry[1] for entry in self.log
                   if isinstance(entry, tuple) and entry[0] == "send"][0]
        self.assertEqual("[抢券] CHAGEE 抢券结果", subject)

    def test_starttls_path_for_port_587(self):
        cfg = cfg_with(**dict(self.smtp_cfg, email_smtp_host="smtp.gmail.com:587",
                              email_use_ssl=False, email_use_tls=True))
        notifier = Notifier(config=cfg, session=FakeSession(),
                            smtp_factory=self._factory(), log=lambda m: None)
        notifier.notify("result", "x")
        self.assertIn("starttls", self.log)
        self.assertEqual(("connect", "smtp.gmail.com", 587, False), self.log[0])

    def test_password_never_recorded_or_logged(self):
        lines = []
        notifier = Notifier(config=cfg_with(**self.smtp_cfg), session=FakeSession(),
                            smtp_factory=self._factory(), log=lines.append)
        notifier.notify("result", "x")
        self.assertNotIn("AUTHCODE777SECRET", json.dumps(str(self.log)))
        self.assertNotIn("AUTHCODE777SECRET", "\n".join(lines))

    def test_missing_recipient_reports_field(self):
        notifier = Notifier(config=cfg_with(**dict(self.smtp_cfg, notify_to_mails=())),
                            session=FakeSession(),
                            smtp_factory=self._factory(), log=lambda m: None)
        _, ok, detail = notifier.notify("result", "x")[0]
        self.assertFalse(ok)
        self.assertIn("notify_to_mails", detail)


class NotifyReportTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)

    def _notifier(self, **over):
        self.session = FakeSession()
        base = dict(notify_targets=("webhook",), notify_mask_labels=True)
        base.update(over)
        return Notifier(config=cfg_with(**base), session=self.session,
                        log=lambda m: None)

    def test_report_summary_masks_labels(self):
        notifier = self._notifier()
        notifier.notify_report("result",
                               {"17718937689": [{"status": "granted"},
                                                {"status": "out_of_stock"}],
                                "19390026704": [{"status": "granted"}]},
                               extra_lines=["波次 1, 请求 3"])
        text = self.session.calls[0]["json"]["text"]
        self.assertNotIn("17718937689", text)
        self.assertIn("177****89", text)
        self.assertIn("状态分布", text)
        self.assertIn("granted", text)
        self.assertIn("波次 1, 请求 3", text)

    def test_report_keeps_labels_when_masking_off(self):
        notifier = self._notifier(notify_mask_labels=False)
        notifier.notify_report("result", {"老号": [{"status": "granted"}]})
        self.assertIn("老号", self.session.calls[0]["json"]["text"])

    def test_empty_items_report(self):
        notifier = self._notifier()
        notifier.notify_report("result", {"老号": []})
        self.assertIn("无结果", self.session.calls[0]["json"]["text"])

    def test_mask_label_helper(self):
        self.assertEqual("177****89", mask_label("17718937689"))
        self.assertEqual("老号", mask_label("老号"))

    def test_already_masked_label_is_left_alone(self):
        """用户自己打过码的 label 不再二次掩码，否则账号认不出来。"""
        self.assertEqual("177****7689", mask_label("177****7689"))
        self.assertEqual("老号*1", mask_label("老号*1"))


class _RecordingNotifier:
    """替身：记录 flows 发出的事件，不触网。"""

    def __init__(self):
        self.events = []
        self.enabled = True

    def notify(self, event, text, title=None):
        self.events.append((event, text))

    def notify_report(self, event, report, extra_lines=()):
        self.events.append((event, report))

    def notify_account(self, label, items, timings=None, extra_lines=(),
                       to_mails=None, targets=None):
        self.events.append(("account_result", label, items, timings,
                            to_mails, targets))


class PerAccountNotifyTest(unittest.TestCase):
    """一账号一条：券名 + 状态 + 发送时刻/耗时 + 服务端最终状态。"""

    ITEMS = [
        {"coupon": "【5折外卖券】立减20", "status": "granted",
         "detail": "{'winPrizeInfo': {'prize': 'ok'}}",
         "grant_status": "GRANTED"},
        {"coupon": "【5折外卖券】立减25", "status": "out_of_stock",
         "detail": "code=60001: 已抢光"},
    ]

    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)
        self.session = FakeSession()
        base = dict(notify_targets=("webhook",),
                    notify_events=("result", "account_result", "auth_expired"))
        self.notifier = Notifier(config=cfg_with(**base), session=self.session,
                                 log=lambda m: None)

    def _text(self):
        return self.session.calls[-1]["json"]["text"]

    def test_message_shape(self):
        self.notifier.notify_account(
            "17718937689", self.ITEMS,
            timings={"【5折外卖券】立减20": ("23:59:59.70", 1.78)})
        sent = self.session.calls[-1]["json"]
        self.assertEqual("account_result", sent["event"])
        text = sent["text"]
        self.assertIn("177****89", text)          # label 掩码
        self.assertNotIn("17718937689", text)
        self.assertIn("立减20: granted（发送 23:59:59.70，耗时 1.78s）"
                      " 服务端 GRANTED", text)
        self.assertIn("立减25: out_of_stock", text)
        self.assertIn("已抢光", text)
        self.assertNotIn("winPrizeInfo", text)    # 成功不重复带奖品 JSON

    def test_label_kept_when_masking_off(self):
        base = dict(notify_targets=("webhook",), notify_mask_labels=False,
                    notify_events=("account_result",))
        notifier = Notifier(config=cfg_with(**base), session=self.session,
                            log=lambda m: None)
        notifier.notify_account("老号", [{"coupon": "券A", "status": "granted"}])
        self.assertIn("老号", self._text())

    def test_event_can_be_filtered_out(self):
        base = dict(notify_targets=("webhook",), notify_events=("result",))
        notifier = Notifier(config=cfg_with(**base), session=self.session,
                            log=lambda m: None)
        self.assertEqual([], notifier.notify_account("老号", self.ITEMS))
        self.assertEqual([], self.session.calls)

    def test_detail_secret_redacted(self):
        GLOBAL_SECRETS.register("SECRETTOKENVALUE123")
        self.notifier.notify_account(
            "老号", [{"coupon": "券A", "status": "failed",
                      "detail": "code=9: SECRETTOKENVALUE123 出错"}])
        self.assertNotIn("SECRETTOKENVALUE123", self._text())
        self.assertIn("***", self._text())

    def test_no_items_says_no_result(self):
        self.notifier.notify_account("老号", [])
        self.assertIn("无结果", self._text())


class FlowsWiringTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)

    def test_ping_notifies_only_on_abnormal(self):
        auth = {"label": "老号", "GL-XSRF-TOKEN": "t", "GOD_UUID": "u",
                "device_id": "d", "cookies": {}}
        good = _RecordingNotifier()
        with mock.patch.object(flows, "ApiClient") as ac:
            ac.return_value.__enter__ = lambda s: s
            ac.return_value.coupon_info = lambda timeout=None: {}
            ac.return_value.grant_status = lambda ids, timeout=None: {}
            report = flows.ping([auth], notifier=good)
        self.assertEqual("reachable", report["老号"])
        self.assertEqual([], good.events)          # 正常不打扰

        bad = _RecordingNotifier()
        with mock.patch.object(flows, "ApiClient") as ac:
            ac.return_value.__enter__ = lambda s: s
            ac.return_value.coupon_info = lambda timeout=None: {}
            from chagee.errors import ApiError
            ac.return_value.grant_status = mock.Mock(
                side_effect=ApiError(873, "重新登录"))
            report = flows.ping([auth], notifier=bad)
        self.assertEqual("expired", report["老号"])
        self.assertEqual(1, len(bad.events))
        self.assertEqual("health", bad.events[0][0])

    def _runner(self, labels):
        auths = [{"label": l, "GL-XSRF-TOKEN": "t", "GOD_UUID": "u",
                  "device_id": "d", "cookies": {}} for l in labels]
        runner = flows.LoopRunner(auths, config=Config(), minutes=0.01,
                                  interval=0.01)
        self.addCleanup(lambda: [c.close() for c in runner.clients.values()])
        return runner

    def test_loop_notifies_result_per_account_and_auth_expired(self):
        from chagee.models import GrantEvent
        runner = self._runner(["老号"])
        notifier = _RecordingNotifier()
        runner.notifier = notifier
        runner.events.append(GrantEvent("2026-10-10 23:59:59.70", "老号",
                                        "【5折外卖券】立减20", "granted", 1.78))
        runner._notify({"老号": [{"coupon": "【5折外卖券】立减20",
                                 "status": "auth_expired"},
                                {"coupon": "【5折外卖券】立减25",
                                 "status": "granted"}]}, wave_count=2)
        names = [e[0] for e in notifier.events]
        self.assertEqual(["result", "account_result", "auth_expired"], names)
        self.assertIn("873", notifier.events[-1][1])
        self.assertIn("import_cookie_export", notifier.events[-1][1])
        # 详情条带上这一账号的时刻/耗时映射
        per_account = notifier.events[1]
        self.assertEqual("老号", per_account[1])
        self.assertEqual({"【5折外卖券】立减20": ("23:59:59.70", 1.78)},
                         per_account[3])

    def test_loop_sends_one_message_per_account(self):
        runner = self._runner(["老号", "小号", "三号"])
        notifier = _RecordingNotifier()
        runner.notifier = notifier
        runner._notify({"老号": [{"status": "granted"}],
                        "小号": [{"status": "granted"}],
                        "三号": [{"status": "out_of_stock"}]}, wave_count=1)
        accounts = [e[1] for e in notifier.events if e[0] == "account_result"]
        self.assertEqual(["老号", "小号", "三号"], accounts)
        self.assertEqual(1, sum(1 for e in notifier.events
                               if e[0] == "result"))

    def test_single_run_notifies_per_account(self):
        auth = {"label": "老号", "GL-XSRF-TOKEN": "t", "GOD_UUID": "u",
                "device_id": "d", "cookies": {},
                "notify_mail": "boss@example.com"}
        notifier = _RecordingNotifier()
        with mock.patch.object(flows, "ApiClient") as ac:
            client = ac.return_value
            client.__enter__ = lambda s: s
            client.find_brand_coupons = lambda: (
                {"brandId": "b1", "brandName": "霸王茶姬"},
                [Coupon(coupon_id="c1", coupon_name="【5折外卖券】立减20",
                        coupon_type="PHONE_REWARD")])
            client.grant_status = lambda ids, timeout=None: {}
            client.grant = lambda brand_id, coupon: {"winPrizeInfo": {"p": 1}}
            client.secrets = GLOBAL_SECRETS
            with contextlib.redirect_stderr(io.StringIO()):
                report, any_error = flows.single_run([auth], notifier=notifier)
        self.assertFalse(any_error)
        self.assertEqual("granted", report["老号"][0]["status"])
        self.assertEqual(["result", "account_result"],
                         [e[0] for e in notifier.events])
        self.assertEqual("老号", notifier.events[1][1])
        # 账号详情只发给该账号凭据里写的 notify_mail
        self.assertEqual(("boss@example.com",), notifier.events[1][4])

    def test_loop_routes_account_mail_from_credential_entry(self):
        auth = {"label": "老号", "GL-XSRF-TOKEN": "t", "GOD_UUID": "u",
                "device_id": "d", "cookies": {}, "notify_mail": "a@x.com"}
        runner = flows.LoopRunner([auth], config=Config(), minutes=0.01,
                                  interval=0.01)
        self.addCleanup(lambda: [c.close() for c in runner.clients.values()])
        notifier = _RecordingNotifier()
        runner.notifier = notifier
        runner._notify({"老号": [{"status": "granted"}]}, wave_count=1)
        accounts = [e for e in notifier.events if e[0] == "account_result"]
        self.assertEqual(("a@x.com",), accounts[0][4])
        self.assertIsNone(accounts[0][5])          # 通道沿用全局
        self.assertEqual((None, None), runner._account_routing("没这个账号"))

    def test_loop_routes_account_channel_from_notify_spec(self):
        auth = {"label": "老号", "GL-XSRF-TOKEN": "t", "GOD_UUID": "u",
                "device_id": "d", "cookies": {},
                "notify": {"targets": ["dingtalk"], "to": ["a@x.com"]}}
        runner = flows.LoopRunner([auth], config=Config(), minutes=0.01,
                                  interval=0.01)
        self.addCleanup(lambda: [c.close() for c in runner.clients.values()])
        notifier = _RecordingNotifier()
        runner.notifier = notifier
        runner._notify({"老号": [{"status": "granted"}]}, wave_count=1)
        accounts = [e for e in notifier.events if e[0] == "account_result"]
        self.assertEqual(("dingtalk",), accounts[0][5])
        self.assertEqual(("a@x.com",), accounts[0][4])


class NotifyConfigTest(unittest.TestCase):
    def test_env_override_targets(self):
        import os
        os.environ["CHAGEE_NOTIFY_TARGETS"] = "telegram,feishu"
        try:
            cfg = load_config()
            self.assertEqual(("telegram", "feishu"), cfg.notify_targets)
        finally:
            del os.environ["CHAGEE_NOTIFY_TARGETS"]

    def test_defaults_disabled(self):
        cfg = Config()
        self.assertEqual((), cfg.notify_targets)
        self.assertTrue(cfg.notify_enabled)
        self.assertTrue(cfg.notify_mask_labels)

    def test_cli_flag_disables_notify(self):
        from chagee import cli
        captured = {}
        original = cli.Notifier

        class Stub:
            def __init__(self, enabled):
                self.enabled = enabled

            @classmethod
            def from_config(cls, cfg):
                captured["enabled"] = cfg.notify_enabled
                return cls(cfg.notify_enabled)

            def close(self):
                pass

        cli.Notifier = Stub
        try:
            with mock.patch.object(cli, "_load_auths",
                                   return_value=[{"label": "a", "_auth_file": "x"}]), \
                    mock.patch.object(cli, "single_run", return_value=({}, False)), \
                    mock.patch("sys.stdout"):
                cli.main(["--no-notify"])
        finally:
            cli.Notifier = original
        self.assertFalse(captured["enabled"])


class CliNotifyTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)

    def _run(self, cfg, accounts, enabled=True, results=None):
        from chagee import cli
        sent = []

        class Stub:
            targets = ("email",)

            def __init__(self):
                self.enabled = enabled

            @classmethod
            def from_config(cls, c):
                return cls()

            def notify(self, event, text, title=None, force=False,
                       to_mails=None, targets=None):
                sent.append({"event": event, "force": force,
                             "to_mails": to_mails, "targets": targets})
                return list(results or [("email", True, "已发送")])

            def close(self):
                pass

        out = io.StringIO()
        with mock.patch.object(cli, "Notifier", Stub), \
                mock.patch.object(cli, "load_auths", return_value=accounts):
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = cli._notify_test(cfg, argparse.ArgumentParser())
        return code, sent, out.getvalue()

    def test_global_send_uses_configured_recipients(self):
        cfg = Config(notify_targets=("email",), notify_to_mails=("you@example.com",))
        code, sent, _ = self._run(cfg, accounts=[])
        self.assertEqual(0, code)
        self.assertEqual([("test", True, ("you@example.com",), None)],
                         [(s["event"], s["force"], s["to_mails"], s["targets"])
                          for s in sent])

    def test_each_routed_account_gets_its_own_send(self):
        cfg = Config(notify_targets=("email",), notify_to_mails=("you@example.com",))
        accounts = [
            {"label": "老号", "notify": {"targets": ["email"],
                                        "to": ["a@x.com"]}},
            {"label": "钉钉号", "notify": {"targets": ["dingtalk"]}},
            {"label": "没配路由"},
        ]
        code, sent, out = self._run(cfg, accounts)
        self.assertEqual(3, len(sent))          # 全局 1 条 + 有路由的 2 个账号
        self.assertEqual(("email",), sent[1]["targets"])
        self.assertEqual(("a@x.com",), sent[1]["to_mails"])
        self.assertEqual(("dingtalk",), sent[2]["targets"])
        self.assertIsNone(sent[2]["to_mails"])
        self.assertIn("老号", out)              # 结果按账号分组
        self.assertIn("钉钉号", out)
        self.assertEqual(0, code)

    def test_failure_makes_exit_code_one(self):
        cfg = Config(notify_targets=("email",), notify_to_mails=("you@example.com",))
        code, _, _ = self._run(cfg, [], results=[("email", False, "HTTP 500")])
        self.assertEqual(1, code)

    def test_only_account_routing_still_sends(self):
        """全局没配通道但账号自带路由：路由本身就是发送意图，照样自检。"""
        accounts = [{"label": "老号", "notify_mail": "a@x.com"}]
        code, sent, _ = self._run(Config(notify_targets=(), notify_to_mails=()),
                                  accounts, enabled=False)
        self.assertEqual(1, len(sent))
        self.assertEqual(("a@x.com",), sent[0]["to_mails"])
        self.assertEqual(0, code)

    def test_notify_test_errors_when_nothing_configurable(self):
        with self.assertRaises(SystemExit):
            self._run(Config(notify_targets=(), notify_to_mails=()), accounts=[],
                      enabled=False)

    def test_notify_test_errors_when_no_channel(self):
        from chagee import cli

        class Disabled:
            enabled = False
            targets = ()

            @classmethod
            def from_config(cls, cfg):
                return cls()

            def close(self):
                pass

        with mock.patch.object(cli, "Notifier", Disabled):
            with self.assertRaises(SystemExit):
                cli._notify_test(Config(), argparse.ArgumentParser())


class PerAccountRecipientTest(unittest.TestCase):
    """收件邮箱可以写在凭据条目里（notify_mail），一账号一份收件箱。"""

    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)

    def test_account_mails_helper(self):
        self.assertEqual(("a@x.com",), account_mails({"notify_mail": "a@x.com"}))
        self.assertEqual(("a@x.com", "b@x.com"),
                         account_mails({"notify_mail": ["a@x.com", "b@x.com"]}))
        self.assertEqual(("a@x.com",), account_mails({"notify_mailbox": "a@x.com"}))
        self.assertIsNone(account_mails({"label": "无邮箱"}))
        self.assertIsNone(account_mails({"notify_mail": ""}))

    def _email_notifier(self, notify_to_mails, log):
        cfg = cfg_with(notify_targets=("email",),
                       email_smtp_host="smtp.qq.com", email_smtp_port=465,
                       email_use_ssl=True, notify_to_mails=notify_to_mails,
                       email_user="s@qq.com", email_password="AUTH123SECRET",
                       email_from="s@qq.com",
                       notify_events=("account_result",))
        return Notifier(config=cfg, session=FakeSession(),
                        smtp_factory=lambda h, p, ssl: RecordingSMTP(log, h, p, ssl),
                        log=lambda m: None)

    def test_override_used_when_global_empty(self):
        """全局 notify_to_mails 留空也能发：收件人来自该账号的 notify_mail 覆盖。"""
        log = []
        notifier = self._email_notifier((), log)
        results = notifier.notify_account("老号", [{"coupon": "券A",
                                                    "status": "granted"}],
                                          to_mails=("mine@example.com",))
        self.assertTrue(results[0][1], results[0])
        sent = [e for e in log if isinstance(e, tuple) and e[0] == "send"]
        self.assertEqual([("send", "CHAGEE 账号领取详情")], sent)

    def test_no_recipient_anywhere_reports_field_name(self):
        log = []
        notifier = self._email_notifier((), log)
        _, ok, detail = notifier.notify_account("老号", [])[0]
        self.assertFalse(ok)
        self.assertIn("notify_to_mails", detail)          # 只报字段名
        self.assertNotIn("AUTH123SECRET", detail)
        self.assertEqual([], [e for e in log if isinstance(e, tuple)
                              and e[0] == "send"])


class RegisterSecretsTimingTest(unittest.TestCase):
    def test_register_happens_at_module_level_helper(self):
        GLOBAL_SECRETS.clear()
        cfg = Config(email_password="SMTPAUTH123SECRET",
                     feishu_webhook="https://x/?token=WEBHOOKTOKEN123")
        self.assertNotIn("***", GLOBAL_SECRETS.redact("SMTPAUTH123SECRET"))
        register_config_secrets(cfg)
        self.assertIn("***", GLOBAL_SECRETS.redact("SMTPAUTH123SECRET"))
        self.assertIn("***", GLOBAL_SECRETS.redact("WEBHOOKTOKEN123"))

    def test_cli_registers_secrets_before_notifier_exists(self):
        """构造 Notifier 之前就登记：否则更早的失败路径可能把管理密码打出来。"""
        from chagee import cli
        cfg = Config(notify_targets=("email",), email_password="SMTPAUTH123SECRET")

        class Boom:
            @classmethod
            def from_config(cls, c):
                raise RuntimeError("密码泄漏风险: SMTPAUTH123SECRET")

        with mock.patch.object(cli, "load_config", return_value=cfg), \
                mock.patch.object(cli, "Notifier", Boom):
            with self.assertRaises(RuntimeError) as cm:
                cli.main(["--notify-test"])
        self.assertIn("***", GLOBAL_SECRETS.redact(str(cm.exception)))
        GLOBAL_SECRETS.clear()


class AccountRoutingTest(unittest.TestCase):
    """账号条目里的 notify 对象：这个账号的详情走哪条通道、发给谁。"""

    def test_full_spec(self):
        targets, to = account_routing(
            {"label": "老号", "notify": {"targets": ["email"],
                                        "to": ["a@x.com", "b@x.com"]}})
        self.assertEqual(("email",), targets)
        self.assertEqual(("a@x.com", "b@x.com"), to)

    def test_targets_accepts_single_string_and_aliases(self):
        self.assertEqual((("dingtalk",), None),
                         account_routing({"notify": {"targets": "dingtalk"}}))
        self.assertEqual((("webhook",), None),
                         account_routing({"notify": {"channel": "webhook"}}))

    def test_shorthand_notify_mail(self):
        targets, to = account_routing({"label": "小号", "notify_mail": "c@x.com"})
        self.assertIsNone(targets)                 # 通道沿用全局
        self.assertEqual(("c@x.com",), to)

    def test_no_spec_means_global(self):
        self.assertEqual((None, None), account_routing({"label": "老号"}))

    def test_bad_spec_warns_and_falls_back(self):
        warns = []
        targets, to = account_routing({"label": "老号", "notify": "email"},
                                      warn=warns.append)
        self.assertEqual((None, None), (targets, to))
        self.assertEqual(1, len(warns))
        self.assertIn("老号", warns[0])

    def test_notifier_sends_only_to_account_targets(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)
        session = FakeSession()
        cfg = cfg_with(notify_targets=("telegram", "feishu"),
                       dingtalk_webhook=DING,
                       notify_events=("account_result",))
        notifier = Notifier(config=cfg, session=session, log=lambda m: None)
        results = notifier.notify_account("老号", [{"coupon": "券",
                                                    "status": "granted"}],
                                          targets=("dingtalk",))
        self.assertEqual([("dingtalk", True, "已发送")], results)
        self.assertEqual(1, len(session.calls))
        self.assertIn("/robot/send", session.calls[0]["url"])

    def test_account_targets_work_without_global_targets(self):
        """全局通道列表为空、但账号指定了 dingtalk：按账号意图发送。"""
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)
        session = FakeSession()
        cfg = cfg_with(notify_targets=(), dingtalk_webhook=DING,
                       notify_events=("account_result",))
        notifier = Notifier(config=cfg, session=session, log=lambda m: None)
        self.assertFalse(notifier.enabled)          # 全局事件没有去处
        results = notifier.notify_account("老号", [{"coupon": "券",
                                                    "status": "granted"}],
                                          targets=("dingtalk",))
        self.assertTrue(results[0][1], results[0])

    def test_unknown_account_channel_warns_and_skips(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)
        session = FakeSession()
        lines = []
        cfg = cfg_with(notify_targets=("telegram",),
                       notify_events=("account_result",))
        notifier = Notifier(config=cfg, session=session, log=lines.append)
        results = notifier.notify_account("老号", [{"status": "granted"}],
                                          targets=("飞书机器人",))
        self.assertEqual([], results)
        self.assertTrue(any("无法识别" in l for l in lines))
        self.assertEqual([], session.calls)


class ResendChannelTest(unittest.TestCase):
    """Resend API：POST https://api.resend.com/emails + Bearer key。"""

    BASE_CFG = dict(notify_targets=("resend",),
                    resend_api_key="re_SECRETKEY123456",
                    resend_from="no-reply@email.troea.com",
                    resend_from_name="chagee 抢券",
                    notify_to_mails=("lastrui@outlook.com",))

    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)
        self.lines = []
        self.session = FakeSession(resp=FakeResp(200, {"id": "email-1"}))

    def _notifier(self, resp=None, **over):
        base = dict(self.BASE_CFG)
        base.update(over)
        if resp is not None:
            self.session = FakeSession(resp=resp)
        return Notifier(config=cfg_with(**base), session=self.session,
                        log=self.lines.append)

    def test_request_shape(self):
        notifier = self._notifier()
        results = notifier.notify("result", "正文")
        self.assertTrue(results[0][1], results[0])
        call = self.session.calls[0]
        self.assertEqual("https://api.resend.com/emails", call["url"])
        self.assertEqual({"Authorization": "Bearer re_SECRETKEY123456"},
                         call["headers"])
        body = call["json"]
        self.assertEqual("chagee 抢券 <no-reply@email.troea.com>", body["from"])
        self.assertEqual(["lastrui@outlook.com"], body["to"])
        self.assertEqual("正文", body["text"])
        self.assertIn("CHAGEE 抢券结果", body["subject"])

    def test_from_with_display_name_kept_as_is(self):
        notifier = self._notifier(resend_from="已带名字 <a@x.com>")
        notifier.notify("result", "x")
        self.assertEqual("已带名字 <a@x.com>",
                         self.session.calls[0]["json"]["from"])

    def test_account_recipients_override_global(self):
        notifier = self._notifier(notify_events=("account_result",))
        notifier.notify_account("老号", [{"coupon": "券", "status": "granted"}],
                                to_mails=("only@x.com",))
        self.assertEqual(["only@x.com"], self.session.calls[0]["json"]["to"])

    def test_missing_id_counts_as_failure(self):
        """HTTP 200 但响应里没有 id —— 不能把没受理当成功。"""
        notifier = self._notifier(resp=FakeResp(200, {"name": "missing_api_key"}))
        _, ok, detail = notifier.notify("result", "x")[0]
        self.assertFalse(ok)
        self.assertIn("未返回消息 id", detail)

    def test_http_401_fails_and_key_stays_masked(self):
        notifier = self._notifier(resp=FakeResp(
            401, text={"name": "invalid_api_key",
                       "message": "re_SECRETKEY123456 无效"}))
        _, ok, _ = notifier.notify("result", "x")[0]
        self.assertFalse(ok)
        text = "".join(self.lines)
        self.assertIn("HTTP 401", text)
        self.assertNotIn("re_SECRETKEY123456", text)
        self.assertIn("***", text)

    def test_missing_api_key_reports_field_name(self):
        notifier = self._notifier(resend_api_key="")
        _, ok, detail = notifier.notify("result", "x")[0]
        self.assertFalse(ok)
        self.assertIn("resend_api_key", detail)
        self.assertNotIn("re_SECRETKEY123456", detail)
        self.assertEqual([], self.session.calls)

    def test_no_recipient_anywhere(self):
        notifier = self._notifier(notify_to_mails=())
        _, ok, detail = notifier.notify("result", "x")[0]
        self.assertFalse(ok)
        self.assertIn("notify_to_mails", detail)


if __name__ == "__main__":
    unittest.main()
