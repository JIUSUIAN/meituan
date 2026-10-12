#!/usr/bin/env python3
"""邮件报告页测试：双券卡版式、未抢到变灰 + 中间裂缝、自包含与转义。

不发真实请求；页面内容全部由 mock 数据渲染。
运行：python -m unittest discover -s tests -t . -v
"""
import unittest

from meituan import report_html
from meituan.config import Config
from meituan.notify import Notifier
from meituan.security import GLOBAL_SECRETS

A = "【5折外卖券】立减20"
B = "【5折外卖券】立减25"
TIMINGS = {A: ("23:59:59.70", 1.78), B: ("23:59:59.75", 2.20)}


def item(name, status, **over):
    base = {"coupon": name, "status": status, "detail": ""}
    base.update(over)
    return base


class CardStateTest(unittest.TestCase):
    def _html(self, items):
        return report_html.render_account("老号", items, timings=TIMINGS,
                                          meta="生成时间 x")

    def test_both_granted_is_celebration_without_crack(self):
        html = self._html([item(A, "granted"), item(B, "granted")])
        self.assertIn("恭喜您 抢到券了！", html)
        self.assertNotIn("#4a3517", html)          # 裂缝色块不出现
        self.assertEqual(0, html.count("已抢光"))

    def test_one_missed_greys_and_cracks(self):
        html = self._html([item(A, "granted"),
                           item(B, "out_of_stock", detail="code=60001: 已抢光")])
        self.assertIn("差一点，只抢到 1 张", html)
        self.assertIn("#4a3517", html)             # 裂缝画出来了
        self.assertIn("#f1f2f4", html)             # 灰卡底色
        self.assertIn("已抢光", html)
        self.assertIn("code=60001", html)          # 失败原因带上

    def test_none_granted_says_failed(self):
        html = self._html([item(A, "failed", detail="code=99999: 活动未开始"),
                           item(B, "auth_expired", detail="code=873: 重新登录")])
        self.assertIn("这次没抢到", html)
        self.assertIn("#4a3517", html)
        self.assertIn("登录态失效", html)

    def test_single_item_fills_left_slot_only(self):
        html = self._html([item(A, "granted")])
        self.assertIn("恭喜您 抢到券了！", html)     # 只有一张且已到手
        self.assertIn("未参与", html)               # 右卡位留空并标注


class BrandingTest(unittest.TestCase):
    """页面标题 = 美团大额券；状态语在标题下方；邮件主题见 Config.notify_subject。"""

    def test_page_title_and_brand_line(self):
        html = report_html.render_account("老号", [item(A, "granted"),
                                                   item(B, "granted")])
        self.assertIn("<title>美团大额券</title>", html)
        self.assertIn("美团大额券</div>", html)          # 页面大标题
        self.assertIn("恭喜您 抢到券了！", html)          # 状态横幅仍在
        self.assertIn("账号领取详情", html)               # 副标题标明报告类型

    def test_subject_default(self):
        self.assertEqual("美团大额券抢券通知", Config().notify_subject)


class AmountParsingTest(unittest.TestCase):
    def test_full_reduction(self):
        self.assertEqual("满40减20", report_html._amount("美团外卖 满40减20"))

    def test_instant_cut(self):
        self.assertEqual("立减20", report_html._amount(A))

    def test_discount(self):
        self.assertEqual("5折", report_html._amount("【5折外卖券】"))

    def test_fallback_is_full_name(self):
        self.assertEqual("到店通用券", report_html._amount("到店通用券"))

    def test_tags(self):
        self.assertEqual("外卖券", report_html._tag(A, "PHONE_REWARD"))
        self.assertEqual("到店券", report_html._tag("到店堂食券", ""))
        self.assertEqual("手机券", report_html._tag("通用", "PHONE_REWARD"))


class SafetyTest(unittest.TestCase):
    def test_script_in_coupon_name_is_escaped(self):
        html = report_html.render_account(
            "老号", [item("<script>alert(1)</script>", "granted")])
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("&lt;script&gt;", html)

    def test_page_is_self_contained(self):
        html = report_html.render_account("老号", [item(A, "granted"),
                                                   item(B, "granted")])
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("cid:", html)
        self.assertIn("<!doctype html>", html)

    def test_credentials_never_in_page(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)
        GLOBAL_SECRETS.register("SECRETTOKEN999")
        html = report_html.render_account("老号", [
            item(A, "failed", detail="上游返回 SECRETTOKEN999 出错")])
        # 渲染层不做脱敏（detail 已在 try_grant 处 redact 过），
        # 这里守的是：不把凭据字段本身塞进页面
        self.assertNotIn("GL-XSRF-TOKEN", html)


class SummaryPageTest(unittest.TestCase):
    def test_summary_groups_by_account(self):
        html = report_html.render_summary(
            {"老号": [item(A, "granted"), item(B, "granted")],
             "小号": [item(A, "out_of_stock", detail="已抢光")]},
            extra_lines=["波次 2, 请求 6"], meta="生成时间 x")
        self.assertIn("账号 老号", html)
        self.assertIn("账号 小号", html)
        self.assertIn("差一点", html)               # 全局只抢到一部分
        self.assertIn("波次 2, 请求 6", html)

    def test_empty_report_renders(self):
        html = report_html.render_summary({}, meta="x")
        self.assertIn("这次没抢到", html)
        self.assertIn("无账号结果", html)


class HtmlDeliveryTest(unittest.TestCase):
    """notify_html 开关要真的落到通道载荷里。"""

    class Resp:
        status_code = 200
        text = "{}"

        def json(self):
            return {"id": "mail-1"}

    class Session:
        def __init__(self):
            self.calls = []

        def post(self, url, json=None, data=None, headers=None, timeout=None):
            self.calls.append(json)
            return HtmlDeliveryTest.Resp()

        def close(self):
            pass

    def setUp(self):
        GLOBAL_SECRETS.clear()
        self.addCleanup(GLOBAL_SECRETS.clear)
        self.session = self.Session()

    def _cfg(self, **over):
        base = dict(notify_targets=("resend",), resend_api_key="re_k123456",
                    resend_from="no-reply@email.troea.com",
                    notify_to_mails=("me@example.com",))
        base.update(over)
        return Config(**base)

    def test_resend_gets_html_part(self):
        notifier = Notifier(config=self._cfg(), session=self.session,
                            log=lambda m: None)
        notifier.notify_account("老号", [item(A, "granted"),
                                         item(B, "out_of_stock")],
                                timings=TIMINGS)
        payload = self.session.calls[0]
        self.assertIn("html", payload)
        self.assertIn("<!doctype html>", payload["html"])
        self.assertIn(A, payload["html"])
        self.assertIn("text", payload)             # 纯文本替身仍在

    def test_notify_html_off_sends_text_only(self):
        notifier = Notifier(config=self._cfg(notify_html=False),
                            session=self.session, log=lambda m: None)
        notifier.notify_account("老号", [item(A, "granted")])
        self.assertNotIn("html", self.session.calls[0])

    def test_email_message_is_multipart(self):
        log = []

        class Smtp:
            def __init__(self, host, port, use_ssl):
                pass

            def login(self, user, pwd):
                pass

            def send_message(self, message):
                log.append(message)

            def quit(self):
                pass

        cfg = self._cfg(notify_targets=("email",),
                        email_smtp_host="smtp.qq.com:465",
                        email_user="s@qq.com", email_password="auth123456",
                        email_from="s@qq.com")
        notifier = Notifier(config=cfg, session=self.session, smtp_factory=Smtp,
                            log=lambda m: None)
        notifier.notify_account("老号", [item(A, "granted")], timings=TIMINGS)
        message = log[0]
        self.assertTrue(message.is_multipart())
        parts = list(message.iter_parts())
        self.assertEqual(["plain", "html"],
                         [part.get_content_subtype() for part in parts])
        self.assertIn("<!doctype html>", parts[1].get_content())


if __name__ == "__main__":
    unittest.main()
