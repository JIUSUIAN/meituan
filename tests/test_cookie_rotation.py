#!/usr/bin/env python3
"""JSESSIONID 轮换跟踪测试：只跟随服务端下发，绝不本地生成。

全部 mock，不访问真实接口。
运行：python -m unittest discover -s tests -t . -v
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

import requests

from meituan.api_client import ApiClient
from meituan.config import Config, load_config
from meituan.errors import ApiTransportError
from meituan.security import GLOBAL_SECRETS, load_auth, save_auth

OLD_JSID = "oldjsessionidvalue000001"
NEW_JSID = "newjsessionidvalue999999"

BASE_AUTH = {
    "GL-XSRF-TOKEN": "tok-SECRET-abcdef123456",
    "GOD_UUID": "uid-SECRET-ffeeddccbb11",
    "device_id": "dev-SECRET-0011223344",
    "label": "acc-1",
}


def auth_with_cookie(jsid=OLD_JSID, auth_file=None):
    auth = dict(BASE_AUTH)
    auth["cookies"] = {"GL-XSRF-TOKEN": auth["GL-XSRF-TOKEN"],
                       "GOD_UUID": auth["GOD_UUID"],
                       "JSESSIONID": jsid}
    if auth_file:
        auth["_auth_file"] = str(auth_file)
    return auth


class Resp:
    def __init__(self, payload=None, set_cookies=None, status_code=200, text=None):
        self.status_code = status_code
        self._payload = payload
        self.cookies = set_cookies or {}
        self.text = text if text is not None else json.dumps(payload or {})

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class ScriptedSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent_headers = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.sent_headers.append(dict(headers or {}))
        if not self.responses:
            raise AssertionError("mock 脚本已用尽")
        return self.responses.pop(0)

    def close(self):
        pass


class RotationTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()

    def tearDown(self):
        GLOBAL_SECRETS.clear()

    def test_rotation_updates_local_and_next_request_follows(self):
        auth = auth_with_cookie()
        session = ScriptedSession([
            Resp({"code": 200, "result": {"brands": []}},
                 set_cookies={"JSESSIONID": NEW_JSID}),
            Resp({"code": 200, "result": {}}),
        ])
        client = ApiClient(auth, session=session, config=Config())
        client.coupon_info()
        self.assertEqual(auth["cookies"]["JSESSIONID"], NEW_JSID)
        # 第二次请求的 Cookie 头必须携带新值
        client.coupon_info()
        self.assertIn("JSESSIONID=%s" % NEW_JSID, session.sent_headers[1]["Cookie"])

    def test_same_value_is_not_treated_as_rotation(self):
        auth = auth_with_cookie()
        events = []
        session = ScriptedSession([
            Resp({"code": 200, "result": {}},
                 set_cookies={"JSESSIONID": OLD_JSID})])
        client = ApiClient(auth, config=Config(), session=session,
                           on_rotate=events.append)
        client.coupon_info()
        self.assertEqual(events, [])
        self.assertEqual(auth["cookies"]["JSESSIONID"], OLD_JSID)

    def test_untracked_cookie_ignored(self):
        auth = auth_with_cookie()
        session = ScriptedSession([
            Resp({"code": 200, "result": {}},
                 set_cookies={"SOMETHING_ELSE": "x" * 12})])
        client = ApiClient(auth, config=Config(), session=session)
        client.coupon_info()
        self.assertNotIn("SOMETHING_ELSE", auth["cookies"])

    def test_rotation_tracked_even_on_error_response(self):
        # HTTP 500 附带轮换：仍应跟随，随后照常抛传输层错误
        auth = auth_with_cookie()
        session = ScriptedSession([
            Resp(status_code=500, text="oops",
                 set_cookies={"JSESSIONID": NEW_JSID})])
        client = ApiClient(auth, config=Config(), session=session)
        with self.assertRaises(ApiTransportError):
            client.coupon_info()
        self.assertEqual(auth["cookies"]["JSESSIONID"], NEW_JSID)

    def test_new_value_registered_for_redaction(self):
        auth = auth_with_cookie()
        session = ScriptedSession([
            Resp({"code": 200, "result": {}},
                 set_cookies={"JSESSIONID": NEW_JSID})])
        client = ApiClient(auth, config=Config(), session=session)
        client.coupon_info()
        self.assertNotIn(NEW_JSID, GLOBAL_SECRETS.redact("leak? %s!" % NEW_JSID))

    def test_on_rotate_receives_name_only(self):
        auth = auth_with_cookie()
        events = []
        session = ScriptedSession([
            Resp({"code": 200, "result": {}},
                 set_cookies={"JSESSIONID": NEW_JSID})])
        client = ApiClient(auth, config=Config(), session=session,
                           on_rotate=events.append)
        client.coupon_info()
        self.assertEqual(events, ["JSESSIONID"])

    def test_persist_updates_entry_in_place(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "cookies.json"
            f.write_text(json.dumps(auth_with_cookie()), encoding="utf-8")
            auth = json.loads(f.read_text(encoding="utf-8"))
            auth["_auth_file"] = str(f)
            session = ScriptedSession([
                Resp({"code": 200, "result": {}},
                     set_cookies={"JSESSIONID": NEW_JSID})])
            client = ApiClient(auth, config=Config(), session=session)
            client.coupon_info()
            saved = json.loads(f.read_text(encoding="utf-8"))
            self.assertEqual(saved["cookies"]["JSESSIONID"], NEW_JSID)
            self.assertNotIn("_auth_file", saved)   # 内部字段不落盘
            self.assertEqual("acc-1", saved["label"])  # 其余字段原样保留
            self.assertFalse(list(f.parent.glob("*.tmp")))  # 临时文件已 rename

    def test_persist_disabled_keeps_memory_only(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "cookies.json"
            cfg = Config()
            cfg.persist_rotated_cookies = False
            auth = auth_with_cookie(auth_file=f)
            f.write_text(json.dumps(auth_with_cookie()), encoding="utf-8")
            session = ScriptedSession([
                Resp({"code": 200, "result": {}},
                     set_cookies={"JSESSIONID": NEW_JSID})])
            client = ApiClient(auth, config=cfg, session=session)
            client.coupon_info()
            self.assertNotIn(NEW_JSID, f.read_text(encoding="utf-8"))
            self.assertEqual(auth["cookies"]["JSESSIONID"], NEW_JSID)


class CookieHeaderTest(unittest.TestCase):
    """回归：cookies 只有 JSESSIONID 时，基础对也必须出现在 Cookie 头。"""

    def setUp(self):
        GLOBAL_SECRETS.clear()

    def test_base_pairs_always_merged(self):
        auth = dict(BASE_AUTH)
        auth["cookies"] = {"JSESSIONID": OLD_JSID}
        session = ScriptedSession([Resp({"code": 200, "result": {}})])
        client = ApiClient(auth, config=Config(), session=session)
        client.coupon_info()
        cookie = session.sent_headers[0]["Cookie"]
        self.assertIn("GL-XSRF-TOKEN=%s" % BASE_AUTH["GL-XSRF-TOKEN"], cookie)
        self.assertIn("GOD_UUID=%s" % BASE_AUTH["GOD_UUID"], cookie)
        self.assertIn("JSESSIONID=%s" % OLD_JSID, cookie)


class SaveAndLoadAuthTest(unittest.TestCase):
    def setUp(self):
        GLOBAL_SECRETS.clear()

    def test_load_auth_records_source_file(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "cookies.json"
            f.write_text(json.dumps(BASE_AUTH), encoding="utf-8")
            auth = load_auth("cookies.json", base_dir=td)
            self.assertEqual(auth["_auth_file"], str(f.resolve()))

    def test_save_auth_strips_internal_keys(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "out.json"
            save_auth(dict(BASE_AUTH, _auth_file=str(f)), f)
            saved = json.loads(f.read_text(encoding="utf-8"))
            self.assertNotIn("_auth_file", saved)
            self.assertEqual(saved["GOD_UUID"], BASE_AUTH["GOD_UUID"])


class SessionCookieNamesConfigTest(unittest.TestCase):
    """跟踪名单可配置（MEITUAN_SESSION_COOKIE_NAMES 逗号分隔）。"""

    def test_env_override(self):
        missing = Path(tempfile.gettempdir()) / "definitely-missing.json"
        os.environ["MEITUAN_SESSION_COOKIE_NAMES"] = "JSESSIONID,APP_SID"
        try:
            cfg = load_config(path=missing)
            self.assertEqual(cfg.session_cookie_names, ("JSESSIONID", "APP_SID"))
        finally:
            del os.environ["MEITUAN_SESSION_COOKIE_NAMES"]

    def test_extra_tracked_name(self):
        GLOBAL_SECRETS.clear()
        auth = auth_with_cookie()
        auth["cookies"]["APP_SID"] = "aaaa111122223333"
        cfg = Config()
        cfg.session_cookie_names = ("JSESSIONID", "APP_SID")
        session = ScriptedSession([
            Resp({"code": 200, "result": {}},
                 set_cookies={"APP_SID": "bbbb111122223333"})])
        client = ApiClient(auth, config=cfg, session=session)
        client.coupon_info()
        self.assertEqual(auth["cookies"]["APP_SID"], "bbbb111122223333")


class CookieStoreTest(unittest.TestCase):
    """cookies.py：单一真源语义。"""

    def setUp(self):
        GLOBAL_SECRETS.clear()

    def test_header_merges_all_and_preserves_order(self):
        from meituan.cookies import CookieStore
        store = CookieStore({"GL-XSRF-TOKEN": "a", "GOD_UUID": "b",
                             "JSESSIONID": "c"},
                            tracked_names=("JSESSIONID",))
        self.assertEqual(store.header(),
                         "GL-XSRF-TOKEN=a; GOD_UUID=b; JSESSIONID=c")

    def test_case_insensitive_get_and_set(self):
        from meituan.cookies import CookieStore
        store = CookieStore({"jsessionid": "c1"}, tracked_names=("JSESSIONID",))
        self.assertEqual(store.get("JSESSIONID"), "c1")
        self.assertFalse(store.set("JsEssIoNiD", "c1"))   # 同值不变
        self.assertTrue(store.set("JSESSIONID", "c2"))    # 变化返回 True
        self.assertEqual(store.get("jsessionid"), "c2")

    def test_apply_response_ignores_untracked(self):
        # 鉴权关键字段不允许被 Set-Cookie 静默改写（签名依赖本地值）
        GLOBAL_SECRETS.clear()
        auth = auth_with_cookie()
        session = ScriptedSession([
            Resp({"code": 200, "result": {}},
                 set_cookies={"GL-XSRF-TOKEN": "evilvalue-abcdef000000",
                              "JSESSIONID": NEW_JSID})])
        client = ApiClient(auth, config=Config(), session=session)
        client.coupon_info()
        self.assertEqual(auth["cookies"]["GL-XSRF-TOKEN"],
                         BASE_AUTH["GL-XSRF-TOKEN"])
        self.assertEqual(auth["cookies"]["JSESSIONID"], NEW_JSID)


class LoadAuthNormalizeTest(unittest.TestCase):
    """security.load_auth：浏览器导出格式与鉴权字段归一化。"""

    def setUp(self):
        GLOBAL_SECRETS.clear()

    def test_browser_export_list_format(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "cookies.json"
            f.write_text(json.dumps({
                "device_id": BASE_AUTH["device_id"],
                "cookies": [
                    {"name": "GL-XSRF-TOKEN",
                     "value": BASE_AUTH["GL-XSRF-TOKEN"]},
                    {"name": "GOD_UUID", "value": BASE_AUTH["GOD_UUID"]},
                    {"name": "JSESSIONID", "value": OLD_JSID},
                ]}), encoding="utf-8")
            auth = load_auth("cookies.json", base_dir=td)
        self.assertEqual(auth["GL-XSRF-TOKEN"], BASE_AUTH["GL-XSRF-TOKEN"])
        self.assertEqual(auth["GOD_UUID"], BASE_AUTH["GOD_UUID"])
        self.assertEqual(auth["cookies"]["JSESSIONID"], OLD_JSID)

    def test_device_id_falls_back_to_ds_website_uuid_cookie(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "cookies.json"
            f.write_text(json.dumps({"cookies": [
                {"name": "GL-XSRF-TOKEN", "value": BASE_AUTH["GL-XSRF-TOKEN"]},
                {"name": "GOD_UUID", "value": BASE_AUTH["GOD_UUID"]},
                {"name": "ds-website-uuid", "value": "dev-from-cookie-123456"},
            ]}), encoding="utf-8")
            auth = load_auth("cookies.json", base_dir=td)
        self.assertEqual(auth["device_id"], "dev-from-cookie-123456")

    def test_top_level_authoritative_over_cookies_dict(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "cookies.json"
            f.write_text(json.dumps({
                "GL-XSRF-TOKEN": "TOPvalue-abcdef000001",
                "GOD_UUID": BASE_AUTH["GOD_UUID"],
                "device_id": BASE_AUTH["device_id"],
                "cookies": {"GL-XSRF-TOKEN": "LOWvalue-abcdef999999",
                            "JSESSIONID": OLD_JSID}}), encoding="utf-8")
            auth = load_auth("cookies.json", base_dir=td)
        # 顶层为准：签名值与 header 值不可能漂移
        self.assertEqual(auth["cookies"]["GL-XSRF-TOKEN"], "TOPvalue-abcdef000001")

    def test_client_header_matches_signature_source(self):
        GLOBAL_SECRETS.clear()
        auth = {"GL-XSRF-TOKEN": "SIGNvalue-abcdef000002",
                "GOD_UUID": BASE_AUTH["GOD_UUID"],
                "device_id": BASE_AUTH["device_id"],
                "cookies": {"GL-XSRF-TOKEN": "OTHERvalue-abcdef888888"}}
        session = ScriptedSession([Resp({"code": 200, "result": {}})])
        client = ApiClient(auth, config=Config(), session=session)
        client.coupon_info()
        self.assertIn("GL-XSRF-TOKEN=SIGNvalue-abcdef000002",
                      session.sent_headers[0]["Cookie"])
        self.assertNotIn("OTHERvalue", session.sent_headers[0]["Cookie"])


if __name__ == "__main__":
    unittest.main()
