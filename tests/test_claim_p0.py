#!/usr/bin/env python3
"""P0 回归测试（P1 模块拆分后迁移）：T01 脱敏 / T02 健康检查语义 / T03 结构化错误。

全部使用 mock，不访问真实第三方业务接口。
运行：python -m unittest discover -s tests -t . -v
"""
import json
import tempfile
import unittest
from pathlib import Path

import requests

from meituan import api_client
from meituan import flows
from meituan.api_client import ApiClient
from meituan.config import Config
from meituan.errors import ApiError, ApiParseError, ApiTransportError, classify_grant_error
from meituan.models import Coupon
from meituan.security import GLOBAL_SECRETS, load_auth, redact


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self._raise_json = text is not None and payload is None
        self.text = text if text is not None else json.dumps(payload or {})

    def json(self):
        if self._payload is None or self._raise_json:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """记录请求路径，按脚本返回响应或抛网络异常。"""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append({"url": url, "data": data, "headers": headers})
        if not self.script:
            raise AssertionError("mock 响应脚本已用尽: %s" % url)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        pass


def make_response(status_code=200, payload=None, text=None):
    return FakeResponse(status_code, payload, text)


AUTH = {
    "GL-XSRF-TOKEN": "tok-SECRET-abcdef123456",
    "GOD_UUID": "uid-SECRET-ffeeddccbb11",
    "device_id": "dev-SECRET-0011223344",
    "label": "test-account",
}

COUPON = Coupon.from_api({"couponId": "cid-1", "couponName": "【5折外卖券】立减20",
                          "couponType": "PHONE_REWARD"})


def fresh_auth():
    return dict(AUTH)


def make_client(script, auth=None):
    return ApiClient(auth or fresh_auth(), session=FakeSession(script),
                     config=Config())


class SecretsTest(unittest.TestCase):
    """T01：脱敏与认证文件校验。"""

    def setUp(self):
        GLOBAL_SECRETS.clear()

    def tearDown(self):
        GLOBAL_SECRETS.clear()

    def test_register_and_redact(self):
        GLOBAL_SECRETS.register(AUTH["GL-XSRF-TOKEN"])
        text = "errmsg contains %s leaked" % AUTH["GL-XSRF-TOKEN"]
        out = redact(text)
        self.assertNotIn(AUTH["GL-XSRF-TOKEN"], out)
        self.assertIn("***", out)

    def test_redact_pattern_fallback(self):
        # 未登记的凭据也应按 key=value 形态兜底脱敏
        out = redact("set-cookie: GL-XSRF-TOKEN=abc123xyz; GOD_UUID=zzz999qqq")
        self.assertNotIn("abc123xyz", out)
        self.assertNotIn("zzz999qqq", out)

    def test_http_error_body_is_redacted(self):
        GLOBAL_SECRETS.register(AUTH["GOD_UUID"])
        body = "server said: user %s not allowed" % AUTH["GOD_UUID"]
        client = make_client([make_response(500, text=body)])
        with self.assertRaises(ApiTransportError) as ctx:
            client.post(Config().info_path, {})
        self.assertNotIn(AUTH["GOD_UUID"], str(ctx.exception))
        self.assertEqual(ctx.exception.http_status, 500)

    def test_load_auth_missing_field_no_value_leak(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cookies.json"
            p.write_text(json.dumps(
                {"GL-XSRF-TOKEN": AUTH["GL-XSRF-TOKEN"],
                 "GOD_UUID": AUTH["GOD_UUID"]}), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                load_auth("cookies.json", base_dir=td)
        msg = str(ctx.exception)
        self.assertIn("device_id", msg)               # 报字段名
        self.assertNotIn(AUTH["GL-XSRF-TOKEN"], msg)  # 不报字段值

    def test_load_auth_invalid_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cookies.json"
            p.write_text("{not json,,,", encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                load_auth("cookies.json", base_dir=td)
        self.assertIn("不是合法 JSON", str(ctx.exception))

    def test_load_auth_registers_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cookies.json"
            p.write_text(json.dumps({k: v for k, v in AUTH.items()
                                     if k != "label"}), encoding="utf-8")
            auth = load_auth("cookies.json", base_dir=td)
        self.assertEqual(auth["label"], "cookies.json")
        self.assertIn(AUTH["GL-XSRF-TOKEN"], GLOBAL_SECRETS._secrets)
        self.assertIn(AUTH["device_id"], GLOBAL_SECRETS._secrets)


class ApiErrorModelTest(unittest.TestCase):
    """T03：错误分层与状态映射。"""

    def test_network_error_to_transport(self):
        client = make_client([requests.ConnectionError("boom")])
        with self.assertRaises(ApiTransportError):
            client.post(Config().info_path, {})

    def test_timeout_to_transport(self):
        client = make_client([requests.Timeout("slow")])
        with self.assertRaises(ApiTransportError):
            client.post(Config().info_path, {})

    def test_success_returns_result(self):
        client = make_client([make_response(
            200, {"code": 200, "result": {"brands": []}})])
        self.assertEqual(client.post(Config().info_path, {}), {"brands": []})

    def test_business_error_to_apierror(self):
        client = make_client([make_response(200, {"code": 803, "errmsg": "今日已领取"})])
        with self.assertRaises(ApiError) as ctx:
            client.grant("b", Coupon.from_api({"couponId": "c"}))
        self.assertEqual(ctx.exception.code, 803)

    def test_non_json_raises_parse_error(self):
        client = make_client([make_response(200, text="<html>502</html>")])
        with self.assertRaises(ApiParseError):
            client.post(Config().info_path, {})

    def test_unknown_code_preserved_not_misclassified(self):
        client = make_client([make_response(
            200, {"code": 12345, "errmsg": "神秘错误"})])
        with self.assertRaises(ApiError) as ctx:
            client.grant("b", Coupon.from_api({"couponId": "c"}))
        self.assertEqual(ctx.exception.code, 12345)
        self.assertEqual(ctx.exception.message, "神秘错误")
        # 未知 code 不得映射成任何已知领域状态
        self.assertEqual(classify_grant_error(ctx.exception), "failed")


class GrantStatusMappingTest(unittest.TestCase):
    """T03：try_grant 按结构化 code 分类，不做字符串猜测。"""

    def setUp(self):
        GLOBAL_SECRETS.clear()

    def tearDown(self):
        GLOBAL_SECRETS.clear()

    def _grant_with_code(self, code):
        client = make_client([make_response(
            200, {"code": code, "errmsg": "err-%s" % code})])
        status, detail, _ = flows.try_grant(client, "brand-1", COUPON)
        return status, detail

    def test_803_already_claimed(self):
        status, _ = self._grant_with_code(803)
        self.assertEqual(status, "already_claimed")

    def test_40007_rate_limited(self):
        status, _ = self._grant_with_code(40007)
        self.assertEqual(status, "rate_limited")

    def test_873_auth_expired(self):
        status, _ = self._grant_with_code(873)
        self.assertEqual(status, "auth_expired")

    def test_60001_out_of_stock(self):
        status, _ = self._grant_with_code(60001)
        self.assertEqual(status, "out_of_stock")

    def test_unknown_code_stays_failed(self):
        status, detail = self._grant_with_code(99999)
        self.assertEqual(status, "failed")
        self.assertIn("code=99999", detail)  # 保留原始 code

    def test_transport_error_not_business_status(self):
        """传输/解析失败不是服务端业务答复：记 error 而非 failed。

        error 会进入退出码判定（cron/告警能感知这轮没抢成），
        failed 仅表示「服务端答复了但不是成功」。"""
        client = make_client([requests.ConnectionError("down")])
        status, detail, _ = flows.try_grant(client, "b", COUPON)
        self.assertEqual(status, "error")
        self.assertIn("传输错误", detail)

    def test_granted_success(self):
        client = make_client([make_response(
            200, {"code": 200, "result": {"winPrizeInfo": {"prize": "券"}}})])
        status, detail, _ = flows.try_grant(client, "b", COUPON)
        self.assertEqual(status, "granted")
        self.assertIn("券", detail)


class GrantStatusQueryTest(unittest.TestCase):
    """T03：grant_status 不再静默吞异常，失败与空结果可区分。"""

    def test_failure_raises(self):
        client = make_client([make_response(200, {"code": 873, "errmsg": "请重新登录"})])
        with self.assertRaises(ApiError):
            client.grant_status([COUPON.coupon_id])

    def test_success_empty(self):
        client = make_client([make_response(
            200, {"code": 200, "result": {"grantItems": []}})])
        self.assertEqual(client.grant_status([COUPON.coupon_id]), {})

    def test_no_ids_no_request(self):
        client = make_client([])
        self.assertEqual(client.grant_status([]), {})
        self.assertEqual(client.session.calls, [])


class PingTest(unittest.TestCase):
    """T02：--ping 只读、无副作用；--verify-session 显式承担副作用。"""

    def setUp(self):
        GLOBAL_SECRETS.clear()
        self._orig_session = api_client.requests.Session
        self.sessions = []

        def factory():
            s = FakeSession(self.next_script)
            self.sessions.append(s)
            return s

        api_client.requests.Session = factory

    def tearDown(self):
        api_client.requests.Session = self._orig_session
        GLOBAL_SECRETS.clear()

    def _run_ping(self, script):
        self.next_script = script
        return flows.ping([fresh_auth()], log_path=None)

    def test_ping_reachable(self):
        # info ok + grant-status ok -> reachable（不谎报 authenticated）
        report = self._run_ping([
            make_response(200, {"code": 200, "result": {"brands": []}}),
            make_response(200, {"code": 200, "result": {"grantItems": []}}),
        ])
        self.assertEqual(report["test-account"], "reachable")

    def test_ping_never_calls_grant(self):
        self._run_ping([
            make_response(200, {"code": 200, "result": {"brands": []}}),
            make_response(200, {"code": 200, "result": {"grantItems": []}}),
        ])
        cfg = Config()
        urls = [c["url"] for s in self.sessions for c in s.calls]
        self.assertEqual(urls,
                         [cfg.base_url + cfg.info_path,
                          cfg.base_url + cfg.grant_status_path])
        self.assertNotIn(cfg.base_url + cfg.grant_path, urls)

    def test_ping_expired_on_873(self):
        report = self._run_ping([
            make_response(200, {"code": 200, "result": {"brands": []}}),
            make_response(200, {"code": 873, "errmsg": "登录已失效"}),
        ])
        self.assertEqual(report["test-account"], "expired")

    def test_ping_unknown_on_other_business_code(self):
        report = self._run_ping([
            make_response(200, {"code": 200, "result": {"brands": []}}),
            make_response(200, {"code": 40007, "errmsg": "操作频繁"}),
        ])
        self.assertEqual(report["test-account"], "unknown")

    def test_ping_error_on_network(self):
        report = self._run_ping([requests.ConnectionError("down")])
        self.assertTrue(report["test-account"].startswith("error"))

    def test_verify_session_authenticated(self):
        # 探针券返回 803（已领取）-> 证明登录态为 authenticated
        api_client.requests.Session = lambda: FakeSession([
            make_response(200, {"code": 803, "errmsg": "已领取"})])
        report = flows.verify_session([fresh_auth()], log_path=None)
        self.assertEqual(report["test-account"], "authenticated")

    def test_verify_session_expired(self):
        api_client.requests.Session = lambda: FakeSession([
            make_response(200, {"code": 873, "errmsg": "重新登录"})])
        report = flows.verify_session([fresh_auth()], log_path=None)
        self.assertEqual(report["test-account"], "expired")


class VerifySessionPathTest(unittest.TestCase):
    """--verify-session 必须真实调用 grant 接口。"""

    def test_calls_grant_path(self):
        cfg = Config()
        client = make_client([make_response(200, {"code": 803, "errmsg": "已领取"})])
        flows.try_grant(client, cfg.fixed_brand_id,
                        Coupon.from_api(cfg.probe_coupon))
        self.assertEqual(client.session.calls[0]["url"],
                         cfg.base_url + cfg.grant_path)


class DocConsistencyTest(unittest.TestCase):
    """T02-5：文档、常量与行为一致（P1 后真源为 Config 默认值）。"""

    def test_backoff_default(self):
        self.assertEqual(Config().rate_limit_backoff, 60)

    def test_interval_default(self):
        self.assertEqual(Config().loop_interval, 2.0)

    def test_cli_doc_mentions_defaults(self):
        src = (Path(__file__).parent.parent / "claim.py").read_text(
            encoding="utf-8")
        self.assertIn("--interval 2.0", src)
        self.assertIn("退避 60 秒", src)


if __name__ == "__main__":
    unittest.main()
