#!/usr/bin/env python3
"""P1 回归测试：InflightGate / GrantPacing / 配置分层 / LoopRunner 冒烟 / single_run。

全部使用 mock，不访问真实第三方业务接口。
运行：python -m unittest discover -s tests -t . -v
"""
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from meituan import api_client
from meituan import flows
from meituan.config import Config, load_config
from meituan.pacing import GrantPacing, InflightGate, RateLimiter

AUTH = {
    "GL-XSRF-TOKEN": "tok-SECRET-abcdef123456",
    "GOD_UUID": "uid-SECRET-ffeeddccbb11",
    "device_id": "dev-SECRET-0011223344",
    "label": "acc-1",
}


class FakeResponse:
    def __init__(self, payload):
        self.status_code = 200
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class RoutingSession:
    """按 URL 路径路由 mock 响应；handler 可为 payload、callable(body)->payload
    或 Exception。记录每次调用的路径，供断言。"""

    def __init__(self, routes):
        self.routes = dict(routes)
        self.calls = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append(url)
        path = url.split("inf.ds.163.com", 1)[-1]
        for key, handler in self.routes.items():
            if path.endswith(key):
                body = json.loads(data.decode("utf-8")) if data else {}
                if isinstance(handler, BaseException):
                    raise handler
                payload = handler(body) if callable(handler) else handler
                return FakeResponse(payload)
        raise AssertionError("未配置路由的 URL: %s" % url)

    def close(self):
        pass


OK = {"code": 200, "result": {}}


class InflightGateTest(unittest.TestCase):
    """P1：在飞闸门容量可动态调整，切换不再靠替换全局 Semaphore。"""

    def test_slot_counts_inflight(self):
        gate = InflightGate(2)
        with gate.slot():
            self.assertEqual(gate.inflight, 1)
            with gate.slot():
                self.assertEqual(gate.inflight, 2)
            self.assertEqual(gate.inflight, 1)
        self.assertEqual(gate.inflight, 0)

    def test_blocks_over_capacity_then_set_max_unblocks(self):
        gate = InflightGate(1)
        entered = threading.Event()
        release = threading.Event()

        def holder():
            with gate.slot():
                entered.set()
                release.wait(5)

        t1 = threading.Thread(target=holder)
        t1.start()
        self.assertTrue(entered.wait(5))

        second_in = threading.Event()

        def second():
            with gate.slot():
                second_in.set()

        t2 = threading.Thread(target=second)
        t2.start()
        self.assertFalse(second_in.wait(0.2))  # 容量 1，应被挡住
        gate.set_max(2)
        self.assertTrue(second_in.wait(5))     # 扩容后放行
        release.set()
        t1.join(5)
        t2.join(5)
        self.assertEqual(gate.inflight, 0)

    def test_set_max_shrink_blocks_new(self):
        gate = InflightGate(4)
        gate.set_max(1)
        self.assertEqual(gate.max_inflight, 1)


class GrantPacingTest(unittest.TestCase):
    def test_sustained_mode_updates_both(self):
        pacing = GrantPacing(0.05, 4, 0.5, 2)
        self.assertEqual(pacing.limiter.min_gap, 0.05)
        self.assertEqual(pacing.gate.max_inflight, 4)
        self.assertFalse(pacing.sustained)
        pacing.enter_sustained_mode()
        self.assertEqual(pacing.limiter.min_gap, 0.5)
        self.assertEqual(pacing.gate.max_inflight, 2)
        self.assertTrue(pacing.sustained)

    def test_rate_limiter_gap(self):
        limiter = RateLimiter(0.05)
        t0 = time.time()
        limiter.wait()
        limiter.wait()
        self.assertGreaterEqual(time.time() - t0, 0.04)


class LoadConfigTest(unittest.TestCase):
    """P1：配置分层 默认值 < JSON 文件 < 环境变量 < CLI overrides。"""

    def test_defaults(self):
        cfg = load_config(path=Path(tempfile.gettempdir()) / "definitely-missing.json")
        self.assertEqual(cfg.loop_minutes, 10)
        self.assertEqual(cfg.rate_limit_backoff, 60)
        self.assertFalse(cfg.burst_test)

    def test_json_file_layer(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cfg.json"
            p.write_text(json.dumps({"loop_minutes": 5, "sustained_gap": 1.0}),
                         encoding="utf-8")
            cfg = load_config(path=p)
        self.assertEqual(cfg.loop_minutes, 5)
        self.assertEqual(cfg.sustained_gap, 1.0)
        self.assertEqual(cfg.loop_interval, 2.0)  # 未覆盖的保持默认

    def test_unknown_key_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cfg.json"
            p.write_text(json.dumps({"loop_minute": 5}), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                load_config(path=p)
        self.assertIn("未知字段", str(ctx.exception))

    def test_env_layer_and_cli_precedence(self):
        missing = Path(tempfile.gettempdir()) / "definitely-missing.json"
        os.environ["MEITUAN_LOOP_MINUTES"] = "7"
        os.environ["MEITUAN_BURST_TEST"] = "1"
        try:
            cfg = load_config(path=missing)
            self.assertEqual(cfg.loop_minutes, 7.0)
            self.assertTrue(cfg.burst_test)
            cfg2 = load_config(path=missing, overrides={"loop_minutes": 3.0})
            self.assertEqual(cfg2.loop_minutes, 3.0)  # CLI 覆盖 env
        finally:
            del os.environ["MEITUAN_LOOP_MINUTES"]
            del os.environ["MEITUAN_BURST_TEST"]

    def test_snipe_coupons_property(self):
        cfg = Config()
        names = [c["couponName"] for c in cfg.snipe_coupons]
        self.assertEqual(len(names), 2)
        self.assertTrue(all("5折" in n for n in names))

    def test_comment_keys_ignored_and_list_to_tuple(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cfg.json"
            p.write_text(json.dumps({"_说明": "注释键应被忽略",
                                     "session_cookie_names": ["JSESSIONID", "A"]}),
                         encoding="utf-8")
            cfg = load_config(path=p)
        self.assertEqual(cfg.session_cookie_names, ("JSESSIONID", "A"))

    def test_shipped_example_config_loads(self):
        example = Path(__file__).parent.parent / "claim.config.example.json"
        cfg = load_config(path=example)
        self.assertEqual(cfg.rate_limit_backoff, 60)
        self.assertEqual(cfg.sustained_inflight, 2)


class LoopRunnerSmokeTest(unittest.TestCase):
    """P1：LoopRunner 端到端冒烟（mock 路由），第一波全中后提前结束。"""

    def setUp(self):
        self._orig = api_client.requests.Session
        self.sessions = []

        cfg = Config()

        def gs_handler(body):
            return {"code": 200,
                    "result": {"grantItems": [
                        {"couponId": cid, "status": "GRANTED"}
                        for cid in body["superCouponIds"]]}}

        self.routes = {
            cfg.grant_path: {"code": 200,
                             "result": {"winPrizeInfo": {"prize": "ok"}}},
            cfg.info_path: {"code": 200, "result": {"brands": []}},
            cfg.grant_status_path: gs_handler,
        }

        def factory():
            s = RoutingSession(self.routes)
            self.sessions.append(s)
            return s

        api_client.requests.Session = factory

    def tearDown(self):
        api_client.requests.Session = self._orig

    def test_loop_grants_all_and_exits_early(self):
        cfg = Config()
        report = flows.loop_run([dict(AUTH)], config=cfg,
                                minutes=0.5, interval=0.05)
        items = report["acc-1"]
        self.assertEqual(len(items), 2)  # 两张5折券
        self.assertTrue(all(i["status"] == "granted" for i in items))
        # grant 只发了两次（第一波全中，没有多余波次）
        grant_urls = [u for s in self.sessions for u in s.calls
                      if u.endswith(cfg.grant_path)]
        self.assertEqual(len(grant_urls), 2)

    def test_loop_out_of_stock_stops_after_streak(self):
        cfg = Config()
        cfg.soldout_stop_after = 2
        cfg.loop_interval = 0.01
        self.routes[Config().grant_path] = {"code": 60001, "errmsg": "已抢光"}
        t0 = time.time()
        report = flows.loop_run([dict(AUTH)], config=cfg,
                                minutes=0.5, interval=0.01)
        items = report["acc-1"]
        # 连续抢光达到阈值后停止重试并提前结束（远早于 0.5 分钟上限）
        self.assertLess(time.time() - t0, 20)
        self.assertTrue(all(i["status"] == "out_of_stock" for i in items))

    def test_loop_auth_expired_stops_immediately(self):
        cfg = Config()
        self.routes[Config().grant_path] = {"code": 873, "errmsg": "重新登录"}
        report = flows.loop_run([dict(AUTH)], config=cfg,
                                minutes=0.5, interval=0.01)
        items = report["acc-1"]
        self.assertTrue(all(i["status"] == "auth_expired" for i in items))


class SingleRunTest(unittest.TestCase):
    """P1：single_run 行为回归（状态校验失败可区分、不中断领取）。"""

    def setUp(self):
        self._orig = api_client.requests.Session
        self.sessions = []

    def tearDown(self):
        api_client.requests.Session = self._orig

    def _patch(self, routes):
        def factory():
            s = RoutingSession(routes)
            self.sessions.append(s)
            return s
        api_client.requests.Session = factory

    def test_single_run_success(self):
        cfg = Config()
        brand_coupons = {
            "code": 200,
            "result": {"brands": [{
                "brandId": "b1", "brandName": "霸王茶姬",
                "superCoupons": [
                    {"couponId": "c1", "couponName": "【5折外卖券】立减20",
                     "couponType": "PHONE_REWARD"},
                ]}]}}
        self._patch({
            cfg.info_path: brand_coupons,
            cfg.grant_status_path: {"code": 200, "result": {"grantItems": []}},
            cfg.grant_path: {"code": 200, "result": {"winPrizeInfo": {"p": 1}}},
        })
        report, any_error = flows.single_run([dict(AUTH)], config=cfg)
        self.assertFalse(any_error)
        self.assertEqual(report["acc-1"][0]["status"], "granted")

    def test_single_run_status_check_failure_logged_and_continues(self):
        cfg = Config()
        brand_coupons = {
            "code": 200,
            "result": {"brands": [{
                "brandId": "b1", "brandName": "霸王茶姬",
                "superCoupons": [
                    {"couponId": "c1", "couponName": "券A",
                     "couponType": "PHONE_REWARD"},
                ]}]}}
        self._patch({
            cfg.info_path: brand_coupons,
            # grant-status 失败（873），但领取本身成功 —— 失败被记录且不中断
            cfg.grant_status_path: {"code": 873, "errmsg": "登录失效"},
            cfg.grant_path: {"code": 200, "result": {"winPrizeInfo": {"p": 1}}},
        })
        report, any_error = flows.single_run([dict(AUTH)], config=cfg)
        self.assertFalse(any_error)
        self.assertEqual(report["acc-1"][0]["status"], "granted")

    def test_single_run_snipe_only_skips_non_target(self):
        """single_run_snipe_only=True：探针券（满28减10）既不领取也不进报告。"""
        cfg = Config(single_run_snipe_only=True)
        granted = []

        def grant_handler(body):
            granted.append(body["superCouponId"])
            return {"code": 200, "result": {"winPrizeInfo": {"p": 1}}}

        brand_coupons = {
            "code": 200,
            "result": {"brands": [{
                "brandId": "b1", "brandName": "霸王茶姬",
                "superCoupons": [
                    {"couponId": "c1", "couponName": "【5折外卖券】立减20",
                     "couponType": "PHONE_REWARD"},
                    {"couponId": "c2", "couponName": "【外卖券】满28减10",
                     "couponType": "PHONE_REWARD"},
                ]}]}}
        self._patch({
            cfg.info_path: brand_coupons,
            cfg.grant_status_path: {"code": 200, "result": {"grantItems": []}},
            cfg.grant_path: grant_handler,
        })
        report, any_error = flows.single_run([dict(AUTH)], config=cfg)
        self.assertFalse(any_error)
        self.assertEqual([i["coupon"] for i in report["acc-1"]],
                         ["【5折外卖券】立减20"])
        self.assertEqual(granted, ["c1"])   # 探针券没有被领取

    def test_single_run_snipe_only_false_keeps_all(self):
        """默认 False：单次执行仍覆盖品牌下全部可领券。"""
        cfg = Config()                       # single_run_snipe_only 默认 False
        self.assertFalse(cfg.single_run_snipe_only)
        brand_coupons = {
            "code": 200,
            "result": {"brands": [{
                "brandId": "b1", "brandName": "霸王茶姬",
                "superCoupons": [
                    {"couponId": "c1", "couponName": "【5折外卖券】立减20",
                     "couponType": "PHONE_REWARD"},
                    {"couponId": "c2", "couponName": "【外卖券】满28减10",
                     "couponType": "PHONE_REWARD"},
                ]}]}}
        self._patch({
            cfg.info_path: brand_coupons,
            cfg.grant_status_path: {"code": 200, "result": {"grantItems": []}},
            cfg.grant_path: {"code": 200, "result": {"winPrizeInfo": {"p": 1}}},
        })
        report, _ = flows.single_run([dict(AUTH)], config=cfg)
        self.assertEqual(len(report["acc-1"]), 2)


class StderrAndRetryTest(unittest.TestCase):
    """收尾批次：日志走 stderr、默认 session 连接级重试。"""

    def test_runlogger_writes_stderr_not_stdout(self):
        import io
        import sys as _sys
        from meituan.flows import RunLogger
        out, err = io.StringIO(), io.StringIO()
        old_o, old_e = _sys.stdout, _sys.stderr
        _sys.stdout, _sys.stderr = out, err
        try:
            with RunLogger(None) as lg:
                lg.log("hello")
        finally:
            _sys.stdout, _sys.stderr = old_o, old_e
        self.assertEqual(out.getvalue(), "")
        self.assertIn("hello", err.getvalue())

    def test_default_session_has_connect_retry_only(self):
        from meituan.api_client import ApiClient
        client = ApiClient(dict(AUTH))  # 自建 session
        try:
            adapter = client.session.get_adapter("https://inf.ds.163.com/x")
            self.assertEqual(adapter.max_retries.connect, 2)
            self.assertEqual(adapter.max_retries.read, 0)
            self.assertEqual(adapter.max_retries.status, 0)
        finally:
            client.close()

    def test_injected_session_not_modified(self):
        from meituan.api_client import ApiClient
        s = RoutingSession({})
        client = ApiClient(dict(AUTH), session=s)
        self.assertIs(client.session, s)


class LoopInterruptTest(unittest.TestCase):
    """收尾批次：Ctrl+C（KeyboardInterrupt）不裸退，仍走统计与状态校验。"""

    def setUp(self):
        self._orig = api_client.requests.Session
        cfg = Config()
        self.grant_calls = []

        def grant_handler(body):
            self.grant_calls.append(body["superCouponId"])
            if len(self.grant_calls) >= 2:
                raise KeyboardInterrupt("模拟 Ctrl+C")
            return {"code": 200, "result": {"winPrizeInfo": {"prize": "ok"}}}

        routes = {
            cfg.grant_path: grant_handler,
            cfg.info_path: {"code": 200, "result": {"brands": []}},
            cfg.grant_status_path: lambda body: {
                "code": 200, "result": {"grantItems": [
                    {"couponId": cid, "status": "GRANTED"}
                    for cid in body["superCouponIds"]]}},
        }
        api_client.requests.Session = lambda: RoutingSession(routes)

    def tearDown(self):
        api_client.requests.Session = self._orig

    def test_loop_run_survives_keyboard_interrupt(self):
        report = flows.loop_run([dict(AUTH)], config=Config(),
                                minutes=0.5, interval=0.05)
        items = report["acc-1"]
        self.assertTrue(items)  # 未崩溃，收尾报告照常产出

    def test_single_run_survives_keyboard_interrupt(self):
        cfg = Config()
        routes = {
            cfg.info_path: {
                "code": 200,
                "result": {"brands": [{
                    "brandId": "b1", "brandName": "霸王茶姬",
                    "superCoupons": [
                        {"couponId": "c1", "couponName": "券A",
                         "couponType": "PHONE_REWARD"}]}]}},
            cfg.grant_status_path: {"code": 200, "result": {"grantItems": []}},
            cfg.grant_path: KeyboardInterrupt("模拟 Ctrl+C"),
        }
        api_client.requests.Session = lambda: RoutingSession(routes)
        report, any_error = flows.single_run([dict(AUTH)], config=cfg)
        self.assertTrue(any_error)  # 中断被记录而非冒泡崩溃


class CouponModelTest(unittest.TestCase):
    """评审第14项：领域模型。API 边界转换、未知字段透传、售罄语义。"""

    def test_from_api_roundtrip_preserves_raw(self):
        from meituan.models import Coupon
        raw = {"couponId": "c1", "couponName": "n", "couponType": "PHONE_REWARD",
               "leftStock": 5, "unknownField": {"x": 1}}
        c = Coupon.from_api(raw)
        self.assertEqual((c.coupon_id, c.coupon_name, c.coupon_type),
                         ("c1", "n", "PHONE_REWARD"))
        self.assertTrue(c.is_phone_reward())
        self.assertFalse(c.sold_out())
        d = c.to_dict()
        self.assertEqual(d["unknownField"], {"x": 1})
        self.assertEqual(d["couponId"], "c1")

    def test_sold_out_only_when_zero(self):
        from meituan.models import Coupon
        self.assertTrue(Coupon.from_api({"couponId": "c", "leftStock": 0}).sold_out())
        # leftStock 未知（None）按未抢光处理，与历史 `== 0` 判断一致
        self.assertFalse(Coupon.from_api({"couponId": "c"}).sold_out())
        self.assertFalse(Coupon.from_api({"couponId": "c", "leftStock": 3}).sold_out())

    def test_grant_event_named_fields(self):
        from meituan.models import GrantEvent
        ev = GrantEvent("ts", "acc", "券", "granted", 0.5)
        self.assertEqual((ev.send_ts, ev.label, ev.status), ("ts", "acc", "granted"))

    def test_try_grant_skips_placeholder_and_direct_link(self):
        from meituan.api_client import ApiClient
        from meituan.flows import try_grant
        from meituan.models import Coupon
        client = ApiClient(dict(AUTH), session=RoutingSession({}))
        status, _, send_ts = try_grant(client, "b",
                                       Coupon(coupon_id="x",
                                              coupon_type="PLACEHOLDER"))
        self.assertEqual(status, "skipped")
        self.assertIsNone(send_ts)   # 没发请求就没有发送时刻
        status, detail, _ = try_grant(client, "b",
                                      Coupon(coupon_id="x",
                                             coupon_type="DIRECT_LINK",
                                             direct_link="http://jump"))
        self.assertEqual(status, "direct_link")
        self.assertIn("jump", detail)
        status, _, _ = try_grant(client, "b",
                              Coupon(coupon_id="x", left_stock=0))
        self.assertEqual(status, "out_of_stock")


if __name__ == "__main__":
    unittest.main()