#!/usr/bin/env python3
"""1.20.0 回归测试：预热并行 / 自适应 lead / 首波全抢光提前收工。

背景：2026-10-12 零点场 0/6。复盘发现 worker 23:59:57 即执行脚本
（27s，正常），但三账号串行预热 6.5s 跨过午夜，触发 wait_until
跨零点 bug 致进程假死；重跑时 00:00:49 已抢光。券约 1 秒内抢完，
首波到达窗口 T+0.0~0.75 已踩线，需压缩一切可压缩项。

全部 mock，不访问真实第三方接口。
运行：python -m unittest discover -s tests -t .
"""
import json
import time
import unittest
from unittest import mock

from chagee import api_client
from chagee import flows
from chagee.config import Config

AUTH = {
    "GL-XSRF-TOKEN": "tok-SECRET-abcdef123456",
    "GOD_UUID": "uid-SECRET-ffeeddccbb11",
    "device_id": "dev-SECRET-0011223344",
}


def auth(label):
    a = dict(AUTH)
    a["label"] = label
    return a


class FakeResponse:
    def __init__(self, payload):
        self.status_code = 200
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class RoutingSession:
    """按 URL 路径路由 mock 响应；记录每次调用的 URL 供断言。"""

    def __init__(self, routes):
        self.routes = dict(routes)
        self.calls = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append(url)
        path = url.split("inf.ds.163.com", 1)[-1]
        for key, handler in self.routes.items():
            if path.endswith(key):
                body = json.loads(data.decode("utf-8")) if data else {}
                payload = handler(body) if callable(handler) else handler
                return FakeResponse(payload)
        raise AssertionError("未配置路由的 URL: %s" % url)

    def close(self):
        pass


SOLDOUT = {"code": 60001, "errmsg": "已抢光"}


# ---------------------------------------------------------------------------
# #2 预热并行：3 账号并发预热，总耗时 ~max 而非 ~sum
# ---------------------------------------------------------------------------

class PreheatParallelTest(unittest.TestCase):
    def test_preheat_runs_accounts_concurrently(self):
        auths = [auth("号%d" % i) for i in range(3)]
        runner = flows.LoopRunner(auths, config=Config(), minutes=0.01,
                                  interval=0.01, fire_at="23:59:59")
        self.addCleanup(lambda: [c.close() for c in runner.clients.values()])

        calls = []

        def fake_grant_status(ids):
            calls.append(time.time())
            time.sleep(0.3)
            return {}

        for c in runner.clients.values():
            c.grant_status = fake_grant_status

        with mock.patch.object(flows, "wait_until") as wu:
            t0 = time.perf_counter()
            runner._preheat_and_wait()
            elapsed = time.perf_counter() - t0

        self.assertEqual(3, len(calls))
        # 串行下限 0.9s；并行应远小于它（留足 CI 抖动余量）
        self.assertLess(elapsed, 0.75,
                        "预热疑似串行：3×0.3s 用了 %.2fs" % elapsed)
        wu.assert_called_once()
        lead = wu.call_args[0][1]
        self.assertGreaterEqual(lead, 0.2)
        self.assertLessEqual(lead, 0.6)


# ---------------------------------------------------------------------------
# #4 自适应 lead：预热 RTT 中位数 * 0.2，钳制 [0.2, 0.6]
# ---------------------------------------------------------------------------

class AdaptiveLeadTest(unittest.TestCase):
    def _runner(self, **kw):
        cfg = Config(**kw)
        r = flows.LoopRunner([auth("号")], config=cfg,
                             minutes=0.01, interval=0.01)
        self.addCleanup(lambda: [c.close() for c in r.clients.values()])
        return r

    def test_typical_rtt_anchors_proven_point(self):
        # RTT 1.5s -> 0.3s，恰为 10-11 实测验证过的固定值
        self.assertAlmostEqual(0.3, self._runner()._adaptive_lead({"a": 1.5}))

    def test_median_of_three(self):
        r = self._runner()
        self.assertAlmostEqual(0.56, r._adaptive_lead(
            {"a": 2.5, "b": 3.0, "c": 2.8}))

    def test_slow_network_capped(self):
        self.assertAlmostEqual(0.6, self._runner()._adaptive_lead({"a": 5.0}))

    def test_fast_network_floored(self):
        self.assertAlmostEqual(0.2, self._runner()._adaptive_lead({"a": 0.5}))

    def test_disabled_falls_back_to_fire_lead(self):
        r = self._runner(adaptive_lead=False, fire_lead=0.3)
        self.assertAlmostEqual(0.3, r._adaptive_lead({"a": 5.0}))

    def test_empty_rtts_falls_back(self):
        r = self._runner(fire_lead=0.3)
        self.assertAlmostEqual(0.3, r._adaptive_lead({}))


# ---------------------------------------------------------------------------
# #3 首波全抢光提前收工：首波 6 发全 60001 -> 确认一波 -> 收工
# ---------------------------------------------------------------------------

class EarlyStopTest(unittest.TestCase):
    def setUp(self):
        self._orig = api_client.requests.Session
        self.sessions = []
        self.routes = {}
        cfg = Config()

        def factory():
            s = RoutingSession(self.routes)
            self.sessions.append(s)
            return s

        api_client.requests.Session = factory
        self.cfg = cfg

    def tearDown(self):
        api_client.requests.Session = self._orig

    def _grant_calls(self):
        return sum(u.endswith(self.cfg.grant_path)
                   for s in self.sessions for u in s.calls)

    def _base_routes(self, grant_handler):
        return {
            self.cfg.grant_path: grant_handler,
            self.cfg.info_path: {"code": 200, "result": {"brands": []}},
            self.cfg.grant_status_path: {"code": 200,
                                         "result": {"grantItems": []}},
        }

    def _auths(self):
        return [auth("号%d" % i) for i in range(3)]

    def test_all_soldout_stops_after_confirmation_wave(self):
        """首波 6 发全 60001，确认波仍全 60001 -> 第 2 波后收工（12 次请求）。"""
        self.routes.update(self._base_routes(SOLDOUT))
        cfg = Config(early_stop_all_soldout=True)
        report = flows.loop_run(self._auths(), config=cfg,
                                minutes=0.5, interval=0.05)
        self.assertEqual(12, self._grant_calls())
        for items in report.values():
            self.assertTrue(all(i["status"] == "out_of_stock" for i in items))

    def test_disabled_runs_original_logic(self):
        """开关关闭时走原逻辑：连续 3 次抢光才停（18 次请求）。"""
        self.routes.update(self._base_routes(SOLDOUT))
        cfg = Config(early_stop_all_soldout=False)
        flows.loop_run(self._auths(), config=cfg, minutes=0.5, interval=0.05)
        self.assertEqual(18, self._grant_calls())

    def test_granted_in_wave2_does_not_trigger(self):
        """确认波出现 granted（非全抢光）-> 不提前收工，继续正常循环。"""
        calls = []

        def grant_handler(body):
            calls.append(1)
            if len(calls) <= 11:
                return SOLDOUT
            return {"code": 200, "result": {"winPrizeInfo": {"p": 1}}}

        self.routes.update(self._base_routes(grant_handler))
        cfg = Config(early_stop_all_soldout=True)
        flows.loop_run(self._auths(), config=cfg, minutes=0.5, interval=0.05)
        # 第 1 波 6 发 + 第 2 波 6 发 + 第 3 波 5 发（1 张已 granted）= 17
        self.assertEqual(17, self._grant_calls())


if __name__ == "__main__":
    unittest.main()
