#!/usr/bin/env python3
"""真实运行数据驱动的改进（1.10.0）：多账号单文件、自适应并发、
发送时刻精度、开火提前量。

依据：2026-10-09 23:59 实测成功日志（提前 0.3s 开火、4 请求同时刻发出、
响应 1.78~3.17s）与 2026-10-10 起「三号并入 cookies.json」的实际凭据形态。
全部 mock / 本地临时文件，不访问真实第三方接口。
运行：python -m unittest discover -s tests -t . -v
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

from meituan import cli, flows
from meituan.api_client import ApiClient
from meituan.config import Config, load_config
from meituan.models import Coupon
from meituan.pacing import GrantPacing
from meituan.security import load_auth, load_auths, update_auth_cookies

REPO_ROOT = Path(__file__).resolve().parent.parent


def ts_to_epoch(text):
    """beijing_ts() 的分数是百分之一秒，strptime 的 %f 会当成微秒，
    这里按真实语义换算回来。"""
    date_part, cs = text.rsplit(".", 1)
    return (time.mktime(time.strptime(date_part, "%Y-%m-%d %H:%M:%S"))
            + int(cs) / 100.0)


def account(label, token, uid, dev, jsid="js-original"):
    return {"label": label, "GL-XSRF-TOKEN": token, "GOD_UUID": uid,
            "device_id": dev, "cookies": {"JSESSIONID": jsid}}


class FakeJar:
    """requests 的 cookiejar 替身：items() 返回 (name, value) 列表。"""

    def __init__(self, cookies):
        self._items = list(cookies.items() if isinstance(cookies, dict)
                           else cookies)

    def items(self):
        return self._items


class FakeResp:
    def __init__(self, payload, set_cookies=None):
        self.status_code = 200
        self._payload = payload
        self.text = json.dumps(payload)
        self.cookies = FakeJar(set_cookies or {})

    def json(self):
        return self._payload


class FakeSession:
    """一次响应，可带 Set-Cookie。"""

    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append((url, data, headers))
        return self.resp

    def close(self):
        pass


# ---------------------------------------------------------------------------
# 多账号单文件（顶层数组）
# ---------------------------------------------------------------------------

class MultiAccountFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, payload, name="cookies.json"):
        (self.dir / name).write_text(json.dumps(payload, ensure_ascii=False),
                                     encoding="utf-8")
        return self.dir / name

    def test_loads_all_entries_with_labels_and_index(self):
        self.write([account("老号", "tok-a", "uid-a", "dev-a"),
                    account("新号", "tok-b", "uid-b", "dev-b")])
        auths = load_auths(["cookies.json"], base_dir=self.dir)
        self.assertEqual(["老号", "新号"], [a["label"] for a in auths])
        self.assertEqual([0, 1], [a["_auth_index"] for a in auths])
        self.assertEqual("tok-b", auths[1]["GL-XSRF-TOKEN"])

    def test_missing_labels_get_position_suffix(self):
        entries = []
        for token, uid, dev in (("tok-c", "uid-c", "dev-c"),
                                ("tok-d", "uid-d", "dev-d")):
            entry = account("占位", token, uid, dev)
            del entry["label"]          # 模拟数组条目里没写 label
            entries.append(entry)
        self.write(entries)
        auths = load_auths(["cookies.json"], base_dir=self.dir)
        self.assertEqual(["cookies.json#0", "cookies.json#1"],
                         [a["label"] for a in auths])

    def test_duplicate_labels_are_disambiguated(self):
        # label 是客户端字典/退避表/报告的键，重复会静默顶掉账号
        self.write([account("同号", "tok-1", "uid-1", "dev-1"),
                    account("同号", "tok-2", "uid-2", "dev-2"),
                    account("同号", "tok-3", "uid-3", "dev-3")])
        auths = load_auths(["cookies.json"], base_dir=self.dir)
        self.assertEqual(["同号#1", "同号#2", "同号#3"],
                         [a["label"] for a in auths])

    def test_single_object_file_has_no_index(self):
        self.write(account("单号", "tok-s", "uid-s", "dev-s"))
        auths = load_auths(["cookies.json"], base_dir=self.dir)
        self.assertEqual(1, len(auths))
        self.assertNotIn("_auth_index", auths[0])

    def test_entry_missing_field_reports_index_not_values(self):
        bad = account("缺字段", "tok-x", "", "dev-x")
        self.write([account("好号", "tok-ok", "uid-ok", "dev-ok"), bad])
        with self.assertRaises(ValueError) as cm:
            load_auths(["cookies.json"], base_dir=self.dir)
        self.assertIn("cookies.json[1]", str(cm.exception))
        self.assertIn("GOD_UUID", str(cm.exception))
        self.assertNotIn("tok-ok", str(cm.exception))   # 不泄漏任何值

    def test_non_object_entry_rejected(self):
        self.write(["just-a-string"])
        with self.assertRaises(ValueError):
            load_auths(["cookies.json"], base_dir=self.dir)

    def test_load_auth_rejects_array_file(self):
        self.write([account("老号", "tok-a", "uid-a", "dev-a")])
        with self.assertRaises(ValueError) as cm:
            load_auth("cookies.json", base_dir=self.dir)
        self.assertIn("load_auths", str(cm.exception))

    def test_missing_files_are_skipped(self):
        self.write(account("老号", "tok-a", "uid-a", "dev-a"))
        auths = load_auths(["cookies.json", "nope.json"], base_dir=self.dir)
        self.assertEqual(1, len(auths))


class UpdateAuthCookiesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.path = self.dir / "cookies.json"
        self.path.write_text(json.dumps([
            account("老号", "tok-a", "uid-a", "dev-a", jsid="js-a"),
            account("新号", "tok-b", "uid-b", "dev-b", jsid="js-b"),
        ], ensure_ascii=False), encoding="utf-8")

    def test_updates_only_target_entry(self):
        # 关键正确性：按条目回写绝不能抹掉同文件里的其他账号
        update_auth_cookies({"JSESSIONID": "js-a-new", "GL-XSRF-TOKEN": "tok-a"},
                            self.path, index=0)
        saved = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual("js-a-new", saved[0]["cookies"]["JSESSIONID"])
        self.assertEqual("js-b", saved[1]["cookies"]["JSESSIONID"])
        self.assertEqual("新号", saved[1]["label"])
        self.assertEqual("uid-b", saved[1]["GOD_UUID"])

    def test_single_object_mode_when_no_index(self):
        obj = self.dir / "solo.json"
        obj.write_text(json.dumps(account("单号", "tok-s", "uid-s", "dev-s"),
                                  ensure_ascii=False), encoding="utf-8")
        update_auth_cookies({"JSESSIONID": "js-s-new"}, obj, index=None)
        saved = json.loads(obj.read_text(encoding="utf-8"))
        self.assertEqual("js-s-new", saved["cookies"]["JSESSIONID"])
        self.assertEqual("单号", saved["label"])

    def test_out_of_range_index_errors(self):
        with self.assertRaises(ValueError):
            update_auth_cookies({"JSESSIONID": "x"}, self.path, index=5)

    def test_index_required_for_array_file(self):
        with self.assertRaises(ValueError):
            update_auth_cookies({"JSESSIONID": "x"}, self.path, index=None)

    def test_no_tmp_leftovers(self):
        update_auth_cookies({"JSESSIONID": "js-a-new"}, self.path, index=0)
        self.assertEqual([], list(self.dir.glob("*.tmp")))


class RotationPersistsPerEntryTest(unittest.TestCase):
    """两个账号同在一个数组文件里，各自轮换互不覆盖。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        (self.dir / "cookies.json").write_text(json.dumps([
            account("老号", "tok-a", "uid-a", "dev-a", jsid="js-a"),
            account("新号", "tok-b", "uid-b", "dev-b", jsid="js-b"),
        ], ensure_ascii=False), encoding="utf-8")
        self.auths = load_auths(["cookies.json"], base_dir=self.dir)

    def test_each_client_updates_its_own_entry(self):
        for i, auth in enumerate(self.auths):
            resp = FakeResp({"code": 200, "result": {}},
                            set_cookies={"JSESSIONID": "js-new-%d" % i})
            client = ApiClient(auth, config=Config(), session=FakeSession(resp))
            client.coupon_info()
        saved = json.loads((self.dir / "cookies.json").read_text(
            encoding="utf-8"))
        self.assertEqual("js-new-0", saved[0]["cookies"]["JSESSIONID"])
        self.assertEqual("js-new-1", saved[1]["cookies"]["JSESSIONID"])
        self.assertEqual(["老号", "新号"], [e["label"] for e in saved])
        self.assertEqual("tok-b", saved[1]["GL-XSRF-TOKEN"])


# ---------------------------------------------------------------------------
# 第一波并发与线程池随账号数自适应
# ---------------------------------------------------------------------------

class AdaptiveConcurrencyTest(unittest.TestCase):
    def test_default_inflight_covers_three_accounts(self):
        # 实测：2 账号 4 并发、3 账号 6 并发，单波 0.15s 内打完不触发 40007
        self.assertEqual(6, Config().first_wave_inflight)

    def test_pacing_gate_uses_config_value(self):
        cfg = Config()
        pacing = GrantPacing(cfg.first_wave_gap, cfg.first_wave_inflight,
                             cfg.sustained_gap, cfg.sustained_inflight)
        self.assertEqual(6, pacing.gate.max_inflight)

    def _runner(self, n_accounts):
        auths = [account("号%d" % i, "tok-%d" % i, "uid-%d" % i, "dev-%d" % i)
                 for i in range(n_accounts)]
        runner = flows.LoopRunner(auths, config=Config(), minutes=0.01,
                                  interval=0.01)
        self.addCleanup(lambda: [c.close() for c in runner.clients.values()])
        return runner

    def test_pool_workers_scale_with_accounts(self):
        # 每账号（3 张目标券：2 张5折 + 满28减10 + 1 个刷新任务）+ 1 余量：
        # 2 账号 -> 9，3 账号 -> 13
        self.assertEqual(9, self._runner(2).pool_workers)
        self.assertEqual(13, self._runner(3).pool_workers)

    def test_one_client_per_account_label(self):
        runner = self._runner(3)
        self.assertEqual(3, len(runner.clients))
        self.assertEqual({"号0", "号1", "号2"}, set(runner.clients))


# ---------------------------------------------------------------------------
# 发送时刻：限速/闸门等到之后、POST 之前才取
# ---------------------------------------------------------------------------

class SendTimestampTest(unittest.TestCase):
    TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{2}$")

    def _client(self):
        auth = account("号", "tok-p", "uid-p", "dev-p")
        resp = FakeResp({"code": 200, "result": {"winPrizeInfo": {"p": 1}}})
        return ApiClient(auth, config=Config(), session=FakeSession(resp))

    def test_send_ts_format_and_presence(self):
        status, detail, send_ts = flows.try_grant(
            self._client(), "b", Coupon(coupon_id="c1", coupon_type="PHONE_REWARD"))
        self.assertEqual("granted", status)
        self.assertRegex(send_ts, self.TS_RE)

    def test_send_ts_reflects_pacing_wait(self):
        """关键：send_ts 必须在限速等待之后，否则第一波统计全是同一时刻
        （昨晚日志就是 4 个请求都记成 23:59:59.70，看不出错峰）。"""
        client = self._client()
        coupon = Coupon(coupon_id="c1", coupon_type="PHONE_REWARD")
        pacing = GrantPacing(0.2, 4, 0.5, 2)
        _, _, first = flows.try_grant(client, "b", coupon, pacing=pacing)
        _, _, second = flows.try_grant(client, "b", coupon, pacing=pacing)
        self.assertGreaterEqual(ts_to_epoch(second) - ts_to_epoch(first), 0.15)

    def test_no_request_no_send_ts(self):
        _, _, send_ts = flows.try_grant(
            self._client(), "b", Coupon(coupon_id="c1", left_stock=0))
        self.assertIsNone(send_ts)


# ---------------------------------------------------------------------------
# 开火提前量（RTT 补偿）
# ---------------------------------------------------------------------------

class FireLeadTest(unittest.TestCase):
    def test_config_default_and_env_override(self):
        self.assertEqual(0.0, Config().fire_lead)
        os.environ["MEITUAN_FIRE_LEAD"] = "0.3"
        try:
            self.assertEqual(0.3, load_config().fire_lead)
        finally:
            del os.environ["MEITUAN_FIRE_LEAD"]

    def test_cli_forwards_fire_lead(self):
        captured = {}

        def fake_loop_run(auths, config=None, **kw):
            captured["cfg"] = config
            captured["kw"] = kw
            return {"号": [{"coupon": "A", "status": "granted"}]}

        with mock.patch.object(cli, "_load_auths",
                               return_value=[account("号", "t", "u", "d")]), \
                mock.patch.object(cli, "loop_run", fake_loop_run), \
                contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["--loop", "--fire-at", "10:00:00.000",
                             "--fire-lead", "0.3"])
        self.assertEqual(0, code)
        self.assertEqual(0.3, captured["cfg"].fire_lead)
        self.assertEqual("10:00:00.000", captured["cfg"].fire_at)

    def test_lead_makes_past_target_return_immediately(self):
        # 目标 0.5s 后，但提前量 2s -> 实际开火时刻已过，应立即返回
        tz = ZoneInfo("Asia/Shanghai")
        target = datetime.now(tz) + timedelta(milliseconds=500)
        t0 = time.time()
        flows.wait_until(target.strftime("%H:%M:%S.%f")[:-3], lead=2.0)
        self.assertLess(time.time() - t0, 0.3)

    def test_zero_lead_still_waits(self):
        tz = ZoneInfo("Asia/Shanghai")
        target = datetime.now(tz) + timedelta(milliseconds=300)
        t0 = time.time()
        flows.wait_until(target.strftime("%H:%M:%S.%f")[:-3], lead=0.0)
        self.assertGreaterEqual(time.time() - t0, 0.25)


# ---------------------------------------------------------------------------
# 时钟校验：无输出时给出可诊断的信息（实测遇过 timedatectl 返回空）
# ---------------------------------------------------------------------------

class ClockCheckMessageTest(unittest.TestCase):
    def test_empty_output_includes_returncode(self):
        runner = flows.LoopRunner([account("号", "t", "u", "d")],
                                  config=Config(), minutes=0.01, interval=0.01)
        self.addCleanup(lambda: [c.close() for c in runner.clients.values()])
        lines = []
        runner.logger.log = lines.append
        fake = mock.Mock(stdout="", stderr="Not built with systemd",
                         returncode=1)
        # _check_clock 只在 Linux 走 timedatectl，这里把平台伪装成 linux
        with mock.patch.object(flows, "sys") as fake_sys, \
                mock.patch.object(flows, "subprocess") as sp:
            fake_sys.platform = "linux"
            sp.run.return_value = fake
            runner._check_clock()
        self.assertEqual(1, len(lines))
        self.assertIn("无输出", lines[0])
        self.assertIn("rc=1", lines[0])
        self.assertIn("systemd", lines[0])

    def test_non_linux_platform_records_skip(self):
        runner = flows.LoopRunner([account("号", "t", "u", "d")],
                                  config=Config(), minutes=0.01, interval=0.01)
        self.addCleanup(lambda: [c.close() for c in runner.clients.values()])
        lines = []
        runner.logger.log = lines.append
        with mock.patch.object(flows, "sys") as fake_sys, \
                mock.patch.object(flows, "subprocess") as sp:
            fake_sys.platform = "darwin"   # 非 Linux：应记为跳过且不调用 subprocess
            runner._check_clock()
        self.assertIn("跳过", lines[0])
        if not sys.platform.startswith("linux"):
            sp.run.assert_not_called()


# ---------------------------------------------------------------------------
# 导出工具并入多账号数组文件（三号并一文件的实际维护路径）
# ---------------------------------------------------------------------------

def _load_tool(name):
    """tools/ 不是包，按文件路径加载（被测对象是独立可执行脚本）。"""
    path = REPO_ROOT / "tools" / ("%s.py" % name)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cookie_tool = _load_tool("import_cookie_export")

EXPORT_JS = [
    {"name": "JSESSIONID", "value": "js-live", "domain": ".ds.163.com"},
    {"name": "GL-XSRF-TOKEN", "value": "tok-live", "domain": ".ds.163.com"},
    {"name": "GOD_UUID", "value": "uid-live", "domain": ".ds.163.com"},
    {"name": "ds-website-uuid", "value": "dev-live", "domain": ".ds.163.com"},
]


class MergeIntoArrayFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        (self.dir / "cookies.json").write_text(json.dumps([
            account("老号", "tok-a", "uid-a", "dev-a", jsid="js-a"),
        ], ensure_ascii=False), encoding="utf-8")
        self.src = self.dir / "export.json"
        self.src.write_text(json.dumps(EXPORT_JS), encoding="utf-8")

    def _run(self, extra):
        err, out = io.StringIO(), io.StringIO()
        with mock.patch.object(cookie_tool, "DIR", self.dir):
            with contextlib.redirect_stderr(err), \
                    contextlib.redirect_stdout(out):
                code = cookie_tool.main(
                    [str(self.src), "-o", "cookies.json"] + extra)
        return code, err.getvalue() + out.getvalue()

    def _saved(self):
        return json.loads(
            (self.dir / "cookies.json").read_text(encoding="utf-8"))

    def test_append_new_label_keeps_other_accounts(self):
        self.assertEqual(0, self._run(["--merge", "--label", "小号"])[0])
        saved = self._saved()
        self.assertEqual(["老号", "小号"], [e["label"] for e in saved])
        self.assertEqual("js-a", saved[0]["cookies"]["JSESSIONID"])  # 原账号不动
        self.assertEqual("js-live", saved[1]["cookies"]["JSESSIONID"])
        self.assertEqual("tok-live", saved[1]["GL-XSRF-TOKEN"])

    def test_same_label_replaces_that_entry_only(self):
        self.assertEqual(0, self._run(["--merge", "--label", "老号"])[0])
        saved = self._saved()
        self.assertEqual(1, len(saved))
        self.assertEqual("js-live", saved[0]["cookies"]["JSESSIONID"])

    def test_output_never_contains_secret_values(self):
        code, text = self._run(["--merge", "--label", "小号"])
        self.assertEqual(0, code)
        for secret in ("tok-live", "uid-live", "dev-live", "js-live",
                       "tok-a", "uid-a"):
            self.assertNotIn(secret, text)

    def test_merge_rolls_back_when_export_incomplete(self):
        bad = [c for c in EXPORT_JS if c["name"] != "GOD_UUID"]
        self.src.write_text(json.dumps(bad), encoding="utf-8")
        code, text = self._run(["--merge", "--label", "小号"])
        self.assertEqual(1, code)
        self.assertIn("GOD_UUID", text)
        self.assertEqual(["老号"], [e["label"] for e in self._saved()])  # 账号没丢


if __name__ == "__main__":
    unittest.main()
