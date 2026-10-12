#!/usr/bin/env python3
"""评审批次回归测试（1.9.0）：凭据临时文件加固、loop 退出码、CLI 校验、
探针券单一真源、事件 JSONL 落盘、开火等待精度。

全部 mock / 本地临时文件，不访问真实第三方接口。
运行：python -m unittest discover -s tests -t . -v
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

from chagee import cli, flows
from chagee.config import Config, load_config
from chagee.models import GrantEvent
from chagee.security import load_auth, save_auth

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_tool(name):
    """tools/ 不是包，按文件路径加载（被测对象是独立可执行脚本）。"""
    path = REPO_ROOT / "tools" / ("%s.py" % name)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cookie_tool = _load_tool("import_cookie_export")

AUTH = {
    "GL-XSRF-TOKEN": "xsrf-token-value",
    "GOD_UUID": "god-uuid-value",
    "device_id": "device-id-value",
    "cookies": {"JSESSIONID": "js-original"},
}


def write_auth(dirpath, name="cookies.json", **over):
    """在临时目录写一份合法认证文件，返回路径。"""
    data = dict(AUTH, **over)
    p = Path(dirpath) / name
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.chmod(p, 0o600)   # 固定 600：umask（如 0007）下默认会是 660，触发权限警告
    return p


# ---------------------------------------------------------------------------
# P0a：save_auth 中转文件加固（崩溃残留不得带凭据长期躺在磁盘上）
# ---------------------------------------------------------------------------

class SaveAuthTmpHardeningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.path = write_auth(self.dir)
        self.addCleanup(self.tmp.cleanup)

    def test_successful_save_leaves_no_tmp(self):
        auth = load_auth(self.path.name, base_dir=self.dir)
        auth["cookies"]["JSESSIONID"] = "js-rotated"
        save_auth(auth, self.path)
        self.assertEqual([], list(self.dir.glob("*.tmp")))
        self.assertEqual("js-rotated",
                         json.loads(self.path.read_text(encoding="utf-8"))
                         ["cookies"]["JSESSIONID"])

    def test_tmp_name_carries_pid_and_failure_cleans_up(self):
        auth = load_auth(self.path.name, base_dir=self.dir)
        seen = []

        def fake_replace(src, dst):
            seen.append(Path(src).name)
            raise OSError("模拟崩溃")

        with mock.patch("os.replace", side_effect=fake_replace):
            with self.assertRaises(OSError):
                save_auth(auth, self.path)
        self.assertEqual(1, len(seen))
        self.assertTrue(seen[0].endswith(".%d.tmp" % os.getpid()), seen[0])
        # 失败后不得留下带凭据的中转文件
        self.assertEqual([], list(self.dir.glob("*.tmp")))

    def test_load_auth_removes_stale_orphan_only(self):
        stale = self.dir / "cookies.json.4242.tmp"
        stale.write_text("{}", encoding="utf-8")
        old = time.time() - 120
        os.utime(stale, (old, old))
        fresh = self.dir / "cookies.json.4343.tmp"
        fresh.write_text("{}", encoding="utf-8")

        load_auth("cookies.json", base_dir=self.dir)

        self.assertFalse(stale.exists())   # 60 秒前的残留 = 崩溃遗留，清掉
        self.assertTrue(fresh.exists())    # 在途写入不能误删

    def test_gitignore_covers_tmp_and_jsonl(self):
        ignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("*.tmp", ignore)
        self.assertIn("*.jsonl", ignore)


# ---------------------------------------------------------------------------
# 账号标识：优先取自 cookie 里的手机号（P_INFO），显式 label 仍优先
# ---------------------------------------------------------------------------

class LabelFromCookieTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _write(self, data, name="cookies.json"):
        p = self.dir / name
        p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return p

    def test_label_derived_from_p_info_phone(self):
        import urllib.parse
        p_info = urllib.parse.quote("phone=17712347689&ts=1")
        self._write(dict(AUTH, cookies={"P_INFO": p_info}))
        auth = load_auth("cookies.json", base_dir=self.dir)
        self.assertEqual("177****7689", auth["label"])

    def test_explicit_label_still_wins(self):
        import urllib.parse
        p_info = urllib.parse.quote("phone=17712347689")
        self._write(dict(AUTH, label="自定义", cookies={"P_INFO": p_info}))
        auth = load_auth("cookies.json", base_dir=self.dir)
        self.assertEqual("自定义", auth["label"])

    def test_no_phone_falls_back_to_file_name(self):
        self._write(dict(AUTH, cookies={"JSESSIONID": "j"}))
        auth = load_auth("cookies.json", base_dir=self.dir)
        self.assertEqual("cookies.json", auth["label"])


# ---------------------------------------------------------------------------
# P0b：loop 退出码必须反映实质失败
# ---------------------------------------------------------------------------

class LoopExitCodeTest(unittest.TestCase):
    def test_auth_expired_is_error(self):
        report = {"acc-1": [{"coupon": "A", "status": "auth_expired"}]}
        self.assertTrue(cli._loop_has_error(report))

    def test_error_status_is_error(self):
        report = {"acc-1": [{"coupon": "A", "status": "error"}]}
        self.assertTrue(cli._loop_has_error(report))

    def test_all_granted_is_success(self):
        report = {"acc-1": [{"coupon": "A", "status": "granted"},
                            {"coupon": "B", "status": "already_claimed"}]}
        self.assertFalse(cli._loop_has_error(report))

    def test_out_of_stock_is_not_hard_error(self):
        report = {"acc-1": [{"coupon": "A", "status": "out_of_stock"}]}
        self.assertFalse(cli._loop_has_error(report))

    def test_empty_report_is_error(self):
        self.assertTrue(cli._loop_has_error({}))


# ---------------------------------------------------------------------------
# P1：--fire-at 校验与 wait_until 精度
# ---------------------------------------------------------------------------

class FireAtValidationTest(unittest.TestCase):
    def test_accepts_valid_forms(self):
        for v in ("14:00", "14:00:00", "14:00:00.500", "9:05:01.05"):
            self.assertEqual(v, cli._fire_at(v))

    def test_rejects_bad_format(self):
        for v in ("abc", "14", "14:00:00.12345", "14-00-00", ""):
            with self.assertRaises(argparse.ArgumentTypeError):
                cli._fire_at(v)

    def test_rejects_out_of_range(self):
        for v in ("25:00", "14:70", "14:00:99"):
            with self.assertRaises(argparse.ArgumentTypeError):
                cli._fire_at(v)

    def test_wait_until_rejects_unparsable(self):
        with self.assertRaises(ValueError):
            flows.wait_until("14")

    def test_wait_until_past_hhmm_returns_immediately(self):
        tz = ZoneInfo("Asia/Shanghai")
        past = (datetime.now(tz) - timedelta(minutes=5)).strftime("%H:%M")
        t0 = time.time()
        flows.wait_until(past)
        self.assertLess(time.time() - t0, 0.5)

    def test_wait_until_honors_target(self):
        tz = ZoneInfo("Asia/Shanghai")
        target = datetime.now(tz) + timedelta(milliseconds=60)
        flows.wait_until(target.strftime("%H:%M:%S.%f")[:-3])
        self.assertGreaterEqual(time.time(), target.timestamp() - 0.002)

    def test_wait_until_cross_midnight_fires_immediately(self):
        # 回归：预热阶段跨过零点后，wait_until 不应再等 ~24 小时，
        # 而应判定开火时刻已过、立即返回（2026-10-12 零点场实测故障）。
        # datetime 与 time.time 必须一起 mock，否则测试只在 00:00~00:30
        # 能过，其它时间会真睡 ~14 小时（2026-10-12 10:12 实测卡死）。
        tz = ZoneInfo("Asia/Shanghai")
        real_datetime = datetime
        fake_now = real_datetime(2026, 10, 12, 0, 0, 4, tzinfo=tz)

        class FakeDatetime(real_datetime):
            @classmethod
            def now(cls, tzinfo=None):
                return fake_now

        with mock.patch.object(flows, "datetime", FakeDatetime), \
                mock.patch("time.time", return_value=fake_now.timestamp()):
            t0 = time.perf_counter()
            flows.wait_until("23:59:59.7")
            self.assertLess(time.perf_counter() - t0, 0.5)


# ---------------------------------------------------------------------------
# P1：--accounts 过滤与缺失认证文件警告
# ---------------------------------------------------------------------------

class AccountsFilterTest(unittest.TestCase):
    def setUp(self):
        self.ap = argparse.ArgumentParser(prog="test")
        self.auths = [
            {"label": "cookies.json", "_auth_file": "/x/cookies.json"},
            {"label": "小号", "_auth_file": "/x/cookies-new.json"},
        ]

    def test_match_by_stem(self):
        kept = cli._filter_accounts(self.auths, "cookies-new", self.ap)
        self.assertEqual(["小号"], [a["label"] for a in kept])

    def test_match_by_label_and_full_name(self):
        kept = cli._filter_accounts(self.auths, "小号,cookies.json", self.ap)
        self.assertEqual(2, len(kept))

    def test_no_match_errors(self):
        with self.assertRaises(SystemExit):
            cli._filter_accounts(self.auths, "nobody", self.ap)


class MissingAuthFileWarningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        write_auth(self.dir, "cookies.json")
        self.addCleanup(self.tmp.cleanup)

    def _capture(self, cfg):
        err = io.StringIO()
        with mock.patch.object(cli, "DIR", self.dir):
            with contextlib.redirect_stderr(err):
                auths = cli._load_auths(cfg)
        return auths, err.getvalue()

    def test_warns_on_explicit_missing_file(self):
        cfg = Config(auth_files=("cookies.json", "cookies-typo.json"))
        auths, err = self._capture(cfg)
        self.assertEqual(1, len(auths))
        self.assertIn("cookies-typo.json", err)
        self.assertIn("已跳过", err)

    def test_silent_for_default_optional_file(self):
        # 默认清单里 cookies-new.json 常不存在，不该每次都刷警告
        cfg = Config()
        auths, err = self._capture(cfg)
        self.assertEqual(1, len(auths))
        self.assertEqual("", err)

    def test_warning_never_leaks_values(self):
        cfg = Config(auth_files=("cookies.json", "cookies-typo.json"))
        _, err = self._capture(cfg)
        self.assertNotIn(AUTH["GL-XSRF-TOKEN"], err)


# ---------------------------------------------------------------------------
# P1：抢券目标为空必须启动即失败，不能空转到超时
# ---------------------------------------------------------------------------

class EmptyTargetsTest(unittest.TestCase):
    def test_loop_runner_rejects_empty_targets(self):
        cfg = Config(snipe_keyword="根本不存在的关键词")
        with self.assertRaises(ValueError):
            flows.LoopRunner([dict(AUTH, label="acc-1")], config=cfg,
                             minutes=0.01)

    def test_cli_errors_before_loading_auth(self):
        with tempfile.TemporaryDirectory() as d:
            cfg_file = Path(d) / "claim.config.json"
            cfg_file.write_text(json.dumps(
                {"snipe_keyword": "根本不存在的关键词"}), encoding="utf-8")
            with mock.patch.object(cli, "DIR", Path(d)):
                with self.assertRaises(SystemExit) as cm:
                    cli.main(["--loop", "--config", str(cfg_file)])
            self.assertEqual(2, cm.exception.code)


# ---------------------------------------------------------------------------
# P2：探针券单一真源 + 环境变量覆盖守卫
# ---------------------------------------------------------------------------

class ProbeCouponTest(unittest.TestCase):
    def test_probe_is_non_snipe_fixed_coupon(self):
        cfg = Config()
        probe = cfg.probe_coupon
        self.assertIsNotNone(probe)
        self.assertNotIn(cfg.snipe_keyword, probe["couponName"])
        self.assertIn(probe, cfg.fixed_coupons)

    def test_probe_id_defined_once_and_not_in_flows(self):
        probe_id = Config().probe_coupon["couponId"]
        cfg_src = (REPO_ROOT / "chagee" / "config.py").read_text(
            encoding="utf-8")
        flows_src = (REPO_ROOT / "chagee" / "flows.py").read_text(
            encoding="utf-8")
        self.assertEqual(1, cfg_src.count(probe_id))
        self.assertNotIn(probe_id, flows_src)

    def test_verify_session_requires_probe(self):
        cfg = Config(fixed_coupons=[
            {"couponId": "c1", "couponName": "【5折外卖券】立减20",
             "couponType": "PHONE_REWARD"}])
        with self.assertRaises(ValueError):
            flows.verify_session([dict(AUTH, label="acc-1")], config=cfg)

    def test_ping_requires_probe(self):
        cfg = Config(fixed_coupons=[
            {"couponId": "c1", "couponName": "【5折外卖券】立减20",
             "couponType": "PHONE_REWARD"}])
        with self.assertRaises(ValueError):
            flows.ping([dict(AUTH, label="acc-1")], config=cfg)


class EnvOverrideGuardTest(unittest.TestCase):
    def test_fixed_coupons_env_override_rejected(self):
        os.environ["MEITUAN_FIXED_COUPONS"] = "[]"
        try:
            with self.assertRaises(ValueError) as cm:
                load_config()
            self.assertIn("不支持环境变量覆盖", str(cm.exception))
        finally:
            del os.environ["MEITUAN_FIXED_COUPONS"]


# ---------------------------------------------------------------------------
# P2：GrantEvent 明细 JSONL 落盘（事后可脚本化复盘）
# ---------------------------------------------------------------------------

class EventsJsonlTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        # 先注册目录清理（LIFO 中最后执行），再注册句柄关闭（先执行）——
        # Windows 上日志句柄未关就删目录会 PermissionError
        self.addCleanup(shutil.rmtree, str(self.dir), True)

    def _runner(self, run_log):
        cfg = Config()
        runner = flows.LoopRunner([dict(AUTH, label="acc-1")], config=cfg,
                                  minutes=0.01, interval=0.01, run_log=run_log)
        self.addCleanup(runner.logger.close)
        self.addCleanup(lambda: [c.close() for c in runner.clients.values()])
        return runner

    def test_events_path_derived_from_run_log(self):
        runner = self._runner(str(self.dir / "claim-2026-10-10.log"))
        self.assertEqual(str(self.dir / "claim-2026-10-10.jsonl"),
                         str(runner.events_path))

    def test_dump_events_writes_jsonl(self):
        runner = self._runner(str(self.dir / "claim.log"))
        runner.events.append(GrantEvent("2026-10-10 14:00:00.01", "acc-1",
                                        "【5折外卖券】立减20", "granted", 0.42))
        runner.events.append(GrantEvent("2026-10-10 14:00:00.06", "acc-1",
                                        "【5折外卖券】立减25", "failed", 0.51))
        runner._dump_events()
        lines = runner.events_path.read_text(
            encoding="utf-8").strip().splitlines()
        self.assertEqual(2, len(lines))
        first = json.loads(lines[0])
        self.assertEqual({"send_ts", "label", "coupon_name", "status",
                          "elapsed"}, set(first))
        self.assertEqual("granted", first["status"])

    def test_dump_events_noop_without_run_log(self):
        runner = self._runner(None)
        self.assertIsNone(runner.events_path)
        runner.events.append(GrantEvent("ts", "acc-1", "券", "granted", 0.1))
        runner._dump_events()  # 不抛异常即通过

    def test_dump_events_contains_no_credentials(self):
        runner = self._runner(str(self.dir / "claim.log"))
        runner.events.append(GrantEvent("ts", "acc-1", "券A", "granted", 0.1))
        runner._dump_events()
        text = runner.events_path.read_text(encoding="utf-8")
        for secret in (AUTH["GL-XSRF-TOKEN"], AUTH["GOD_UUID"],
                       AUTH["device_id"], "js-original"):
            self.assertNotIn(secret, text)


# ---------------------------------------------------------------------------
# P2：浏览器 Cookie 导出 -> 认证文件转换工具（873 之后的会话重建闭环）
# ---------------------------------------------------------------------------

EXPORT = [
    {"name": "JSESSIONID", "value": "js-exported", "domain": ".ds.163.com"},
    {"name": "GL-XSRF-TOKEN", "value": "xsrf-exported", "domain": ".ds.163.com"},
    {"name": "GOD_UUID", "value": "uuid-exported", "domain": ".ds.163.com"},
    {"name": "ds-website-uuid", "value": "device-exported",
     "domain": ".ds.163.com"},
    {"name": "empty", "value": "", "domain": ".ds.163.com"},
    {"name": "other", "value": "x", "domain": ".example.com"},
]


class CookieExportToolTest(unittest.TestCase):
    def test_collect_from_array(self):
        cookies = cookie_tool.collect_cookies(EXPORT)
        self.assertEqual("js-exported", cookies["JSESSIONID"])
        self.assertNotIn("empty", cookies)   # 空值跳过
        self.assertIn("other", cookies)      # 不给 domain 时全收

    def test_collect_from_wrapped_object(self):
        self.assertEqual({"JSESSIONID": "js-exported"},
                         cookie_tool.collect_cookies({"cookies": EXPORT[:1]}))

    def test_domain_filter(self):
        cookies = cookie_tool.collect_cookies(EXPORT, domain="163.com")
        self.assertNotIn("other", cookies)
        self.assertEqual(4, len(cookies))

    def test_rejects_bad_shape(self):
        with self.assertRaises(ValueError):
            cookie_tool.collect_cookies("not-a-list")

    def _run(self, export_items, out="cookies-new.json"):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(d), True)
        src = d / "export.json"
        src.write_text(json.dumps(export_items), encoding="utf-8")
        err, out_buf = io.StringIO(), io.StringIO()
        with mock.patch.object(cookie_tool, "DIR", d):
            with contextlib.redirect_stderr(err), \
                    contextlib.redirect_stdout(out_buf):
                code = cookie_tool.main([str(src), "-o", out])
        return code, d, err.getvalue(), out_buf.getvalue()

    def test_main_writes_valid_auth_file(self):
        code, d, err, out = self._run(EXPORT)
        self.assertEqual(0, code)
        written = json.loads(
            (d / "cookies-new.json").read_text(encoding="utf-8"))
        self.assertEqual("js-exported", written["cookies"]["JSESSIONID"])
        for secret in ("xsrf-exported", "js-exported", "uuid-exported",
                       "device-exported"):
            self.assertNotIn(secret, err + out)   # 值不回显

    def test_main_rejects_incomplete_export(self):
        incomplete = [c for c in EXPORT if c["name"] != "GOD_UUID"]
        code, d, err, _ = self._run(incomplete)
        self.assertEqual(1, code)
        self.assertIn("GOD_UUID", err)            # 只报字段名
        self.assertNotIn("uuid-exported", err)
        self.assertFalse((d / "cookies-new.json").exists())  # 不留半成品


if __name__ == "__main__":
    unittest.main()