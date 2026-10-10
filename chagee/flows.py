#!/usr/bin/env python3
"""业务流程：健康检查、会话验证、单次执行、循环抢券。

P1 变更：
- loop_run 巨型函数拆为 LoopRunner（状态实例化，不再依赖模块级可变全局）；
- 日志统一走 RunLogger（输出前脱敏）；
- 节奏控制走注入的 GrantPacing；
- 业务错误分类全部基于结构化 code（errors.classify_grant_error）。
"""
import json
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .api_client import ApiClient
from .config import Config
from .errors import (AUTH_EXPIRED_CODES, ApiError, ApiTransportError,
                    classify_grant_error)
from .models import Coupon, GrantEvent
from .pacing import GrantPacing
from .security import GLOBAL_SECRETS


def beijing_ts():
    """北京时间戳，精确到百分之一秒：2026-10-09 14:02:39.45"""
    now = datetime.now(ZoneInfo("Asia/Shanghai"))
    return now.strftime("%Y-%m-%d %H:%M:%S") + ".%02d" % (now.microsecond // 10000)


class RunLogger:
    """控制台 + 可选文件的日志器；所有消息输出前统一脱敏。"""

    def __init__(self, path=None, secrets=None):
        self.secrets = secrets if secrets is not None else GLOBAL_SECRETS
        self._f = None
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._f = open(path, "a", encoding="utf-8")

    def log(self, msg):
        line = "%s %s" % (beijing_ts(), self.secrets.redact(msg))
        # 日志走 stderr：stdout 只留给最终 JSON 报告，外部可可靠管道解析
        print(line, file=sys.stderr, flush=True)
        if self._f:
            self._f.write(line + "\n")
            self._f.flush()

    def close(self):
        if self._f:
            self._f.close()
            self._f = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _write_keepalive(log_path, log_lines, secrets=None):
    if not log_path:
        return
    registry = secrets if secrets is not None else GLOBAL_SECRETS
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write("\n".join(registry.redact(x) for x in log_lines) + "\n")


# ---------------------------------------------------------------------------
# T02：健康检查（只读）与会话验证（有副作用）
# ---------------------------------------------------------------------------

def ping(auths, config=None, log_path=None):
    """只读健康检查：仅调用 info + grant-status 两个只读接口，绝不领取。

    每账号返回统一健康状态之一：
      reachable  —— 只读接口成功，网络与签名可用（只读接口无法证明登录态，
                    因此不报 authenticated）
      expired    —— 只读接口返回明确鉴权失败（业务码 873）
      unknown    —— 只读接口返回其他业务错误，无法判断
      error      —— 网络/HTTP 层失败
    """
    cfg = config or Config()
    probe = cfg.probe_coupon
    if not probe:
        raise ValueError("配置里没有可用作探针的券（probe_coupon 为空）")
    report = {}
    log_lines = []
    for auth in auths:
        label = auth["label"]
        t0 = time.time()
        try:
            with ApiClient(auth, config=cfg) as client:
                try:
                    # info 不校验登录，仅用于确认服务可达
                    client.coupon_info(timeout=cfg.ping_timeout)
                    client.grant_status([probe["couponId"]],
                                        timeout=cfg.ping_timeout)
                    report[label] = "reachable"
                except ApiError as e:
                    if e.code in AUTH_EXPIRED_CODES:
                        report[label] = "expired"
                    else:
                        report[label] = "unknown"  # 保留原始 code，不误分类
        except Exception as e:
            # 传输层/HTTP 层失败与其他意外一律归为 error，消息已脱敏限长
            report[label] = "error: " + str(e)[:120]
        log_lines.append("%s [%s] %s (%.2fs)" %
                         (beijing_ts(), label, report[label], time.time() - t0))
    _write_keepalive(log_path, log_lines)
    return report


def verify_session(auths, config=None, log_path=None):
    """会话验证（有副作用！）：用探针券尝试一次领取来证明登录态。

    若当天探针券（满28减10）尚未领取，会实际领掉一张。
    每账号返回：authenticated / expired / unknown / error: ...
    """
    cfg = config or Config()
    probe_cfg = cfg.probe_coupon
    if not probe_cfg:
        raise ValueError("配置里没有可用作探针的券（probe_coupon 为空）")
    probe = Coupon.from_api(probe_cfg)
    report = {}
    log_lines = []
    for auth in auths:
        label = auth["label"]
        t0 = time.time()
        try:
            with ApiClient(auth, config=cfg) as client:
                status, detail = try_grant(client, cfg.fixed_brand_id, probe,
                                           config=cfg)
            if status in ("granted", "already_claimed", "out_of_stock"):
                # 60001=会话有效只是没库存，同样证明登录态正常
                report[label] = "authenticated"
            elif status == "auth_expired":
                report[label] = "expired"
            elif status == "rate_limited":
                report[label] = "unknown"  # 被限流挡在门外，无法判断登录态
            else:
                report[label] = "error: " + detail[:120]
        except Exception as e:
            report[label] = "error: " + str(e)[:120]
        log_lines.append("%s [%s] %s (%.2fs)" %
                         (beijing_ts(), label, report[label], time.time() - t0))
    _write_keepalive(log_path, log_lines)
    return report


# ---------------------------------------------------------------------------
# 领取尝试（结构化错误分类，无字符串猜测）
# ---------------------------------------------------------------------------

def try_grant(client, brand_id, coupon, pacing=None, config=None):
    """尝试领取一张券（coupon: models.Coupon），返回 (status, detail)。

    pacing 提供时走限速+在飞闸门；status 取自 GRANT_CODE_STATUS 映射
    或 granted/failed，未知 code 保留原码不误分类。"""
    cfg = config or client.config
    if coupon.sold_out():
        return "out_of_stock", "已抢光"
    if coupon.coupon_type in cfg.skip_types:
        if coupon.coupon_type == "PLACEHOLDER":
            return "skipped", "占位券（敬请期待）"
        return "direct_link", "需跳转领取：%s" % coupon.direct_link
    try:
        if pacing is not None:
            with pacing.slot():
                grant_result = client.grant(brand_id, coupon)
        else:
            grant_result = client.grant(brand_id, coupon)
        prize = (grant_result or {}).get("winPrizeInfo") or grant_result
        return "granted", client.secrets.redact(str(prize))[:200]
    except ApiError as e:
        return (classify_grant_error(e),
                "code=%s: %s" % (e.code,
                                 client.secrets.redact(e.message)[:200]))
    except ApiTransportError as e:
        return "failed", "传输错误: %s" % client.secrets.redact(str(e))[:200]


# ---------------------------------------------------------------------------
# 单次执行
# ---------------------------------------------------------------------------

def single_run(auths, config=None, run_log=None):
    """单次执行：每个账号尝试一次，返回 (报告, 是否有错误)。"""
    cfg = config or Config()
    with RunLogger(run_log) as logger:
        log = logger.log
        report = {}
        any_error = False
        try:
            any_error = _single_run_accounts(auths, cfg, log, report)
        except KeyboardInterrupt:
            log("收到中断信号，单次执行提前结束（已完成账号的结果保留）")
            any_error = True
    return report, any_error


def _single_run_accounts(auths, cfg, log, report):
    """single_run 主体：逐账号执行，结果写入 report，返回是否有错误。"""
    any_error = False
    for auth in auths:
        label = auth["label"]
        outcomes = []
        log("[%s] 单次执行开始" % label)
        try:
            def on_rotate(name, label=label, log=log):
                log("[%s] 服务端轮换会话 Cookie: %s（本地已跟随）"
                    % (label, name))
            with ApiClient(auth, config=cfg, on_rotate=on_rotate) as client:
                t0 = time.time()
                brand, coupons = client.find_brand_coupons()
                log("[%s] 拉取列表成功，耗时 %.2fs，品牌: %s，券数: %d" %
                    (label, time.time() - t0,
                     brand.get("brandName") if brand else None,
                     len(coupons) if coupons else 0))
                if not brand:
                    outcomes.append({"coupon": None, "status": "no_brand",
                                     "detail": "列表中未找到霸王茶姬品牌"})
                elif not coupons:
                    outcomes.append({"coupon": None, "status": "no_coupon",
                                     "detail": "品牌下暂无券"})
                else:
                    # 状态校验失败与「查询成功且为空」区分开：失败时明确记日志
                    ids = [c.coupon_id for c in coupons]
                    try:
                        statuses = client.grant_status(ids)
                    except (ApiError, ApiTransportError) as e:
                        log("[%s] 状态校验失败（将无法跳过已领取券）: %s" %
                            (label, str(e)[:200]))
                        statuses = {}
                    for c in coupons:
                        name = c.coupon_name
                        if statuses.get(c.coupon_id) == "GRANTED":
                            outcomes.append({
                                "coupon": name, "status": "already_claimed",
                                "detail": "已领取", "grant_status": "GRANTED"})
                            log("[%s] %s -> already_claimed（已领取，跳过）"
                                % (label, name))
                            continue
                        t1 = time.time()
                        status, detail = try_grant(
                            client, brand["brandId"], c, config=cfg)
                        log("[%s] %s -> %s (%.2fs): %s" %
                            (label, name, status, time.time() - t1,
                             detail[:200]))
                        item = {"coupon": name, "status": status,
                                "detail": detail}
                        if statuses.get(c.coupon_id):
                            item["grant_status"] = statuses[c.coupon_id]
                        outcomes.append(item)
        except Exception as e:
            log("[%s] 执行异常: %s" % (label, str(e)[:200]))
            outcomes.append({"coupon": None, "status": "error",
                             "detail": str(e)[:200]})
            any_error = True
        log("[%s] 单次执行结束" % label)
        report[label] = outcomes
    return any_error


def wait_until(target_str):
    """等到目标时刻（HH:MM[:SS[.毫秒]]，按 Asia/Shanghai 解析，不受系统时区影响）
    再返回；目标已过则直接返回。最后 5ms 忙等，保证毫秒级精度。"""
    tz = ZoneInfo("Asia/Shanghai")
    now_bj = datetime.now(tz)  # 取北京时间的日期，避免系统时区干扰
    parts = target_str.split(":")
    if len(parts) < 2:
        raise ValueError("开火时刻格式应为 HH:MM[:SS[.毫秒]]: %s" % target_str)
    h, m = int(parts[0]), int(parts[1])
    sec = float(parts[2]) if len(parts) > 2 else 0.0
    target_dt = datetime(now_bj.year, now_bj.month, now_bj.day,
                         h, m, int(sec), int((sec - int(sec)) * 1e6),
                         tzinfo=tz)
    target = target_dt.timestamp()
    delta = target - time.time()
    if delta <= 0:
        return
    print("等待 %.1fs 至 %s（北京时间）准时开抢..." % (delta, target_str),
          file=sys.stderr, flush=True)
    # 剩余时长用单调钟锚定：Windows 上 time.time 分辨率约 15ms，
    # 忙等段若继续比对 time.time 可能整体偏移一个 tick
    end = time.perf_counter() + delta
    if delta > 0.005:
        time.sleep(delta - 0.005)
    while time.perf_counter() < end:
        pass


# ---------------------------------------------------------------------------
# 循环抢券
# ---------------------------------------------------------------------------

class LoopRunner:
    """循环抢券：双账号并发尝试，请求错峰 + 限流退避，直到全部到手或超时。

    全部运行状态（done/final/events/targets/backoff）都是实例属性，
    由 self.lock 保护；不再依赖模块级可变全局。"""

    def __init__(self, auths, config=None, minutes=10, interval=2.0,
                 fire_at=None, run_log=None, logger=None):
        self.auths = auths
        self.cfg = config or Config()
        # 目标为空时每波都是 0 任务、_all_settled 永远不成立，会空转到超时；
        # 配置错误应当在启动时就报出来，而不是静默跑十分钟
        if not self.cfg.snipe_coupons:
            raise ValueError(
                "抢券目标为空：关键词 %r 未匹配到任何固定券，"
                "请检查 snipe_keyword / fixed_coupons 配置"
                % self.cfg.snipe_keyword)
        self.minutes = minutes
        self.interval = interval
        self.fire_at = fire_at
        self.logger = logger or RunLogger(run_log)
        # 结构化事件副本（JSONL），与人读日志同名同目录；未给 run_log 则不落盘
        self.events_path = (Path(run_log).with_suffix(".jsonl")
                            if run_log else None)

        def rotate_cb(label):
            def cb(name):
                self.logger.log("[%s] 服务端轮换会话 Cookie: %s（本地已跟随）"
                                % (label, name))
            return cb

        self.clients = {a["label"]: ApiClient(a, config=self.cfg,
                                              on_rotate=rotate_cb(a["label"]))
                        for a in auths}
        self.pacing = GrantPacing(self.cfg.first_wave_gap,
                                  self.cfg.first_wave_inflight,
                                  self.cfg.sustained_gap,
                                  self.cfg.sustained_inflight)
        self.lock = threading.Lock()
        self.done = {a["label"]: set() for a in auths}    # 已搞定的 couponId
        self.final = {a["label"]: {} for a in auths}      # couponName -> item
        # 每次grant事件：(发送时刻ts, 账号, 券名, 状态, 耗时)，用于收尾统计
        self.events = []
        # 固定券直接就位，第一波零等待开抢；后台刷新只做增量合并（防阵容变化）
        # 只抢5折券（snipe_coupons），满28减10不进目标
        self.targets = {
            a["label"]: [(self.cfg.fixed_brand_id, Coupon.from_api(c))
                         for c in self.cfg.snipe_coupons]
            for a in auths}
        self.backoff_until = {a["label"]: 0.0 for a in auths}
        self.soldout_streak = {a["label"]: {} for a in auths}  # cid -> 连续抢光次数

    # -- 子任务 -----------------------------------------------------------

    def _refresh_one(self, auth):
        """后台刷新：只增量合并列表中新出现的券，不删除固定券（线程安全）。
        抢券期间用短超时快速失败。"""
        label = auth["label"]
        cfg = self.cfg
        try:
            brand, coupons = self.clients[label].find_brand_coupons(
                timeout=cfg.refresh_timeout)
        except (ApiError, ApiTransportError) as e:
            self.logger.log("[%s] 列表拉取失败: %s" % (label, str(e)[:200]))
            return
        except Exception as e:
            self.logger.log("[%s] 列表拉取失败: %s" % (label, str(e)[:200]))
            return
        added = 0
        with self.lock:
            known = {c.coupon_id for _, c in self.targets[label]}
            brand_id = brand["brandId"] if brand else cfg.fixed_brand_id
            for c in (coupons or []):
                if c.coupon_type in cfg.skip_types or not c.coupon_id:
                    continue
                # 只合并5折券，28-10等不进目标
                if cfg.snipe_keyword not in c.coupon_name:
                    continue
                if c.coupon_id not in known:
                    self.targets[label].append((brand_id, c))
                    added += 1
        if added:
            self.logger.log("[%s] 发现 %d 张新券，已加入抢券" % (label, added))

    def _is_priority(self, coupon):
        """两张5折券优先并发。"""
        return self.cfg.snipe_keyword in coupon.coupon_name

    def _grant_one(self, auth, brand_id, coupon):
        """单张券的一次尝试；成功/已领/连续抢光则标记 done 停止重试。"""
        label = auth["label"]
        cid = coupon.coupon_id
        name = coupon.coupon_name
        log = self.logger.log
        with self.lock:
            if cid in self.done[label] or time.time() < self.backoff_until[label]:
                return
        t0 = time.time()
        send_ts = beijing_ts()  # 发送时刻（百分之一秒）
        status, detail = try_grant(self.clients[label], brand_id, coupon,
                                   pacing=self.pacing, config=self.cfg)
        elapsed = time.time() - t0
        with self.lock:
            self.events.append(GrantEvent(send_ts, label, name, status, elapsed))
            if status in ("granted", "already_claimed"):
                self.done[label].add(cid)
                self.final[label][name] = {"coupon": name, "status": status,
                                           "detail": detail}
                log("[%s] %s -> %s (发送%s, 耗时%.2fs)" %
                    (label, name, status, send_ts, elapsed))
            elif status == "rate_limited":
                self.backoff_until[label] = time.time() + self.cfg.rate_limit_backoff
                self.soldout_streak[label].pop(cid, None)
                self.final[label][name] = {"coupon": name, "status": status,
                                           "detail": detail}
                log("[%s] 命中限流，退避 %ds (发送%s, 耗时%.2fs)" %
                    (label, self.cfg.rate_limit_backoff, send_ts, elapsed))
            elif status == "auth_expired":
                # 登录态失效：重试无意义，直接停止并记录
                self.soldout_streak[label].pop(cid, None)
                self.done[label].add(cid)
                self.final[label][name] = {"coupon": name, "status": status,
                                           "detail": detail}
                log("[%s] %s -> 登录态失效，停止重试 (发送%s, 耗时%.2fs)" %
                    (label, name, send_ts, elapsed))
            elif status == "out_of_stock":
                streak = self.soldout_streak[label].get(cid, 0) + 1
                self.soldout_streak[label][cid] = streak
                self.final[label][name] = {"coupon": name, "status": status,
                                           "detail": detail}
                if streak >= self.cfg.soldout_stop_after:
                    self.done[label].add(cid)
                    log("[%s] %s 连续%d次抢光，停止重试 (发送%s, 耗时%.2fs)" %
                        (label, name, streak, send_ts, elapsed))
                else:
                    log("[%s] %s -> 抢光第%d次 (发送%s, 耗时%.2fs)" %
                        (label, name, streak, send_ts, elapsed))
            else:
                self.soldout_streak[label].pop(cid, None)
                self.final[label][name] = {"coupon": name, "status": status,
                                           "detail": detail}
                # 兜底：接口未在业务码上区分「券不存在/已下架」，只能按文案
                # 识别（这些词不是业务错误码，不参与核心分类，仅决定是否停）。
                if any(k in detail for k in ("不存在", "已下架", "已失效",
                                             "not exist", "invalid")):
                    self.done[label].add(cid)
                    log("[%s] %s 已失效，停止重试 (发送%s, 耗时%.2fs)" %
                        (label, name, send_ts, elapsed))
                else:
                    log("[%s] %s -> %s (发送%s, 耗时%.2fs): %s" %
                        (label, name, status, send_ts, elapsed, detail[:150]))

    # -- 主流程（拆分后的步骤） -------------------------------------------

    def _check_clock(self):
        """时钟校验：开火精度依赖系统时钟。Linux 查 timedatectl NTP 同步，
        其他平台记录跳过（timedatectl 是 systemd 专用）。"""
        if not sys.platform.startswith("linux"):
            self.logger.log("时钟校验: 非 Linux 平台跳过（精度依赖系统时钟）")
            return
        try:
            r = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized"],
                               capture_output=True, text=True, timeout=2)
            out = r.stdout.strip() or "timedatectl无输出"
            self.logger.log("时钟校验: %s" % out)
        except Exception as e:
            self.logger.log("时钟校验跳过: %s" % e)

    def _preheat_and_wait(self):
        """预热连接后精确等待开火时刻（等待计入总时长之外）。"""
        log = self.logger.log
        log("预热连接...")
        for auth in self.auths:
            label = auth["label"]
            try:
                self.clients[label].grant_status(
                    [c.coupon_id for _, c in self.targets[label][:1]])
                log("[%s] 预热完成" % label)
            except Exception as e:
                log("[%s] 预热失败: %s" % (label, str(e)[:80]))
        wait_until(self.fire_at)
        log("开火！")

    def _build_wave_tasks(self):
        """本轮任务：两张5折券排前面优先并发发出。"""
        tasks = []
        with self.lock:
            for auth in self.auths:
                label = auth["label"]
                pending = [(b, c) for (b, c) in self.targets[label]
                           if c.coupon_id not in self.done[label]]
                pri = [(auth, b, c) for (b, c) in pending if self._is_priority(c)]
                rest = [(auth, b, c) for (b, c) in pending
                        if not self._is_priority(c)]
                tasks.extend(pri + rest)
        return tasks

    def _all_settled(self):
        with self.lock:
            pending = any(
                c.coupon_id not in self.done[auth["label"]]
                for auth in self.auths for _, c in self.targets[auth["label"]])
        return not pending and any(self.targets.values())

    def _log_summary(self, wave_count):
        """收尾统计：事件汇总，供事后复盘优化。"""
        if not self.events:
            return
        log = self.logger.log
        cnt = Counter(e.status for e in self.events)
        elapseds = [e.elapsed for e in self.events]
        log("=== 收尾统计 ===")
        log("总波次: %d, 总请求: %d" % (wave_count, len(self.events)))
        log("状态分布: %s" % dict(cnt))
        log("耗时: 最小%.2fs 最大%.2fs 平均%.2fs" %
            (min(elapseds), max(elapseds), sum(elapseds) / len(elapseds)))
        # 第一波 = 时间戳最小的一批事件（不硬编码前N个）
        first_ts = self.events[0].send_ts
        first_wave = [e for e in self.events if e.send_ts == first_ts]
        if first_wave:
            log("第一波发送时刻: %s" % " | ".join(e.send_ts for e in first_wave))

    def _dump_events(self):
        """把 GrantEvent 明细追加写 JSONL：人读日志之外的机器可读副本，
        事后可脚本化复盘发送时刻/耗时分布（调参依据）。纯 best-effort。"""
        if not self.events_path or not self.events:
            return
        try:
            self.events_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.events_path, "a", encoding="utf-8") as f:
                for e in self.events:
                    f.write(json.dumps(asdict(e), ensure_ascii=False) + "\n")
            self.logger.log("事件明细已写入: %s" % self.events_path)
        except OSError as e:
            self.logger.log("事件明细写入失败: %s" % e)

    def _finalize(self):
        """收尾：用 grant-status 补一次状态校验（直接用目标券，不再拉列表）。"""
        log = self.logger.log
        report = {}
        for auth in self.auths:
            label = auth["label"]
            try:
                all_coupons = [c for _, c in self.targets[label]]
                statuses = self.clients[label].grant_status(
                    [c.coupon_id for c in all_coupons])
                id2name = {c.coupon_id: c.coupon_name for c in all_coupons}
                for cid, st in statuses.items():
                    name = id2name.get(cid, cid)
                    if name not in self.final[label]:
                        self.final[label][name] = {"coupon": name}
                    self.final[label][name]["grant_status"] = st
            except Exception as e:
                log("[%s] 收尾校验失败: %s" % (label, str(e)[:200]))
            report[label] = list(self.final[label].values())
        return report

    def run(self):
        cfg = self.cfg
        log = self.logger.log
        wave_count = 0
        try:
            log("并发抢券开始，持续 %s 分钟，间隔 %ss"
                "（第一波%.2f秒极限%d并发只抢5折，后续%.1f秒安全模式）" %
                (self.minutes, self.interval, cfg.first_wave_gap,
                 cfg.first_wave_inflight, cfg.sustained_gap))
            self._check_clock()
            try:
                if self.fire_at:
                    self._preheat_and_wait()
                deadline = time.time() + self.minutes * 60
                # 6 线程：双账号 × 优先券；实际领取请求由在飞闸门限制
                with ThreadPoolExecutor(max_workers=6) as pool:
                    # 固定券已就位，第一波零等待纯开抢（不掺刷新请求，避免叠加触发限流）；
                    # 第一波结束后立即后台刷新一次，之后每30秒刷新，只做增量合并
                    last_refresh = time.time()
                    while time.time() < deadline:
                        if (wave_count == 1
                                or time.time() - last_refresh >= cfg.refresh_every):
                            for auth in self.auths:
                                pool.submit(self._refresh_one, auth)
                            last_refresh = time.time()
                        tasks = self._build_wave_tasks()
                        futs = [pool.submit(self._grant_one, auth, b, c)
                                for (auth, b, c) in tasks]
                        log("第 %d 波开始，共 %d 个任务" % (wave_count + 1, len(tasks)))
                        for f in as_completed(futs):
                            f.result()
                        wave_count += 1
                        if wave_count == 1 and not cfg.burst_test:
                            # 第一波（极限速度）结束，切到安全模式防持续限流
                            self.pacing.enter_sustained_mode()
                            log("第一波结束，已切换到安全模式（%.1f秒间隔、最多%d并发）"
                                % (cfg.sustained_gap, cfg.sustained_inflight))
                        # 判断机制：所有目标券都已有结论（已领/抢光停止）则提前退出
                        if self._all_settled():
                            log("所有券已有结论（已领/抢光停止），提前结束")
                            break
                        remaining = deadline - time.time()
                        if remaining > 0:
                            time.sleep(min(self.interval, remaining))
            except KeyboardInterrupt:
                # Ctrl+C：不裸退，进入收尾统计 + 状态校验，保住已有战果
                log("收到中断信号，跳过剩余波次，进入收尾统计与状态校验...")
            self._log_summary(wave_count)
            self._dump_events()
            return self._finalize()
        finally:
            for c in self.clients.values():
                c.close()
            self.logger.close()


def loop_run(auths, config=None, minutes=10, interval=2.0, fire_at=None,
             run_log=None):
    """循环抢券入口（薄封装，状态都在 LoopRunner 实例里）。"""
    runner = LoopRunner(auths, config=config, minutes=minutes,
                        interval=interval, fire_at=fire_at, run_log=run_log)
    return runner.run()
