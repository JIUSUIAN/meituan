#!/usr/bin/env python3
"""命令行入口：参数解析、配置装配、分发到 flows。"""
import argparse
import json
import re
import sys
from pathlib import Path

from .config import DIR, Config, load_config
from .flows import beijing_ts, loop_run, ping, single_run, verify_session
from .security import load_auths

# 开火时刻：HH:MM[:SS[.毫秒]]，秒可省略
FIRE_AT_RE = re.compile(r"^\d{1,2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?$")


def _run_log_name(cfg, prefix):
    return str(Path(cfg.run_log_dir) /
               ("%s-%s.log" % (prefix,
                               beijing_ts().replace(" ", "_").replace(":", ""))))


# 这些终态代表本次运行实质失败（登录态失效/执行异常），退出码必须反映出来，
# 否则 cron 等自动化层看到的永远是成功
_LOOP_FAILURE_STATUSES = {"auth_expired", "error"}


def _loop_has_error(report):
    """loop 报告里任一账号出现失败终态即视为有错。"""
    if not report:
        return True
    return any(item.get("status") in _LOOP_FAILURE_STATUSES
               for items in report.values()
               for item in (items or []))


def _fire_at(value):
    """argparse type：格式不合法直接人话报错，不留到 wait_until 抛 traceback。"""
    if not FIRE_AT_RE.match(value):
        raise argparse.ArgumentTypeError(
            "开火时刻格式应为 HH:MM[:SS[.毫秒]]，例如 14:00:00.000，收到: %s"
            % value)
    parts = value.split(":")
    h, m = int(parts[0]), int(parts[1])
    s = float(parts[2]) if len(parts) > 2 else 0.0
    if not (0 <= h <= 23 and 0 <= m <= 59 and 0 <= s < 60):
        raise argparse.ArgumentTypeError("开火时刻超出合法范围: %s" % value)
    return value


def _load_auths(cfg):
    """加载全部账号凭据（一个文件可是单对象，也可是多账号数组）。
    配置里显式写了却不存在的文件要警告——静默跳过会让人以为在双账号并发，
    实际只跑了单账号。"""
    auths = []
    for f in cfg.auth_files:
        if (DIR / f).exists():
            auths.extend(load_auths([f], base_dir=DIR))
        elif f not in Config.auth_files:
            print("警告: 配置指定的认证文件不存在，已跳过: %s" % f,
                  file=sys.stderr)
    if not auths:
        raise FileNotFoundError(
            "没有任何账号 Cookie 文件（%s）" % " / ".join(cfg.auth_files))
    return auths


def _filter_accounts(auths, spec, ap):
    """--accounts 子集过滤：按 label 或认证文件名（含/不含扩展名）匹配。"""
    wanted = {s.strip() for s in spec.split(",") if s.strip()}
    kept = []
    for a in auths:
        p = Path(a.get("_auth_file") or a["label"])
        if a["label"] in wanted or p.name in wanted or p.stem in wanted:
            kept.append(a)
    if not kept:
        ap.error("--accounts 未匹配到任何账号: %s" % spec)
    return kept


def main(argv=None):
    ap = argparse.ArgumentParser(prog="claim.py")
    ap.add_argument("--loop", action="store_true", help="循环抢券模式（并发+错峰）")
    ap.add_argument("--minutes", type=float, default=None,
                    help="循环持续分钟数（默认 10，可被配置/环境变量覆盖）")
    ap.add_argument("--interval", type=float, default=None,
                    help="每轮间隔秒数（默认 2.0，可被配置/环境变量覆盖）")
    ap.add_argument("--fire-at", type=_fire_at, default=None,
                    help="开火时刻 HH:MM[:SS[.毫秒]]，到点才打第一波（已过则立即开火）")
    ap.add_argument("--fire-lead", type=float, default=None,
                    help="开火提前量秒数（补偿首波网络往返；整点抢实测响应 "
                         "1.8~3.2s，建议 0.3）")
    ap.add_argument("--config", default=None,
                    help="JSON 配置文件路径（默认同目录 claim.config.json，存在才读）")
    ap.add_argument("--accounts", default=None,
                    help="只运行指定账号（逗号分隔，按 label 或认证文件名匹配）")
    ap.add_argument("--ping", action="store_true",
                    help="只读健康检查：仅调用 info/grant-status 只读接口，"
                         "无业务副作用；无法证明登录态时返回 reachable")
    ap.add_argument("--verify-session", action="store_true",
                    help="会话验证：有业务副作用！尝试领取探针券以证明登录态，"
                         "若探针券当天未领会实际领掉一张")
    args = ap.parse_args(argv)

    if args.ping and args.verify_session:
        ap.error("--ping 与 --verify-session 互斥（前者只读，后者有副作用）")

    cfg = load_config(path=args.config, overrides={
        "loop_minutes": args.minutes,
        "loop_interval": args.interval,
        "fire_at": args.fire_at,
        "fire_lead": args.fire_lead,
    })

    # 配置层校验先于凭据加载：配置写错时不该先去读 cookies 文件
    if args.loop and not cfg.snipe_coupons:
        ap.error("抢券目标为空（关键词 %r 未匹配到任何固定券），"
                 "loop 会空转到超时——请检查 snipe_keyword / fixed_coupons"
                 % cfg.snipe_keyword)

    auths = _load_auths(cfg)
    if args.accounts:
        auths = _filter_accounts(auths, args.accounts, ap)

    if args.ping:
        report = ping(auths, config=cfg, log_path=cfg.keepalive_log)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1 if any(v == "expired" or v.startswith("error")
                        for v in report.values()) else 0

    if args.verify_session:
        report = verify_session(auths, config=cfg, log_path=cfg.keepalive_log)
        # 成功账号回显凭据文件路径：确认「重新登录后导出的文件已可用」这一闭环
        for auth in auths:
            if report.get(auth["label"], "").startswith("authenticated"):
                print("认证文件已可用: %s" % auth.get("_auth_file"),
                      file=sys.stderr)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1 if any(not v.startswith("authenticated")
                        for v in report.values()) else 0

    if args.loop:
        report = loop_run(auths, config=cfg, minutes=cfg.loop_minutes,
                          interval=cfg.loop_interval, fire_at=cfg.fire_at,
                          run_log=_run_log_name(cfg, "claim"))
        any_error = _loop_has_error(report)
    else:
        report, any_error = single_run(
            auths, config=cfg, run_log=_run_log_name(cfg, "claim-single"))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if any_error else 0


if __name__ == "__main__":
    sys.exit(main())
