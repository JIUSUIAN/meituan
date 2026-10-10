#!/usr/bin/env python3
"""命令行入口：参数解析、配置装配、分发到 flows。"""
import argparse
import json
import sys
from pathlib import Path

from .config import DIR, load_config
from .flows import beijing_ts, loop_run, ping, single_run, verify_session
from .security import load_auth


def _run_log_name(cfg, prefix):
    return str(Path(cfg.run_log_dir) /
               ("%s-%s.log" % (prefix,
                               beijing_ts().replace(" ", "_").replace(":", ""))))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="claim.py")
    ap.add_argument("--loop", action="store_true", help="循环抢券模式（并发+错峰）")
    ap.add_argument("--minutes", type=float, default=None,
                    help="循环持续分钟数（默认 10，可被配置/环境变量覆盖）")
    ap.add_argument("--interval", type=float, default=None,
                    help="每轮间隔秒数（默认 2.0，可被配置/环境变量覆盖）")
    ap.add_argument("--fire-at", default=None,
                    help="开火时刻 HH:MM:SS[.毫秒]，到点才打第一波（已过则立即开火）")
    ap.add_argument("--config", default=None,
                    help="JSON 配置文件路径（默认同目录 claim.config.json，存在才读）")
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
    })

    auths = []
    for f in cfg.auth_files:
        if (DIR / f).exists():
            auths.append(load_auth(f, base_dir=DIR))
    if not auths:
        raise FileNotFoundError(
            "没有任何账号 Cookie 文件（%s）" % " / ".join(cfg.auth_files))

    if args.ping:
        report = ping(auths, config=cfg, log_path=cfg.keepalive_log)
        print(json.dumps(report, ensure_ascii=False))
        return 1 if any(v == "expired" or v.startswith("error")
                        for v in report.values()) else 0

    if args.verify_session:
        report = verify_session(auths, config=cfg, log_path=cfg.keepalive_log)
        print(json.dumps(report, ensure_ascii=False))
        return 1 if any(not v.startswith("authenticated")
                        for v in report.values()) else 0

    if args.loop:
        report = loop_run(auths, config=cfg, minutes=cfg.loop_minutes,
                          interval=cfg.loop_interval, fire_at=cfg.fire_at,
                          run_log=_run_log_name(cfg, "claim"))
        any_error = False
    else:
        report, any_error = single_run(
            auths, config=cfg, run_log=_run_log_name(cfg, "claim-single"))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if any_error else 0


if __name__ == "__main__":
    sys.exit(main())
