#!/usr/bin/env python3
"""把浏览器 Cookie 导出文件转成认证文件（默认写 cookies-new.json）。

为什么需要这个工具：JSESSIONID 是 HttpOnly，页面 JS（document.cookie / 书签栏
脚本）读不到，只能用浏览器扩展（Cookie-Editor、EditThisCookie 等）导出；而扩展
导出的是数组结构，认证文件要求对象结构。本脚本只做这层格式转换 + 完整性校验。

两种写法：
  单对象文件    python tools/import_cookie_export.py export.json -o cookies-a.json
  并入多账号文件 python tools/import_cookie_export.py export.json -o cookies.json \
                     --merge --label 177****7689
  （--merge 按 label 定位：同 label 替换该条，否则追加，其他账号原样不动；
    先在中转文件上校验，通过才落盘——校验不过时正式文件一个字节都不动）

凭据内容全程不打印：只输出 cookie 数量、label 与（如有）缺失字段名。
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from meituan.config import DIR                        # noqa: E402
from meituan.security import (load_auths,             # noqa: E402
                              _atomic_write_json, _cross_process_lock)


def collect_cookies(raw, domain=None):
    """导出文件 -> {name: value}。domain 给定时只保留该域（含子域）的条目。"""
    if isinstance(raw, dict):
        raw = raw.get("cookies") or raw.get("data") or []
    if not isinstance(raw, list):
        raise ValueError("导出文件应为 cookie 数组，或含 cookies/data 数组的对象")
    out = {}
    for item in raw:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        if item.get("value") in (None, ""):
            continue
        if domain:
            host = str(item.get("domain") or "")
            if domain not in host:
                continue
        out[str(item["name"])] = str(item["value"])
    return out


def build_entry(cookies, label):
    """账号条目：顶层鉴权字段与 cookies 都写上，便于人工核对
    （即便漏写，load_auth 也会从 cookies 反推出来）。"""
    def pick(*names):
        for n in names:
            for k, v in cookies.items():
                if k.lower() == n.lower():
                    return v
        return ""
    return {
        "label": label,
        "GL-XSRF-TOKEN": pick("GL-XSRF-TOKEN"),
        "GOD_UUID": pick("GOD_UUID"),
        "device_id": pick("device_id", "ds-website-uuid"),
        "cookies": cookies,
    }


def existing_entries(path, ap):
    """目标文件里已有的账号数组；文件不存在视为空数组，非数组直接报错。"""
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        ap.error("目标文件不是合法 JSON（第 %s 行第 %s 列）: %s"
                 % (e.lineno, e.colno, path))
    if not isinstance(raw, list):
        ap.error("目标文件不是多账号数组，去掉 --merge 才是整体写入单对象: %s"
                 % path)
    return raw


def merge_entry(entries, entry):
    """按 label 定位：同 label 替换该条，否则追加。其他条目原样保留。"""
    for i, item in enumerate(entries):
        if isinstance(item, dict) and item.get("label") == entry["label"]:
            entries[i] = entry
            return entries, "替换"
    entries.append(entry)
    return entries, "追加"


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="import_cookie_export.py",
        description="浏览器 Cookie 导出文件 -> 认证文件（单对象或多账号数组条目）")
    ap.add_argument("export", help="扩展导出的 JSON 文件路径")
    ap.add_argument("-o", "--output", default="cookies-new.json",
                    help="输出的认证文件名（相对项目根目录，默认 cookies-new.json）")
    ap.add_argument("--domain", default=None,
                    help="只保留 domain 含该子串的 cookie（如 163.com）")
    ap.add_argument("--label", default=None,
                    help="账号 label（默认为输出文件名主干）；--merge 时靠它定位条目")
    ap.add_argument("--merge", action="store_true",
                    help="并入多账号数组文件：同 label 替换该条，否则追加")
    args = ap.parse_args(argv)

    src = Path(args.export)
    if not src.exists():
        ap.error("导出文件不存在: %s" % src)
    try:
        raw = json.loads(src.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        ap.error("导出文件不是合法 JSON（第 %s 行第 %s 列）" % (e.lineno, e.colno))

    try:
        cookies = collect_cookies(raw, domain=args.domain)
    except ValueError as e:
        ap.error(str(e))
    if not cookies:
        ap.error("导出文件里没有可用 cookie（检查 --domain 过滤是否过严）")

    out_path = DIR / args.output
    entry = build_entry(cookies, args.label or out_path.stem)

    # 合并模式下先确认目标文件是合法数组（格式不对直接报错，不做任何写入）
    before = existing_entries(out_path, ap) if args.merge else None
    if args.merge:
        payload, action = merge_entry(list(before), entry)
    else:
        payload, action = entry, "整体写入"

    # 先写中转文件并在真实加载路径上校验，通过才替换正式文件。
    # 曾经的顺序是「先写正式文件、后校验、失败再 unlink/回滚」：
    # 非 merge 模式下会删掉被覆盖的旧凭据；merge 的回滚快照还会盖掉
    # 校验期间别的进程刚轮换写入的新会话。现在正式文件在校验通过前
    # 一个字节都不会被碰。
    tmp_path = out_path.with_name("%s.new.%d.tmp" % (out_path.name, os.getpid()))
    try:
        _atomic_write_json(tmp_path, payload)
        load_auths([tmp_path.name], base_dir=DIR)
    except (ValueError, OSError) as e:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        print("校验失败，未写入 %s：%s" % (out_path, e), file=sys.stderr)
        return 1
    # 落盘走目标文件的跨进程锁，避免与并发轮换的读-改-写交叉
    with _cross_process_lock(out_path):
        os.replace(tmp_path, out_path)
    print("已%s %s（%d 个 cookie，label=%s），校验通过。"
          "建议接着跑：python claim.py --verify-session --accounts %s"
          % (action, out_path, len(cookies), entry["label"], entry["label"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
