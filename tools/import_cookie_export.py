#!/usr/bin/env python3
"""把浏览器 Cookie 导出文件转成认证文件（默认写 cookies-new.json）。

为什么需要这个工具：JSESSIONID 是 HttpOnly，页面 JS（document.cookie / 书签栏
脚本）读不到，只能用浏览器扩展（Cookie-Editor、EditThisCookie 等）导出；而扩展
导出的是数组结构，认证文件要求对象结构。本脚本只做这层格式转换 + 完整性校验。

凭据内容全程不打印：只输出 cookie 数量与（如有）缺失字段名。

用法：
  python tools/import_cookie_export.py export.json
  python tools/import_cookie_export.py export.json -o cookies.json
  python tools/import_cookie_export.py export.json --domain 163.com
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chagee.config import DIR                      # noqa: E402
from chagee.security import load_auth, save_auth    # noqa: E402


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


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="import_cookie_export.py",
        description="浏览器 Cookie 导出文件 -> 认证文件（cookies-new.json）")
    ap.add_argument("export", help="扩展导出的 JSON 文件路径")
    ap.add_argument("-o", "--output", default="cookies-new.json",
                    help="输出的认证文件名（相对项目根目录，默认 cookies-new.json）")
    ap.add_argument("--domain", default=None,
                    help="只保留 domain 含该子串的 cookie（如 163.com）")
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
    save_auth({"cookies": cookies}, out_path)
    # 复用 load_auth 做完整性校验：它会把 GL-XSRF-TOKEN / GOD_UUID / device_id
    # 从 cookies 反推出来，缺什么直接报字段名（不报值）
    try:
        load_auth(args.output, base_dir=DIR)
    except ValueError as e:
        out_path.unlink(missing_ok=True)
        print("校验失败，已删除 %s：%s" % (args.output, e), file=sys.stderr)
        return 1
    print("已写入 %s（%d 个 cookie），校验通过。"
          "建议接着跑：python claim.py --verify-session --accounts %s"
          % (out_path, len(cookies), out_path.stem))
    return 0


if __name__ == "__main__":
    sys.exit(main())
