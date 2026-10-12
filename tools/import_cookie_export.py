#!/usr/bin/env python3
"""把浏览器 Cookie 导出文件转成认证文件（默认写 cookies-new.json）。

为什么需要这个工具：JSESSIONID 是 HttpOnly，页面 JS（document.cookie / 书签栏
脚本）读不到，只能用浏览器扩展（Cookie-Editor、EditThisCookie 等）导出；而扩展
导出的是数组结构，认证文件要求对象结构。本脚本只做这层格式转换 + 完整性校验。

两种写法：
  单对象文件    python tools/import_cookie_export.py export.json -o cookies-a.json
  并入多账号文件 python tools/import_cookie_export.py export.json -o cookies.json \
                     --merge --label 小号
  （--merge 按 label 定位：同 label 替换该条，否则追加，其他账号原样不动；
    校验不过会回滚成原文件，不会毁掉同文件里的其他账号）

凭据内容全程不打印：只输出 cookie 数量、label 与（如有）缺失字段名。
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from meituan.config import DIR                        # noqa: E402
from meituan.security import load_auths, write_auth_file  # noqa: E402


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

    # 先留住原内容：校验不过要能回滚，不能毁掉同文件里的其他账号
    before = existing_entries(out_path, ap) if args.merge else None
    if args.merge:
        payload, action = merge_entry(list(before), entry)
    else:
        payload, action = entry, "整体写入"
    write_auth_file(payload, out_path)

    try:
        load_auths([args.output], base_dir=DIR)
    except ValueError as e:
        if args.merge and before:
            write_auth_file(before, out_path)      # 回滚，其他账号不受影响
        else:
            out_path.unlink(missing_ok=True)
        back = "已回滚" if (args.merge and before) else "已删除"
        print("校验失败，%s %s：%s" % (back, args.output, e), file=sys.stderr)
        return 1
    print("已%s %s（%d 个 cookie，label=%s），校验通过。"
          "建议接着跑：python claim.py --verify-session --accounts %s"
          % (action, out_path, len(cookies), entry["label"], entry["label"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
