#!/usr/bin/env python3
"""T01 安全模块：凭据加载、敏感值登记与统一脱敏。"""
import json
import os
import re
import sys
import time
from pathlib import Path

# 敏感字段清单：值可进内存与请求头，但不得进日志、异常信息或版本库
SENSITIVE_FIELDS = ("GL-XSRF-TOKEN", "GOD_UUID", "device_id")

# 兜底正则：即使某个凭据没经过 register，也按 key=value 形态脱敏
_SECRET_PATTERNS = [
    re.compile(r"(GL-XSRF-TOKEN|GL-X-XSRF-TOKEN|GOD_UUID|GL-Uid|GL-DeviceId"
               r"|GL-CheckSum|ds-website-uuid)\s*[=:]\s*[^\s;&\"']+", re.I),
]


class SecretsRegistry:
    """敏感值登记表：登记过的明文值在 redact() 时替换为 ***。

    实例级状态，可注入；进程默认使用 GLOBAL_SECRETS 单例。"""

    def __init__(self):
        self._secrets = set()

    def register(self, value):
        if isinstance(value, str) and len(value) >= 6:
            self._secrets.add(value)

    def register_auth(self, auth):
        """登记一份认证配置里的全部凭据值。"""
        for key in SENSITIVE_FIELDS:
            self.register(auth.get(key))
        for v in (auth.get("cookies") or {}).values():
            self.register(v)

    def redact(self, text):
        if text is None:
            return ""
        if not isinstance(text, str):
            text = str(text)
        for secret in sorted(self._secrets, key=len, reverse=True):
            if secret in text:
                text = text.replace(secret, "***")
        for pat in _SECRET_PATTERNS:
            text = pat.sub(lambda m: m.group(1) + "=***", text)
        return text

    def clear(self):
        self._secrets.clear()


GLOBAL_SECRETS = SecretsRegistry()


def redact(text):
    """统一脱敏入口（进程级登记表）。"""
    return GLOBAL_SECRETS.redact(text)


def _coerce_cookies(raw):
    """统一三种 cookies 形态为 {name: value}：
    dict；浏览器导出数组 [{name, value}, ...]；单键对象数组 [{k: v}, ...]。"""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if v not in (None, "")}
    if isinstance(raw, list):
        out = {}
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("cookies 数组条目应为对象")
            if "name" in item:
                if item.get("value"):
                    out[str(item["name"])] = str(item["value"])
            elif len(item) == 1:
                k, v = next(iter(item.items()))
                if v:
                    out[str(k)] = str(v)
            else:
                raise ValueError("cookies 数组条目格式无法识别")
        return out
    raise ValueError("cookies 字段格式错误（应为对象或数组）")


def _cleanup_orphan_tmp(p):
    """清理上次崩溃残留的中转文件（含凭据，不能长期躺在磁盘上）。

    只删 60 秒前的：并发进程可能正在写自己的中转文件，不能误删在途写入。"""
    cutoff = time.time() - 60
    for orphan in p.parent.glob(p.name + ".*.tmp"):
        try:
            if orphan.stat().st_mtime < cutoff:
                orphan.unlink()
        except OSError:
            pass


def load_auth(path, base_dir=None, secrets=None):
    """加载账号凭据。按 文件存在 -> JSON 合法 -> 归一化 -> 必填字段 -> 权限
    顺序校验，并保证顶层鉴权字段与 cookies 字典一致（顶层为权威）。

    支持手写格式与浏览器插件导出格式（cookies 为 [{name,value},...]）；
    GL-XSRF-TOKEN / GOD_UUID / device_id 可从 cookies 反向推导
    （device_id 兼容 ds-website-uuid cookie）。

    错误信息只报告文件名与缺失字段名，绝不输出字段值。"""
    # 默认基准 = 项目根目录（chagee/ 的上一级），与 config.DIR 语义一致
    base = (Path(base_dir) if base_dir
            else Path(__file__).resolve().parent.parent)
    p = base / path
    if not p.exists():
        raise FileNotFoundError("认证文件不存在: %s" % path)
    _cleanup_orphan_tmp(p)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError("认证文件不是合法 JSON: %s（第 %s 行第 %s 列）"
                         % (path, e.lineno, e.colno)) from None
    if not isinstance(raw, dict):
        raise ValueError("认证文件格式错误（应为 JSON 对象）: %s" % path)
    auth = dict(raw)
    cookies = _coerce_cookies(auth.get("cookies"))

    def _from_cookies(key):
        for n, v in cookies.items():
            if n.lower() == key.lower():
                return v
        return None

    def _pick(key):
        return auth.get(key) or _from_cookies(key)

    # 归一化：顶层缺失时从 cookies 推导；device_id 兼容 ds-website-uuid
    auth["GL-XSRF-TOKEN"] = _pick("GL-XSRF-TOKEN")
    auth["GOD_UUID"] = _pick("GOD_UUID")
    auth["device_id"] = (_pick("device_id") or _pick("ds-website-uuid"))
    missing = [k for k in SENSITIVE_FIELDS if not auth.get(k)]
    if missing:
        raise ValueError("%s 缺少字段: %s" % (path, ", ".join(missing)))
    # cookies 与顶层对齐（顶层为权威），保证 header 合成与签名一致
    for k in ("GL-XSRF-TOKEN", "GOD_UUID"):
        for n in [n for n in cookies if n.lower() == k.lower()]:
            if n != k:
                del cookies[n]
        cookies[k] = auth[k]
    auth["cookies"] = cookies
    # 权限检查仅在 POSIX 平台有意义；Windows 上跳过
    if os.name == "posix":
        try:
            mode = p.stat().st_mode
            if mode & 0o077:
                print("警告: %s 权限对组/其他用户可读（%o），建议 chmod 600"
                      % (path, mode & 0o777), file=sys.stderr)
        except OSError:
            pass
    auth.setdefault("label", path)
    auth["_auth_file"] = str(p.resolve())
    registry = secrets if secrets is not None else GLOBAL_SECRETS
    registry.register_auth(auth)
    return auth


def save_auth(auth, path):
    """原子回写认证文件：剔除下划线开头的内部字段，POSIX 下收紧为 600 权限。

    只应写经过 load_auth 加载的结构；内容不打印、不进日志。
    label 不回写——它由 load_auth 按文件路径重新推导。
    中转文件名带 pid（cookies.json.1234.tmp）：多进程并发保存互不覆盖，
    且 *.tmp 已被 gitignore 覆盖，崩溃残留不会误入库。"""
    data = {k: v for k, v in auth.items()
            if not k.startswith("_") and k != "label"}
    p = Path(path)
    tmp = p.with_name("%s.%d.tmp" % (p.name, os.getpid()))
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        if os.name == "posix":
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
        os.replace(tmp, p)
    except BaseException:
        # 写入中途失败不能留下带凭据的中转文件
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
