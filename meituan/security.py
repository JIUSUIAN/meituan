#!/usr/bin/env python3
"""T01 安全模块：凭据加载、敏感值登记与统一脱敏。"""
import json
import os
import re
import sys
import threading
import time
from collections import Counter
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


def _read_json(p, path):
    """读认证文件，把 JSON 解析错误转成带位置的人话报错。"""
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError("认证文件不是合法 JSON: %s（第 %s 行第 %s 列）"
                         % (path, e.lineno, e.colno)) from None


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


def _normalize_entry(entry, p, path, index=None, secrets=None):
    """单条账号字典 -> 归一化 auth：cookies 形态归一、鉴权字段反推、必填校验、
    顶层与 cookies 对齐、权限警告、登记脱敏。错误只报文件名与字段名，不报值。"""
    auth = dict(entry)
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
        where = path if index is None else "%s[%d]" % (path, index)
        raise ValueError("%s 缺少字段: %s" % (where, ", ".join(missing)))
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
    if not auth.get("label"):
        # 数组条目没写 label 就用 文件名#序号，保证账号标识唯一且可追溯
        auth["label"] = path if index is None else "%s#%d" % (path, index)
    auth["_auth_file"] = str(p.resolve())
    if index is not None:
        # 多账号单文件：回写时按此序号就地更新本条，不动其他账号
        auth["_auth_index"] = index
    registry = secrets if secrets is not None else GLOBAL_SECRETS
    registry.register_auth(auth)
    return auth


def _dedupe_labels(auths):
    """label 是客户端字典、退避表与报告的键，重复会静默顶掉账号。

    有重复时，该 label 的所有实例统一加 #序号（保留文件里的原始命名习惯）。"""
    counts = Counter(a["label"] for a in auths)
    dup = {k for k, n in counts.items() if n > 1}
    if not dup:
        return
    seen = Counter()
    for a in auths:
        if a["label"] in dup:
            seen[a["label"]] += 1
            a["label"] = "%s#%d" % (a["label"], seen[a["label"]])


def load_auth(path, base_dir=None, secrets=None):
    """加载单账号认证文件（顶层 JSON 对象）。

    按 文件存在 -> JSON 合法 -> 归一化 -> 必填字段 -> 权限 顺序校验，并保证
    顶层鉴权字段与 cookies 字典一致（顶层为权威）。

    支持手写格式与浏览器插件导出格式（cookies 为 [{name,value},...]）；
    GL-XSRF-TOKEN / GOD_UUID / device_id 可从 cookies 反向推导
    （device_id 兼容 ds-website-uuid cookie）。

    文件顶层是账号数组（多号并一文件）时请用 load_auths。
    错误信息只报告文件名与缺失字段名，绝不输出字段值。"""
    # 默认基准 = 项目根目录（meituan/ 的上一级），与 config.DIR 语义一致
    base = (Path(base_dir) if base_dir
            else Path(__file__).resolve().parent.parent)
    p = base / path
    if not p.exists():
        raise FileNotFoundError("认证文件不存在: %s" % path)
    _cleanup_orphan_tmp(p)
    raw = _read_json(p, path)
    if not isinstance(raw, dict):
        raise ValueError("认证文件格式错误（应为 JSON 对象；多账号数组请用 "
                         "load_auths）: %s" % path)
    return _normalize_entry(raw, p, path, secrets=secrets)


def load_auths(paths, base_dir=None, secrets=None):
    """从若干认证文件加载全部账号。

    每个文件顶层可以是单对象（一账号）或数组（多账号并入一个文件——实际用法）。
    数组条目会记下 `_auth_index`，轮换回写时只更新自己那一条。
    文件不存在则跳过（是否存在、要不要警告由调用方决定，与 load_auth 区分）。"""
    base = (Path(base_dir) if base_dir
            else Path(__file__).resolve().parent.parent)
    auths = []
    for path in paths:
        p = base / path
        if not p.exists():
            continue
        _cleanup_orphan_tmp(p)
        raw = _read_json(p, path)
        if isinstance(raw, dict):
            entries = [(raw, None)]
        elif isinstance(raw, list):
            entries = []
            for i, item in enumerate(raw):
                if not isinstance(item, dict):
                    raise ValueError("认证文件第 %d 个条目不是对象: %s"
                                     % (i, path))
                entries.append((item, i))
        else:
            raise ValueError("认证文件格式错误（应为 JSON 对象或账号数组）: %s"
                             % path)
        for entry, index in entries:
            auths.append(_normalize_entry(entry, p, path, index=index,
                                          secrets=secrets))
    _dedupe_labels(auths)
    return auths


# 读-改-写需要进程内串行：同一文件里多个账号并发轮换时不能互相覆盖条目
_FILE_LOCK = threading.Lock()


def _atomic_write_json(p, data):
    """原子写 JSON：pid 后缀中转文件 + rename，POSIX 下收紧 600。

    中转文件名带 pid（cookies.json.1234.tmp）：多进程并发保存互不覆盖，
    且 *.tmp 已被 gitignore 覆盖，崩溃残留不会误入库；写入失败即清理。"""
    p = Path(p)
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


def write_auth_file(data, path):
    """原子写入整个认证文件（单对象或多账号数组），POSIX 下收紧 600 权限。

    轮换回写不要用这个（整体覆盖会抹掉同文件其他账号），用 update_auth_cookies。"""
    _atomic_write_json(path, data)


def save_auth(auth, path):
    """整体回写认证文件：剔除下划线开头的内部字段。

    只应写经过 load_auth 加载的结构；内容不打印、不进日志。
    label 不回写——它由 load_auth 按文件路径重新推导。
    多账号单文件的轮换回写不要用这个函数（整体覆盖会抹掉同文件其他账号），
    要用 update_auth_cookies。"""
    data = {k: v for k, v in auth.items()
            if not k.startswith("_") and k != "label"}
    _atomic_write_json(path, data)


def update_auth_cookies(cookies, path, index=None):
    """把轮换后的 cookies 就地写回文件对应条目，其余字段（含 label）原样保留。

    index 为 None -> 单对象文件；给定 -> 多账号数组文件的第 index 条
    （load_auths 会记下 _auth_index）。读-改-写全程持锁。"""
    p = Path(path)
    with _FILE_LOCK:
        raw = _read_json(p, p.name)
        if index is None:
            if not isinstance(raw, dict):
                raise ValueError("认证文件是数组格式但缺少条目序号: %s" % path)
            raw["cookies"] = dict(cookies)
        elif (isinstance(raw, list) and 0 <= index < len(raw)
              and isinstance(raw[index], dict)):
            raw[index]["cookies"] = dict(cookies)
        else:
            raise ValueError("认证文件里找不到第 %s 个账号条目: %s"
                             % (index, path))
        _atomic_write_json(p, raw)
