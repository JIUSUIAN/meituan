#!/usr/bin/env python3
"""Cookie 单一真源：CookieStore。

- 大小写不敏感、保留原始拼写；
- header() 是请求 Cookie 头的唯一出口；
- 服务端 Set-Cookie 只允许更新「跟踪名单」内的名字（默认 JSESSIONID）——
  GL-XSRF-TOKEN 等鉴权关键字段不允许被响应静默改写（签名依赖本地值）；
- 任何进入 store 的值都自动登记进脱敏表。

线程安全：内部锁保证 apply/header/to_dict 的一致性；同账号并发请求
（loop 第一波）共享同一 store。
"""
import threading

from .security import GLOBAL_SECRETS


class CookieStore:
    def __init__(self, initial=None, tracked_names=(), secrets=None):
        self._lock = threading.Lock()
        self._secrets = secrets if secrets is not None else GLOBAL_SECRETS
        self._tracked = {n.lower(): n for n in tracked_names}
        self._data = {}  # 小写名 -> (显示名, 值)，按插入顺序渲染
        for k, v in (initial or {}).items():
            if v:
                self._store(k, v)

    def _store(self, name, value):
        self._data[name.lower()] = (name, value)
        self._secrets.register(value)

    def get(self, name):
        with self._lock:
            entry = self._data.get(name.lower())
            return entry[1] if entry else None

    def set(self, name, value):
        """写入并返回是否发生变化（新名字算变化）。"""
        with self._lock:
            old = self._data.get(name.lower())
            if old is not None and old[1] == value:
                return False
            self._store(name, value)
            return True

    def header(self):
        with self._lock:
            return "; ".join("%s=%s" % (disp, v)
                             for disp, v in self._data.values())

    def apply_response(self, jar):
        """应用响应 Set-Cookie：仅更新跟踪名单内的名字。

        返回发生变化的显示名列表；非跟踪名字一律忽略（鉴权字段由本地掌控）。"""
        if not jar:
            return []
        try:
            items = list(jar.items())
        except Exception:
            return []
        changed = []
        with self._lock:
            for k, v in items:
                canonical = self._tracked.get(k.lower())
                if canonical is None or not v:
                    continue
                old = self._data.get(canonical.lower())
                if old is None or old[1] != v:
                    self._store(canonical, v)
                    changed.append(canonical)
        return changed

    def to_dict(self):
        with self._lock:
            return {disp: v for disp, v in self._data.values()}
