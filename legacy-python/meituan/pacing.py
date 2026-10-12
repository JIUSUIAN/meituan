#!/usr/bin/env python3
"""节奏控制：全局限速器 + 可动态调整容量的在飞请求闸门。

P1 变更：不再用「替换全局 Semaphore」切换安全模式（P0 存在切换瞬间
在途请求仍持旧信号量的竞态），改为 InflightGate.set_max 动态调容量。
"""
import threading
import time
from contextlib import contextmanager


class RateLimiter:
    """全局领取请求限速器：任意两次 grant 之间至少间隔 min_gap 秒。

    由 GrantPacing 在**持有在飞闸门之后**调用，因此这里的「间隔」就是真实
    发送间隔的下界：等待发生在持闸期间，拿到时间槽即可发出。"""

    def __init__(self, min_gap):
        self.min_gap = min_gap
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            now = time.time()
            wait_for = self.min_gap - (now - self.last)
            if wait_for > 0:
                time.sleep(wait_for)
            self.last = time.time()


class InflightGate:
    """最多允许 max_inflight 个请求同时在飞；容量可运行时调整。"""

    def __init__(self, max_inflight):
        self.cond = threading.Condition(threading.Lock())
        self.max_inflight = max_inflight
        self.inflight = 0

    def set_max(self, n):
        with self.cond:
            self.max_inflight = n
            self.cond.notify_all()

    @contextmanager
    def slot(self):
        with self.cond:
            while self.inflight >= self.max_inflight:
                self.cond.wait()
            self.inflight += 1
        try:
            yield
        finally:
            with self.cond:
                self.inflight -= 1
                self.cond.notify()


class GrantPacing:
    """领取节奏 = 限速器（时间槽）+ 在飞闸门（并发上限）。

    实例级对象，随 LoopRunner 创建；不再有模块级可变全局。"""

    def __init__(self, first_gap, first_inflight,
                 sustained_gap, sustained_inflight):
        self.limiter = RateLimiter(first_gap)
        self.gate = InflightGate(first_inflight)
        self._sustained_gap = sustained_gap
        self._sustained_inflight = sustained_inflight
        self.sustained = False

    @contextmanager
    def slot(self):
        # 先取并发容量，再在真正发送前统一卡最小间隔。
        # 反过来（先限速、后等闸门）会让多个已经错峰的线程在闸门放开的瞬间
        # 挤在一起发出——0.5s 的安全间隔可能被打成 ~0s。
        # 持闸等待期间该线程仍占一个在飞位，容量统计保持真实。
        with self.gate.slot():
            self.limiter.wait()
            yield

    def enter_sustained_mode(self):
        """第一波结束后切换到安全模式。"""
        self.limiter.min_gap = self._sustained_gap
        self.gate.set_max(self._sustained_inflight)
        self.sustained = True
