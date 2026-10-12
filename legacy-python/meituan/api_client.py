#!/usr/bin/env python3
"""API Client：签名、请求发送与错误分层转换（网络层 -> 结构化异常）。

业务函数不再接触 requests 细节，也不再解析 RuntimeError 字符串。
"""
import hashlib
import json
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Config
from .cookies import CookieStore
from .errors import ApiError, ApiParseError, ApiTransportError
from .models import Coupon
from .security import GLOBAL_SECRETS, update_auth_cookies


class ApiClient:
    """单账号 API 客户端。session 可注入（测试/复用），否则自建并负责关闭。

    JSESSIONID 轮换跟踪：服务端在任意响应（含错误响应）里通过 Set-Cookie
    下发新的会话 Cookie 时，本地跟随更新、登记脱敏、可选原子回写认证文件。
    本地只跟随不制造——绝不自行生成/猜测会话 ID。"""

    def __init__(self, auth, session=None, config=None, secrets=None,
                 on_rotate=None):
        self.auth = auth
        self.config = config or Config()
        self.secrets = secrets if secrets is not None else GLOBAL_SECRETS
        # 同账号可能并发发起多个请求（loop 第一波），轮换更新需要小锁
        self._cookie_lock = threading.Lock()
        # on_rotate(cookie_name)：轮换发生时的回调（只传名字，不传值）
        self.on_rotate = on_rotate
        # Cookie 单一真源：以 auth["cookies"] 为准；鉴权字段以顶层为权威覆盖
        # （签名始终用顶层 GL-XSRF-TOKEN，头部必须同值——防绕过 load_auth
        # 归一化直接构造 auth 的调用方出现签名/头部漂移）
        seed = dict(auth.get("cookies") or {})
        seed["GL-XSRF-TOKEN"] = auth["GL-XSRF-TOKEN"]
        seed["GOD_UUID"] = auth["GOD_UUID"]
        self.cookies = CookieStore(seed,
                                   tracked_names=self.config.session_cookie_names,
                                   secrets=self.secrets)
        if session is not None:
            self.session = session
            self._owns_session = False
        else:
            self.session = requests.Session()
            self._owns_session = True
            # 连接级重试（请求尚未发出即失败才重试，grant 等非幂等 POST 安全）；
            # 读超时/状态码不自动重试，交由上层波次逻辑决定。
            # 仅对支持 mount 的真实 Session 生效（注入的测试替身跳过）。
            if hasattr(self.session, "mount"):
                retry = Retry(total=2, connect=2, read=0, status=0, redirect=0,
                              backoff_factor=0.1)
                adapter = HTTPAdapter(max_retries=retry)
                self.session.mount("https://", adapter)
                self.session.mount("http://", adapter)

    def close(self):
        if self._owns_session:
            self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- 底层 POST：与页面 axios 行为对齐 -------------------------------

    def post(self, path, body, timeout=None):
        """手动序列化 JSON（保证签名用的字节与发送一致），统一转换错误：

        网络异常/HTTP 非 2xx -> ApiTransportError；非 JSON -> ApiParseError；
        业务 code 非 200 -> ApiError(code)。消息均已脱敏且限长 200。"""
        cfg = self.config
        timeout = cfg.api_timeout if timeout is None else timeout
        # 对齐 JS 的 JSON.stringify：无空格、键按插入顺序、不转义 Unicode
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        xsrf = self.auth["GL-XSRF-TOKEN"]
        checksum = hashlib.sha1((raw + xsrf).encode("utf-8")).hexdigest()
        # Cookie 头唯一出口：CookieStore（load_auth 已保证与签名用值一致）
        cookie_header = self.cookies.header()
        headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "GL-DeviceId": self.auth["device_id"],
            "GL-X-XSRF-TOKEN": xsrf,
            "GL-Uid": self.auth["GOD_UUID"],
            "GL-ClientType": "60",
            "GL-CheckSum": checksum,
            "Cookie": cookie_header,
            "User-Agent": cfg.user_agent,
            "Origin": "https://vip.ds.163.com",
            "Referer": ("https://vip.ds.163.com/partner-perks"
                        "?wvFullScreen=true&wvStatusBarStyle=white"
                        "&utm_source=hy.myicon"),
        }
        try:
            r = self.session.post(cfg.base_url + path, data=raw.encode("utf-8"),
                                  headers=headers, timeout=timeout)
        except requests.RequestException as e:
            raise ApiTransportError("网络请求失败: %s" %
                                    self.secrets.redact(str(e))[:200]) from None
        # 轮换跟踪先于错误处理：Set-Cookie 可能随任意状态码（含 4xx/5xx）下发
        self._follow_cookie_rotation(r)
        if r.status_code >= 400:
            # 响应正文限长且脱敏后才进异常，避免整段响应进日志
            raise ApiTransportError(
                "HTTP %s: %s" % (r.status_code, self.secrets.redact(r.text)[:200]),
                http_status=r.status_code)
        try:
            data = r.json()
        except ValueError:
            raise ApiParseError("响应不是合法 JSON（HTTP %s）" % r.status_code,
                                http_status=r.status_code) from None
        if not isinstance(data, dict):
            raise ApiParseError("响应结构异常（非 JSON 对象）",
                                http_status=r.status_code)
        if data.get("code") != 200:
            raise ApiError(data.get("code"),
                           self.secrets.redact(str(data.get("errmsg") or ""))[:200],
                           http_status=r.status_code)
        return data.get("result")

    def userinfo(self, timeout=None):
        """查询用户信息（只读 GET，无副作用）。返回原始 result。

        登录过期时抛 ApiError(873)，可作无副作用的会话探针——
        替代 grant-status 探针，后者在探针券当天未领时会实际领掉一张。
        GET 不带 body，故不做 GL-CheckSum 签名（与官方 web 端行为一致）。
        """
        cfg = self.config
        timeout = cfg.api_timeout if timeout is None else timeout
        headers = {
            "GL-DeviceId": self.auth["device_id"],
            "GL-X-XSRF-TOKEN": self.auth["GL-XSRF-TOKEN"],
            "GL-Uid": self.auth["GOD_UUID"],
            "GL-ClientType": "60",
            "Cookie": self.cookies.header(),
            "User-Agent": cfg.user_agent,
            "Origin": "https://vip.ds.163.com",
        }
        try:
            r = self.session.get(cfg.base_url + cfg.userinfo_path,
                                 headers=headers, timeout=timeout)
        except requests.RequestException as e:
            raise ApiTransportError("网络请求失败: %s" %
                                    self.secrets.redact(str(e))[:200]) from None
        # 轮换跟踪先于错误处理：Set-Cookie 可能随任意状态码下发
        self._follow_cookie_rotation(r)
        if r.status_code >= 400:
            raise ApiTransportError(
                "HTTP %s: %s" % (r.status_code, self.secrets.redact(r.text)[:200]),
                http_status=r.status_code)
        try:
            data = r.json()
        except ValueError:
            raise ApiParseError("响应不是合法 JSON（HTTP %s）" % r.status_code,
                                http_status=r.status_code) from None
        if not isinstance(data, dict):
            raise ApiParseError("响应结构异常（非 JSON 对象）",
                                http_status=r.status_code)
        if data.get("code") != 200:
            raise ApiError(data.get("code"),
                           self.secrets.redact(str(data.get("errmsg") or ""))[:200],
                           http_status=r.status_code)
        return data.get("result")

    # -- JSESSIONID 等会话 Cookie 的轮换跟踪 -------------------------------

    def _follow_cookie_rotation(self, r):
        """响应 Set-Cookie -> CookieStore 按跟踪名单跟随 -> 同步 auth ->
        可选原子回写 -> on_rotate 回调（只传 cookie 名，不传值）。

        纯 best-effort：轮换处理失败绝不影响主请求路径。"""
        try:
            changed = self.cookies.apply_response(getattr(r, "cookies", None))
        except Exception:
            return
        if not changed:
            return
        with self._cookie_lock:
            self.auth["cookies"] = self.cookies.to_dict()
            if self.config.persist_rotated_cookies:
                auth_file = self.auth.get("_auth_file")
                if auth_file:
                    try:
                        # 多账号单文件按 _auth_index 就地更新本条，
                        # 整体覆盖会抹掉同文件里的其他账号
                        update_auth_cookies(self.auth["cookies"], auth_file,
                                            index=self.auth.get("_auth_index"))
                    except (OSError, ValueError):
                        pass  # 回写失败不影响本次请求；下次轮换再试
        if self.on_rotate is not None:
            for name in changed:
                try:
                    self.on_rotate(name)
                except Exception:
                    pass

    # -- 业务端点 -------------------------------------------------------

    def coupon_info(self, timeout=None):
        """券列表（只读，不校验登录）。"""
        return self.post(self.config.info_path, {}, timeout=timeout)

    def find_brand_coupons(self, timeout=None):
        """拉取目标品牌及券列表，返回 (brand, [Coupon])（API 边界即转换模型）。"""
        result = self.coupon_info(timeout=timeout)
        brands = (result or {}).get("brands") or []
        brand = next((b for b in brands
                      if self.config.brand_keyword in (b.get("brandName") or "")),
                     None)
        if not brand:
            return None, []
        coupons = [Coupon.from_api(c)
                   for c in (brand.get("superCoupons") or [])
                   if isinstance(c, dict)]
        return brand, coupons

    def grant(self, brand_id, coupon):
        """领取一张券（有业务副作用）。返回原始 result。"""
        body = {"brandId": brand_id, "superCouponId": coupon.coupon_id}
        if coupon.is_phone_reward():
            body["phoneBizType"] = "VIP"
        return self.post(self.config.grant_path, body)

    def grant_status(self, coupon_ids, timeout=None):
        """查询券状态（只读）。失败抛异常——调用方可区分「成功且为空」与「失败」。

        返回 {couponId: status}。"""
        ids = [c for c in coupon_ids if c]
        if not ids:
            return {}
        st = self.post(self.config.grant_status_path,
                       {"superCouponIds": ids}, timeout=timeout)
        # 历史响应里键名有过 couponId / superCouponId 两种写法，按请求侧字段名
        # 优先取 couponId；两者同时出现时以 couponId 为准（与 grant 请求一致）
        return {(g.get("couponId") or g.get("superCouponId")): g.get("status")
                for g in ((st or {}).get("grantItems") or [])}
