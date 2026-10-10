#!/usr/bin/env python3
"""配置分层：dataclass 默认值 -> JSON 配置文件 -> CHAGEE_* 环境变量 -> CLI 覆盖。

优先级从左到右递增；Config 实例创建后视为只读（运行期可变状态放在
pacing/flows 的实例里，不放模块全局）。
"""
import json
import os
from dataclasses import MISSING, dataclass, field, fields
from pathlib import Path
from typing import Optional

# 项目根目录（chagee/ 的上一级）：claim.config.json 与 cookies*.json 的所在处
DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_FILE = "claim.config.json"
ENV_PREFIX = "CHAGEE_"


@dataclass
class Config:
    # --- 业务目标 ---
    brand_keyword: str = "霸王茶姬"
    fixed_brand_id: str = "6a5f1884bde244285e958847"
    fixed_coupons: list = field(default_factory=lambda: [
        {"couponId": "6a5f1a1d4d7fef55f1590b26",
         "couponName": "【外卖券】满28减10", "couponType": "PHONE_REWARD"},
        {"couponId": "6a5f1a02f34ee33e0d7d9978",
         "couponName": "【5折外卖券】立减20", "couponType": "PHONE_REWARD"},
        {"couponId": "6a5f1a3df34ee33e0d7d9979",
         "couponName": "【5折外卖券】立减25", "couponType": "PHONE_REWARD"},
    ])
    snipe_keyword: str = "5折"        # 只抢含该关键词的券
    skip_types: tuple = ("PLACEHOLDER", "DIRECT_LINK")
    soldout_stop_after: int = 3       # 连续抢光 N 次则停止重试该券

    # --- 节奏参数（实测值，勿随意调）---
    refresh_every: float = 30         # 抢券期间列表刷新间隔（秒）
    first_wave_gap: float = 0.05      # 第一波任意两次 grant 最小间隔（秒）
    sustained_gap: float = 0.5        # 后续波次间隔（秒）
    # 第一波在飞上限：账号数 × 目标券数（实测 2 账号 4 并发、3 账号 6 并发，
    # 单波都在 0.15s 内打完且不触发 40007；跨波持续高频才会撞限流）
    first_wave_inflight: int = 6
    sustained_inflight: int = 2       # 后续波次在飞上限
    rate_limit_backoff: float = 60    # 命中限流后的退避秒数

    # --- 超时与网络 ---
    api_timeout: float = 20
    refresh_timeout: float = 8
    ping_timeout: float = 15
    user_agent: str = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36")
    base_url: str = "https://inf.ds.163.com"
    info_path: str = "/v1/web/exp-vip/external/super-coupon/info"
    grant_path: str = "/v1/web/exp-vip/external/super-coupon/grant"
    grant_status_path: str = "/v1/web/exp-vip/external/super-coupon/grant-status"

    # --- 文件与凭据 ---
    auth_files: tuple = ("cookies.json", "cookies-new.json")
    # 服务端轮换跟踪：JSESSIONID 是登录态载体（实测），响应 Set-Cookie 下发
    # 新值时本地必须跟随并回写，否则后续请求继续携带旧会话 ID
    session_cookie_names: tuple = ("JSESSIONID",)
    persist_rotated_cookies: bool = True  # 轮换后原子回写认证文件
    keepalive_log: str = str(
        Path.home() / "workspace/goals/goal/hidden_files/keepalive.log")
    run_log_dir: str = str(
        Path.home() / "workspace/goals/goal/hidden_files")

    # --- 消息通知（token/webhook/SMTP 密码都是凭据，登记脱敏）---
    # 通道名：telegram / feishu / dingtalk / serverchan / email / webhook
    notify_targets: tuple = ()
    notify_enabled: bool = True       # --no-notify 可临时关掉
    # 只发这些事件，避免高频打扰；account_result = 每账号单独一条领取详情，
    # 不想要逐条推送就把它从这里去掉
    notify_events: tuple = ("result", "account_result", "auth_expired", "health")
    notify_timeout: float = 5.0
    notify_mask_labels: bool = True   # 通知里掩掉 label 中的手机号等长数字
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    feishu_webhook: str = ""
    dingtalk_webhook: str = ""
    dingtalk_secret: str = ""         # 机器人「加签」密钥，留空则不签名
    serverchan_send_key: str = ""
    notify_webhook_url: str = ""      # 通用 webhook：POST {event,title,text}
    # 邮件类通道（email / resend）的全局收件人；账号条目里的
    # notify.to / notify_mail 可以覆盖它
    notify_to_mails: tuple = ()
    # 邮件：QQ/163 用 smtp 主机 + 授权码 + SSL(465)；Gmail 用 STARTTLS(587)
    email_smtp_host: str = ""         # 可写 'smtp.qq.com:465' 覆盖端口
    email_smtp_port: int = 465
    email_use_ssl: bool = True        # 465 隐式 TLS
    email_use_tls: bool = False       # 587 STARTTLS（use_ssl=False 时才生效）
    email_user: str = ""
    email_password: str = ""          # 授权码/应用专用密码，不是登录密码
    email_from: str = ""
    email_subject_prefix: str = ""
    # Resend（https://resend.com）：域名验证后直接用 API 发信，无需 SMTP
    resend_api_key: str = ""          # 建议用环境变量 CHAGEE_RESEND_API_KEY 注入
    resend_from: str = ""             # 例 no-reply@email.example.com（已验证域名）
    resend_from_name: str = "chagee 抢券"

    # --- 运行参数（CLI/环境变量可覆盖） ---
    loop_minutes: float = 10
    loop_interval: float = 2.0
    fire_at: Optional[str] = None
    # 开火提前量（秒）：整点抢的响应在 1.8~3.2s，把请求提前发出去补偿网络往返；
    # 0 表示严格按 fire_at 发出
    fire_lead: float = 0.0
    burst_test: bool = False          # CHAGEE_BURST_TEST=1：跳过安全模式切换

    @property
    def snipe_coupons(self):
        """抢券目标：只取含 snipe_keyword 的固定券。"""
        return [c for c in self.fixed_coupons
                if self.snipe_keyword in c["couponName"]]

    @property
    def probe_coupon(self):
        """会话验证探针券：固定券里不属于抢券目标的那张（满28减10）。

        与 fixed_coupons 同源——券 ID 只有一处定义，避免两处漂移。
        没有符合条件的券时返回 None，调用方需明确报错而不是猜一个 ID。"""
        return next((c for c in self.fixed_coupons
                     if self.snipe_keyword not in c["couponName"]), None)


def _cast(value, target_type):
    """把字符串值转成字段默认值的类型。"""
    if target_type is bool:
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if target_type is int:
        return int(value)
    if target_type is float:
        return float(value)
    if target_type is tuple:
        return tuple(s.strip() for s in str(value).split(",") if s.strip())
    return value


def load_config(path=None, overrides=None):
    """构建最终配置。

    层1 dataclass 默认值；层2 JSON 文件（存在才读，键必须是 Config 字段名）；
    层3 环境变量 CHAGEE_<FIELD_UPPER>；层4 overrides（CLI，仅非 None 项）。"""
    values = {}

    cfg_path = Path(path) if path else (DIR / DEFAULT_CONFIG_FILE)
    if cfg_path.exists():
        try:
            file_values = json.loads(cfg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError("配置文件不是合法 JSON: %s（第 %s 行第 %s 列）"
                             % (cfg_path, e.lineno, e.colno)) from None
        if not isinstance(file_values, dict):
            raise ValueError("配置文件格式错误（应为 JSON 对象）: %s" % cfg_path)
        # 下划线开头的键视为注释，忽略
        file_values = {k: v for k, v in file_values.items()
                       if not k.startswith("_")}
        known = {f.name for f in fields(Config)}
        unknown = set(file_values) - known
        if unknown:
            raise ValueError("配置文件包含未知字段: %s" % ", ".join(sorted(unknown)))
        values.update(file_values)

    for f in fields(Config):
        env_key = ENV_PREFIX + f.name.upper()
        if env_key not in os.environ:
            continue
        if f.default is MISSING:
            # default_factory 字段（fixed_coupons）是嵌套结构，环境变量表达不了；
            # 与其静默塞进一个字符串让 Config(**values) 炸出难懂的 TypeError，
            # 不如在这里就报清楚
            raise ValueError("字段 %s 不支持环境变量覆盖（请改配置文件）: %s"
                             % (f.name, env_key))
        values[f.name] = _cast(os.environ[env_key],
                               type(f.default) if f.default is not None else str)

    for k, v in (overrides or {}).items():
        if v is not None:
            values[k] = v

    # JSON 数组 -> tuple（与 dataclass 字段类型对齐）
    for f in fields(Config):
        if isinstance(f.default, tuple) and isinstance(values.get(f.name), list):
            values[f.name] = tuple(values[f.name])

    return Config(**values)
