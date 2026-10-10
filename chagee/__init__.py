#!/usr/bin/env python3
"""chagee：网易大神 partner-perks 霸王茶姬领券自动化包。

模块（P1 收敛后）：
  cli.py        命令行入口（claim.py 为薄启动器）
  config.py     配置分层：默认值 -> claim.config.json -> CHAGEE_* 环境变量 -> CLI
  security.py   凭据加载、敏感值登记与统一脱敏（T01）
  errors.py     结构化 API 错误体系与业务码映射（T03）
  cookies.py    CookieStore：单账号 Cookie 单一真源 + 跟踪名单
  models.py     领域模型：Coupon / GrantEvent
  api_client.py 签名、请求、错误转换、JSESSIONID 轮换跟随（单账号客户端）
  pacing.py     限速器 + 可动态调容量的在飞闸门
  flows.py      业务流程：ping / verify_session / single_run / LoopRunner
"""

__version__ = "1.8.0"
