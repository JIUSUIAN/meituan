#!/usr/bin/env python3
"""霸王茶姬优惠券直调领取脚本（网易大神 partner-perks 页），多账号并发版。

原理：复刻页面 JS 的请求签名，直接 POST 领券接口，跳过浏览器。
实现细节见 chagee 包（chagee/__init__.py 有模块地图）。

用法：
  单次执行：    python3 claim.py
  只读健康检查：python3 claim.py --ping
                仅调用只读接口（info / grant-status），无业务副作用；
                能证明网络可达，无法证明登录态时返回 reachable 而非 authenticated。
  会话验证：    python3 claim.py --verify-session
                注意：有业务副作用！用探针券尝试一次领取来证明登录态，
                若当天探针券未领取，会实际领掉一张。
  循环抢券：    python3 claim.py --loop [--minutes 10] [--interval 2.0]
              循环模式：双账号并发尝试领取，每轮内请求错峰发出
              （任意两次领取请求间隔 >= 0.35s，避免触发 40007 限流；
               命中限流后该账号退避 60 秒）。
  配置文件：    可选 claim.config.json（本目录，字段见 chagee/config.Config），
                亦可被 CHAGEE_* 环境变量与 CLI 参数覆盖（优先级递增）。
输出：JSON 走 stdout（日志走 stderr，可 `2>/dev/null > result.json`）。
策略：领取霸王茶姬品牌下所有有库存、可直接领取的券（不怕阵容变化）。
"""
import sys

from chagee.cli import main

if __name__ == "__main__":
    sys.exit(main())
