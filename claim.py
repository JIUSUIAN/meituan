#!/usr/bin/env python3
"""美团外卖优惠券直调领取脚本（网易大神 partner-perks 页），多账号并发版。

原理：复刻页面 JS 的请求签名，直接 POST 领券接口，跳过浏览器。
实现细节见 meituan 包（meituan/__init__.py 有模块地图）。

用法：
  单次执行：    python3 claim.py
  只读健康检查：python3 claim.py --ping
                仅调用只读接口（info / grant-status），无业务副作用；
                能证明网络可达，无法证明登录态时返回 reachable 而非 authenticated。
  会话验证：    python3 claim.py --verify-session
                注意：有业务副作用！用探针券尝试一次领取来证明登录态，
                若当天探针券未领取，会实际领掉一张。
  循环抢券：    python3 claim.py --loop [--minutes 10] [--interval 2.0]
                [--fire-at 23:59:59.70] [--fire-lead 0.3]
              循环模式：多账号并发尝试领取，每轮内请求错峰发出
              （第一波 0.05s 极限间隔、最多 6 在飞（账号数×2 张券）；
               之后 0.5s 安全模式；命中限流后该账号退避 60 秒）。
              --fire-lead 是开火提前量：整点抢实测响应 1.8~3.2s，
              提前 0.3s 发出让请求在整点那一刻已到达服务端。
  指定账号：    python3 claim.py --loop --accounts 小号
                只跑匹配 label/认证文件名的账号（逗号分隔可多选）。
  消息通知：    配置 notify_targets = ["telegram","feishu","dingtalk",
                "serverchan","email","resend","webhook"] 里的任意几个，
                全局收件人用 notify_to_mails；
                收尾汇总 / 每账号领取详情 / 登录态失效 / 健康检查异常会推送到
                这些通道；账号条目里写 "notify": {"targets": [...], "to": [...]}
                或简写 "notify_mail": "邮箱" 可让每个账号走自己的通道与收件人。
                --no-notify 临时关掉，--notify 强制打开，
                --notify-test 按「全局 + 每账号路由」各发一条测试消息。
  凭据文件：    cookies.json 可以是单个账号对象，也可以是多账号数组
                （每条自带 label；轮换回写只更新自己那一条）。
  配置文件：    可选 claim.config.json（本目录，字段见 meituan/config.Config），
                亦可被 MEITUAN_* 环境变量与 CLI 参数覆盖（优先级递增）。
输出：JSON 走 stdout（日志走 stderr，可 `2>/dev/null > result.json`）。
策略：领取霸王茶姬品牌下所有有库存、可直接领取的券（不怕阵容变化）。
"""
import sys

from meituan.cli import main

if __name__ == "__main__":
    sys.exit(main())
