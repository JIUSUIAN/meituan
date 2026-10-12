# 美团外卖优惠券自动领取（meituan）

网易大神「大神会员 partner-perks」页面美团外卖券的自动领取工具：复刻页面 JS 的请求签名，
直调领券接口、跳过浏览器。支持多账号并发、整点定时开抢、限流退避、会话凭据自动跟随，
结果输出为可管道解析的 JSON，并可推送富文本报告邮件。

| 项 | 值 |
|---|---|
| 版本 | `1.21.0`（真源 `meituan/__init__.py:__version__`） |
| 运行环境 | Python ≥ 3.9，依赖 `requests`（Windows 另需 `tzdata`） |
| 测试 | 267 个，全部 mock，不访问真实第三方接口 |
| 当前活动商家 | 霸王茶姬（`brand_keyword`） |
| 抢券目标 | 两张 5 折外卖券（`snipe_keyword="5折"`） |
| 探针券 | 【外卖券】满28减10（`--verify-session` 用，不参与抢券） |

## 1. 工作原理

页面 JS 用 axios 带一组 `GL-*` 头访问接口，本项目在 `meituan/api_client.py` 中等价复刻：

| 接口 | 方法 / 请求体 | 用途 |
|---|---|---|
| `/v1/web/exp-vip/external/super-coupon/info` | `POST {}` | 券列表（**不校验登录**，只取阵容与探活） |
| `/v1/web/exp-vip/external/super-coupon/grant` | `POST {brandId, superCouponId[, phoneBizType:"VIP"]}` | 领取（有业务副作用） |
| `/v1/web/exp-vip/external/super-coupon/grant-status` | `POST {superCouponIds:[...]}` | 已领状态（只读，可证明登录态） |

签名与身份：

```
GL-CheckSum     = SHA1( JSON.stringify(body) + GL-XSRF-TOKEN 的 cookie 值 )
GL-X-XSRF-TOKEN = GL-XSRF-TOKEN        GL-Uid      = GOD_UUID cookie
GL-DeviceId     = localStorage 的 ds-website-uuid    GL-ClientType = 60
```

`JSON.stringify` 的对齐是关键：请求体由代码手工序列化（`separators=(",", ":")`、
`ensure_ascii=False`、按插入顺序），**签名用的字节与实际发送的字节完全一致**，否则校验失败。
Cookie 头由 `CookieStore` 单点合成，且签名用的 `GL-XSRF-TOKEN` 与头部同值——顶层鉴权字段为权威，
防止签名与请求头漂移。

## 2. 安装

```bash
cd meituan
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .                                  # 或 pip install -r requirements.txt
```

三种等价入口：`meituan ...`（控制台脚本）、`python claim.py ...`、`python -m meituan.cli ...`。

Windows 注意：控制台为 GBK 时中文日志可能乱码，设 `PYTHONIOENCODING=utf-8`（日志文件本身是 UTF-8）；
`zoneinfo` 需要 `tzdata` 包（已作为平台条件依赖写入 `pyproject.toml`）。

## 3. 快速开始

```bash
meituan --ping                                          # 只读健康检查（cron 保活用）
meituan --verify-session --accounts cookies-new         # 验证新导出的凭据（有副作用！）
meituan --loop --fire-at 23:59:59.70                    # 整点抢（自动算开火提前量）
meituan --loop --accounts 177****7689                   # 只跑某个账号
meituan --loop 2>/dev/null > result.json                # stdout 只有 JSON 报告
meituan --notify-test                                   # 按通道 + 账号路由各发一条自检
```

## 4. 凭据准备

凭据文件放在**项目根目录**（`meituan/` 的上一级），文件名由 `auth_files` 配置，
默认 `("cookies.json", "cookies-new.json")`——存在哪个用哪个。

`cookies.example.json` 是模板（会入库），照着填即可。桌面 Chrome 获取方式：
打开领券页并保持登录 → F12 → Application → Cookies → 取 `vip.ds.163.com` / `.163.com`
域下的 `GL-XSRF-TOKEN` 与 `GOD_UUID`；同面板 Local Storage → 取 `ds-website-uuid` 作为 `device_id`。

### 4.1 多账号（一个文件放账号数组，推荐）

```json
[
  { "label": "177****7689", "GL-XSRF-TOKEN": "...", "GOD_UUID": "...",
    "device_id": "...", "cookies": { "JSESSIONID": "..." },
    "notify": { "targets": ["email"], "to": ["老板邮箱@example.com"] } },
  { "label": "193****6704", "...": "..." }
]
```

- `notify` / `notify_mail` 可选：**账号级通知路由**，决定这个账号的领取详情
  （`account_result`）走哪条通道、发给谁。`targets` 缺省沿用全局 `notify_targets`，
  `to` 缺省沿用全局 `notify_to_mails`；`notify_mail` 是「只换收件人」的简写。
  通道凭据（SMTP 授权码、webhook 等）仍只放全局配置——凭据不散落到多个文件，
  路由又能跟账号一起进 gitignore 的凭据文件。
- 三条鉴权字段可省略，会从 `cookies` 反推（`device_id` 兼容 `ds-website-uuid` cookie）；
  `cookies` 也支持浏览器扩展导出的数组形态 `[{name, value}, ...]`。
- 没写 `label` 时：**优先从 cookie 里解析手机号**（`P_INFO` / `S_INFO` / `NTES_YD_PASSPORT`，
  实测 `P_INFO` 稳定携带），脱敏成 `前3****后4`（如 `177****7689`）；解析不到才退回 `文件名#序号`。
- label 重复一律加序号去重——label 是客户端字典、退避表与报告的键，重复会静默顶掉账号。

### 4.2 从浏览器导出（JSESSIONID 是 HttpOnly）

页面 JS / 书签栏脚本读不到 HttpOnly 的 JSESSIONID，**只能用浏览器扩展**
（Cookie-Editor、EditThisCookie 等）导出，再用工具转换：

```bash
python tools/import_cookie_export.py export.json --domain 163.com -o cookies-new.json
python tools/import_cookie_export.py export.json --domain 163.com \
    --merge --label 177****7689 -o cookies.json
```

`--merge` 按 label 定位：同 label 替换该条，否则追加，其他账号原样不动。
工具只做格式转换与完整性校验（校验不过会回滚，不毁掉同文件其他账号），
**不生成、不猜测任何凭据值**。

### 4.3 安全红线（代码强制）

- `GL-XSRF-TOKEN` / `GOD_UUID` / `device_id` / 所有 cookie 值：登记进脱敏表，
  日志、异常信息、stdout 报告输出前统一 `redact()`；另有 `KEY=value` 形态兜底正则。
- `cookies*.json`、`claim.config.json`、`*.log`、`*.jsonl`、`*.tmp` 全部 gitignore；
  CI 有「凭据入库守卫」，检测到 `cookies*.json` 被跟踪就直接失败。
  凭据一旦入库按已泄露处理，重新获取。
- 会话 ID 只跟随服务端下发，绝不本地生成/伪造。
- HTTP 错误正文截断 200 字符并脱敏后才进异常对象。

## 5. 命令与四种运行模式

```bash
meituan                              # 单次执行（默认）
meituan --loop [--minutes 10] [--interval 2.0]
meituan --loop --fire-at 23:59:59.70
meituan --ping                       # 只读健康检查
meituan --verify-session             # 会话验证（有副作用）
meituan --loop --accounts 177****7689 # 只跑指定账号（label 或文件名，逗号分隔）
meituan --loop 2>/dev/null > result.json
```

| 模式 | 做什么 | 副作用 | 报告状态 | 退出码 |
|---|---|---|---|---|
| 单次（默认） | 拉列表 → 查已领状态 → 逐张尝试可领券（`single_run_snipe_only=true` 时只处理目标券） | 会真领 | 每账号一组 `{coupon, status, detail}` | 任一账号执行异常 → 1 |
| `--loop` | 只抢目标券（两张 5 折），波次重试直到全有结论或超时 | 会真领 | 同上 + `grant_status` | 任一 `auth_expired`/`error` → 1 |
| `--ping` | 只调 info + grant-status 两个只读接口 | 无 | `reachable` / `expired` / `unknown` / `error: ...` | 任一 `expired`/`error` → 1 |
| `--verify-session` | 用探针券试领一次，证明登录态 | **有**（当天探针券未领会领掉一张） | `authenticated` / `expired` / `unknown` / `error: ...` | 有任一非 `authenticated` → 1 |

- `--ping` 与 `--verify-session` 互斥。
- 只读接口不校验登录，所以 `--ping` **不会**谎报 `authenticated`；想确认登录态用
  `--verify-session`（已领过返回 803 仍判 `authenticated`，幂等）。
- 单次与 loop 的目标不同：单次默认覆盖品牌下全部可领券，loop 只打 `snipe_keyword`
  命中的券，把第一波火力留给目标。想让单次也只处理目标券，开 `single_run_snipe_only`。

## 6. 抢券行为细节（`--loop`）

### 6.1 时间线

1. 装配：每账号一个 `ApiClient`（独立 CookieStore + 连接级重试）+ 一套节奏控制器；
   目标券直接来自配置（**不等列表，第一波零延迟**）。
2. 时钟校验：Linux 查 `timedatectl`（空输出会附带 rc/stderr 便于诊断），其他平台记「跳过」。
3. 预热（仅指定 `--fire-at` 时）：各账号并发打一次只读请求（串行约 6.5s，并行约 2s），
   把 TCP+TLS 握手做完并测得 RTT。
4. 自适应提前量：按预热 RTT 中位数 × 0.2 计算 `lead`，钳制在 [0.2, 0.6]s
   （RTT≈1.5s 时恰为实测验证过的 0.3s）；关闭 `adaptive_lead` 或无预热数据时回退固定 `fire_lead`。
5. 精确等待：`sleep` 到只剩 5ms，最后用 `perf_counter` 单调钟忙等（Windows 上
   `time.time` 分辨率约 15ms，会整体偏移）。跨零点保护：若已错过目标 30 分钟内则立即开火。
6. 波次循环（deadline = `minutes`）：
   - 第一波结束后、以及每 `refresh_every` 秒提交一次列表刷新，**只增量合并**新出现的
     `snipe_keyword` 券，不删已有目标；
   - 每波任务 = 各账号未 settled 的目标券，优先券排前；
   - 第一波打完自动切「安全模式」（`sustained_gap` / `sustained_inflight`）；
   - **首波全抢光提前收工**：第一波全部为 60001（抢光）时，第二波确认后仍全抢光即收工，
     不再空转烧配额（每日一次投放，1 秒内抢完后不会补货）；出现 granted / 限流则不触发；
   - 所有目标都有结论 → 提前结束；否则 sleep `interval` 进下一波。
7. 收尾：统计 → 事件明细落 JSONL → 用 `grant-status` 再核一次真实领取状态 → 输出报告。

### 6.2 节奏参数（实测值，改前先看 JSONL 数据）

| 参数 | 默认 | 说明 |
|---|---|---|
| `first_wave_gap` | 0.05s | 第一波任意两次 grant 的最小间隔 |
| `first_wave_inflight` | 6 | 第一波同时在飞上限（账号数 × 2 张券；实测 2 账号 4、3 账号 6 都不触发 40007） |
| `sustained_gap` / `sustained_inflight` | 0.5s / 2 | 后续波次安全模式 |
| `rate_limit_backoff` | 60s | 命中 40007 后该账号退避 |
| `soldout_stop_after` | 3 | 同一张券连续 60001 达到次数即停 |
| `refresh_every` | 30s | 抢券期间列表刷新间隔 |
| `fire_lead` | 0.0 | 固定开火提前量（`adaptive_lead` 关闭时使用） |
| `adaptive_lead` | true | 用预热 RTT 自适应提前量（中位数×0.2，钳制 0.2~0.6s） |
| `early_stop_all_soldout` | true | 首波全抢光时确认一波后提前收工 |
| `api_timeout` / `refresh_timeout` / `ping_timeout` | 20 / 8 / 15 | 超时按用途分档，抢券期间快速失败 |

线程池规模 = `账号数 × (目标券数 + 1) + 1`（2 账号 → 7，3 账号 → 10）；
真正的领取并发由「限速器 + 在飞闸门」双重限制，与线程数无关。

### 6.3 单张券的状态机

| 业务码 | 领域状态 | 之后怎么做 |
|---|---|---|
| 200 | `granted` | 该券收工 |
| 803 | `already_claimed` | 收工 |
| 40007 | `rate_limited` | 该账号退避 60s，保留重试 |
| 873 | `auth_expired` | **停止重试**（重试无意义），报告里标出 |
| 60001 | `out_of_stock` | 连击计数，达 `soldout_stop_after` 才停 |
| 其他码 | `failed`（detail 保留原码） | 保留重试；文案命中「不存在/已下架/已失效」才停 |

未知业务码一律记 `failed` 并保留原码，**不做字符串猜测、不误分类**。
本地预检：`leftStock == 0` → `out_of_stock`（未知按未抢光）；`PLACEHOLDER` → `skipped`；
`DIRECT_LINK` → `direct_link`。

传输/解析失败（网络异常、超时、HTTP 非 2xx、响应不是合法 JSON）记为 `error`，
`detail` 形如 `传输错误: ...`。它**不是业务状态**：`--loop` 中照常重试，
但会进入退出码判定——cron 与告警因此能发现「这一轮根本没抢成」，
而业务上的没抢到（60001）不会误报成失败。

`send_ts`（实际发出 POST 的时刻，百分之一秒）在限速等待与在飞闸门都等到之后才采集，
收尾统计里的「第一波发送时刻」因此能真正反映错峰效果。

## 7. 输出

### 7.1 stdout（可管道解析）

```json
{
  "177****7689": [
    {"coupon": "【5折外卖券】立减20", "status": "granted",
     "detail": "{'winPrizeInfo': {...}}", "grant_status": "GRANTED"},
    {"coupon": "【5折外卖券】立减25", "status": "out_of_stock",
     "detail": "code=60001: 已抢光"}
  ]
}
```

`grant_status` 来自收尾的 `grant-status` 复核，是服务端记录的最终事实；
`detail` 一律脱敏且限长 200。日志、进度、警告全部走 stderr。

### 7.2 文件产物

| 文件 | 位置 | 内容 |
|---|---|---|
| 运行日志 | `run_log_dir/claim-<时间>.log`、`claim-single-<时间>.log` | 与 stderr 同源（UTF-8） |
| 事件明细 | 同目录同名 `.jsonl` | 每次 grant 一行：`send_ts / label / coupon_name / status / elapsed`，无凭据 |
| 保活日志 | `keepalive_log` | `--ping`/`--verify-session` 每账号一行 |

默认 `run_log_dir` / `keepalive_log` 指向 `~/workspace/goals/goal/hidden_files`，
用 `MEITUAN_RUN_LOG_DIR`、`MEITUAN_KEEPALIVE_LOG` 或配置文件改。

复盘建议：`jsonl` 里能算出第一波实际错峰间隔与耗时分布，是调参的唯一依据。

## 8. 会话与 JSESSIONID

实测确认 JSESSIONID 是大神登录态载体，因此内置「跟随层」：

- **能做的**：任意响应（含 4xx/5xx 与业务错误）的 `Set-Cookie` 里出现跟踪名单内的
  名字且值变化 → 更新内存 → 登记脱敏 → **按条目原子回写认证文件**（数组文件只动
  自己那条，读-改-写持锁）→ 触发 `on_rotate` 回调（只传 cookie 名，不传值）。
  `single_run` 与 `--loop` 会为此记一行日志；`--ping`/`--verify-session` 同样跟随回写，
  但不传回调，因此不留日志。
- **名单可配**：`session_cookie_names`（默认 `("JSESSIONID",)`）；名单外的字段
  不接受服务端改写，`GL-XSRF-TOKEN` 等签名依赖字段由本地掌控。
  `persist_rotated_cookies=False` 可关回写（仅内存跟随）。
- **不做的**：不生成、不猜测、不改写会话 ID。Servlet session 是服务端状态，
  本地造的串只会被当无效会话。
- **过期后**：873 → 标记 `auth_expired` 并停止；重建 = 人工登录 → 扩展导出 →
  `import_cookie_export.py --merge --label ...` → `--verify-session` 确认。

## 9. 消息通知

配置里填了 `notify_targets` 才启用；通道可选：

| 通道 | 需要的配置 | 载荷 |
|---|---|---|
| `telegram` | `telegram_bot_token` + `telegram_chat_id` | Bot API `sendMessage` |
| `feishu` | `feishu_webhook` | 自定义机器人 text |
| `dingtalk` | `dingtalk_webhook`（+ 可选 `dingtalk_secret` 加签） | text + HMAC-SHA256 签名 |
| `serverchan` | `serverchan_send_key` | Server酱 `SCTxxx.send` 表单 |
| `email` | `email_smtp_host`（可带端口）+ 收件人 `notify_to_mails`，鉴权用 `email_user`/`email_password` | 标准库 `smtplib`，465 SSL 或 587 STARTTLS |
| `resend` | `resend_api_key` + `resend_from`（已验证域名下的地址）+ 收件人 `notify_to_mails` | `POST https://api.resend.com/emails` + `Bearer`，body `{from,to,subject,text}`，响应含 `id` 才算受理 |
| `webhook` | `notify_webhook_url` | 通用 `POST {event, title, text}` |

邮件通道举例（QQ/163 用授权码而不是登录密码）：

```json
{
  "notify_targets": ["email"],
  "email_smtp_host": "smtp.qq.com:465",
  "email_use_ssl": true,
  "email_user": "你的邮箱@qq.com",
  "email_password": "邮箱授权码",
  "email_from": "你的邮箱@qq.com",
  "notify_to_mails": ["you@example.com"]
}
```

### 9.1 什么时候发（`notify_events` 过滤）

默认发这四类，其他一律不打扰：

| 事件 | 触发点 | 内容 |
|---|---|---|
| `result` | `--loop` 收尾、单次执行结束 | 汇总一条：状态分布 + 每账号全部券与状态 + 波次/请求数 + 事件明细路径 |
| `account_result` | 同上，**每个账号一条** | 该账号的领取详情：每张券的状态、发送时刻、耗时、服务端最终状态、失败原因；收件人与通道优先用该账号条目里的 `notify` / `notify_mail` |
| `auth_expired` | 报告里出现 873 | 哪些账号会话失效，以及「重新登录 → 导出 → `--merge` → `--verify-session`」的恢复步骤 |
| `health` | `--ping` / `--verify-session` **有异常账号时** | 异常账号与状态；全部正常时不打扰 |

一次运行会发 `1 + 账号数` 封（1 封汇总 + 每账号 1 封详情）；嫌逐条太吵就把
`account_result` 从 `notify_events` 去掉，只留汇总那条。
`send_ts`/耗时来自 JSONL 同源的事件表，同一张券多次尝试时取最后一次的时刻。

### 9.2 富文本报告页

邮件类通道（`email` / `resend`）会用 `meituan/report_html.py` 生成 HTML 报告页
（`notify_html=false` 时只发纯文本）：

- **账号详情页**（`render_account`）：双券卡版式，两张都到手则两张都亮、横幅「恭喜您 抢到券了！」；
  任一边没抢到则该卡变灰、中间裂一条缝（纯表格拼的锯齿，邮件端可画）；
  超过两张的券补一张「其他券」表。状态全部在生成时烘进 HTML。
- **汇总页**（`render_summary`）：状态分布 + 每个账号下的**全部**券与状态、领到张数。
  汇总页不再截断成两张卡，超过两张的券也会列出来。
- 三条边界：自包含（无外链/图片/脚本）、动态文本一律先脱敏再 `html.escape`
  （券名与 `detail` 都来自远端响应，不能当标记解释）、不含任何凭据值。

```bash
meituan --notify-test      # 全成功退出码 0
```

自检按通道强制发测试消息（绕过 `notify_events` 过滤）：全局通道发一条，
每个带 `notify` / `notify_mail` 的账号**按自己的路由各发一条**。

### 9.3 通知的三条边界

- **旁路失败不影响抢券**：任何通道异常都被吞掉，只在 stderr 记一行
  `通知[result] telegram: 失败 ...`；HTTP 200 但业务失败（`ok:false` /
  `errcode!=0` / `code!=0`）也会判失败，不会把没送达当成功。
- **通知凭据同等保密**：bot token、webhook URL（含 query 里的 token）、sendkey、
  加签 secret、SMTP 密码一律登记进脱敏表，日志与异常里只会出现 `***`。
- **默认掩码账号标识**：`notify_mask_labels=true` 时把 label 里的长数字
  （多为手机号）掩成 `177****89` 再推给第三方；`email_subject_prefix` 只作用于邮件标题。

## 10. 配置

优先级：`Config` 默认值 < `claim.config.json` < `MEITUAN_<字段名大写>` 环境变量 < CLI。

```bash
meituan --config /path/to/claim.config.json      # 指定配置文件
MEITUAN_LOOP_MINUTES=5 meituan --loop --fire-at 10:00:00
```

- 配置文件键名必须是 `Config` 字段名（未知键直接报错，防手滑拼错）；
  下划线开头的键视为注释忽略；JSON 数组会自动转成 tuple 字段。
- 环境变量只能表达标量；`MEITUAN_FIXED_COUPONS` 这类嵌套结构会被明确拒绝并提示改配置文件。
  （`CHAGEE_` 旧前缀已移除，只认 `MEITUAN_`。）
- **通知凭据别提交**：`claim.config.json` 已 gitignore，也可以用环境变量注入，例如
  `MEITUAN_EMAIL_PASSWORD`。两者都会被登记进脱敏表。
- 完整可调项见 `claim.config.example.json`（复制为 `claim.config.json` 生效），
  字段真源见 `meituan/config.py`。

字段分组速查：业务目标（`brand_keyword` / `fixed_brand_id` / `fixed_coupons` /
`snipe_keyword` / `single_run_snipe_only` / `skip_types` / `soldout_stop_after`）、
节奏与抢券（见 6.2）、超时与网络、文件与凭据（`auth_files` / `session_cookie_names` /
`persist_rotated_cookies` / `keepalive_log` / `run_log_dir`）、消息通知（见第 9 节）、
运行参数（`loop_minutes` / `loop_interval` / `fire_at` / `fire_lead` /
`adaptive_lead` / `early_stop_all_soldout` / `burst_test`）。

## 11. 保活与调度

会话靠「被访问」续命，定时打一次只读请求即可延长有效期，同时给服务端一次换发
JSESSIONID 的机会（本项目会自动跟随回写）。

```cron
# 每 10 分钟只读探活；退出码 1 = 失效或网络异常，可接告警
*/10 * * * * cd /path/to/meituan && python3 claim.py --ping >> keepalive.cron.log 2>&1 || notify-send "美团 会话异常"
```

想连登录态一起确认，把 `--ping` 换成 `--verify-session`。Windows 用「任务计划程序」，
操作填 `C:/.../meituan/.venv/Scripts/python.exe C:/.../meituan/claim.py --ping`。
间隔务必小于服务端 session 空闲超时。

配好通知通道后就不用自己写告警脚本了：`--ping`/`--verify-session` 发现有异常账号
会直接推 `health` 事件（全部正常时不发），cron 行里的 `|| notify-send` 可以省掉。

## 12. 故障排查

| 现象 | 原因与处理 |
|---|---|
| `没有任何账号 Cookie 文件（...）` | 认证文件不在**项目根目录**，或 `auth_files` 名字写错 |
| `cookies.json[1] 缺少字段: GOD_UUID` | 数组里第 2 条凭据不全，重新导出（值不会被打印） |
| `认证文件不是合法 JSON: ...（第 N 行第 M 列）` | 手工编辑漏了逗号/引号 |
| 配置里写的账号没跑，却没报错 | 看 stderr 的「已跳过」警告：只有配置显式写了却不存在的文件才警告，默认清单里的可选项缺失是静默的 |
| `--fire-at` 报 `格式应为 HH:MM[:SS[.毫秒]]` | 例 `10:00`、`10:00:00`、`23:59:59.700` 合法；`25:00` 越界 |
| 第一波就 `rate_limited` | 高频跨波才会撞 40007；确认没开 `MEITUAN_BURST_TEST`，必要时降 `first_wave_inflight` |
| 一直 `out_of_stock` | 库存真的为空是常态；连击 3 次自动停，可增大 `soldout_stop_after` 延长追抢 |
| `抢券目标为空（关键词 '5折' 未匹配...）` | `snipe_keyword` / `fixed_coupons` 改坏了，启动即失败而不是空转到超时 |
| Windows 中文日志乱码 | 控制台是 GBK，设 `PYTHONIOENCODING=utf-8`；日志文件本身是 UTF-8 |
| zoneinfo 报找不到 `Asia/Shanghai`（Windows） | 缺 `tzdata` 包：`pip install -r requirements.txt` |
| 收尾 `[x] 收尾校验失败` | 报告仍给出领取尝试结果，只是缺 `grant_status`；多为收尾时刻网络抖动 |
| 一条通知都没发 | `notify_targets` 为空即整体禁用；或事件不在 `notify_events` 里；或用了 `--no-notify` |
| `通知[x] email: 失败 ...` | QQ/163 要用**授权码**而不是登录密码；465 走 `email_use_ssl`、587 走 `email_use_tls` |
| `通知[x] dingtalk: 失败 通道返回失败 errcode=310000` | 钉钉机器人安全设置不匹配（加签没填 `dingtalk_secret`，或关键词/IP 段受限） |
| `通知[x] resend: 失败 HTTP 4xx` | `resend_api_key` 无效，或 `resend_from` 所在域名未验证/未配 DKIM+SPF |

## 13. 项目结构与模块职责

```
claim.py                  薄启动器（用法摘要）
pyproject.toml            包元数据 / 依赖 / console_scripts（meituan = meituan.cli:main）
cookies.example.json      认证文件模板（照抄为 cookies.json）
claim.config.example.json 配置模板（照抄为 claim.config.json）
meituan/
  __init__.py             模块地图 + __version__
  cli.py                  参数解析、配置装配、账号筛选、分发、退出码
  config.py               Config dataclass + 四层配置合并
  security.py             凭据加载与归一化（单对象/数组）、按条目回写、脱敏登记
  errors.py               ApiError / ApiTransportError / ApiParseError + 业务码映射
  cookies.py              CookieStore：Cookie 头唯一出口 + 跟踪名单 + 线程安全
  models.py               Coupon / GrantEvent（API 边界即转模型，raw 透传）
  api_client.py           签名、POST、错误分层、JSESSIONID 跟随
  pacing.py               RateLimiter + InflightGate（容量可运行时调整）
  notify.py               Notifier：7 通道 + 账号级路由
  report_html.py          邮件报告页：账号详情双券卡 + 汇总页全部券列表
  flows.py                RunLogger、ping / verify_session / single_run / LoopRunner
tools/import_cookie_export.py   扩展导出 -> 认证文件（支持并入数组）
tests/                    267 个 unittest（全部 mock）
.github/workflows/ci.yml  多版本 Python 测试 + compileall + 凭据入库守卫
```

## 14. 开发与测试

```bash
python -m unittest discover -s tests -t . -v      # 全套测试
python -m compileall -q meituan tests tools claim.py
```

CI 在 `ubuntu-latest` 上跑 Python 3.9 / 3.11 / 3.13 三版本：装依赖 → 凭据入库守卫 →
`compileall` → 全套 mock 测试。测试一律 mock，禁止访问真实第三方接口。

代码不变量（改动时请保持）：

1. 业务层不直接碰 `requests`，一切经 `ApiClient`；错误按结构化 `code` 分类，不猜字符串。
2. 任何输出（stdout/stderr/日志/异常 detail）先过 `redact()`；凭据只报字段名。
3. 运行期可变状态挂在实例上（LoopRunner / GrantPacing / CookieStore），不用模块级全局。
4. 服务端 `Set-Cookie` 只能改跟踪名单内的字段；session ID 只跟随不生成。
5. 多账号单文件的回写必须按条目更新，不得整体覆盖。
6. 测试一律 mock，禁止访问真实第三方接口。
7. 节奏参数以实测为依据，调整前先拿 JSONL 事件数据说话。
8. 通知是**旁路**：任何通道异常都不许冒泡影响抢券主流程；通知凭据与业务凭据同等脱敏；
   「HTTP 200 但业务失败」必须判为失败。

## 15. 已知限制

- 单次执行的 `grant_status` 取的是**领取前**查询到的状态，不是领取后复核（`--loop` 会复核）。
- loop 的 `deadline` 只约束「是否提交下一波」，不取消已提交任务，也不含开火等待、线程池收尾、
  收尾复核与通知耗时，不是进程级硬超时。
- `--notify-test` 与真实投递都不能证明各邮箱客户端的最终渲染效果。
- 凭据回写有跨进程锁（旁路锁文件 `<认证文件>.lock`，10 秒超时），两个实例同时跑时
  可能有一方拿不到锁而放弃这次回写（不会与对方交叉覆盖）；调度上仍建议保证同一时刻
  只有一个实例在跑。

## 16. 版本与演进

`1.21.0` 稳定性与正确性修补：HTML 报告页与纯文本同一口径脱敏（`_safe_items` /
`_safe_lines`，堵住上游回显凭据时随邮件外泄）；账号详情页 >2 张券时丢券/重复与
横幅误报祝贺（`_ordered` 统一卡片位与溢出顺序，headline 按全部券统计）；传输/解析失败
改记 `error` 并进入退出码判定（不再把网络故障当「正常没抢到」）；`GrantPacing.slot`
改为「先取并发容量、再卡间隔」，修复闸门放开瞬间多请求挤在一起发出；凭据回写增加
跨进程旁路锁 `<认证文件>.lock`（Windows 共享冲突重试）；导入工具改为先在中转文件上
校验、通过才落盘，不再先覆盖再删除。`.gitignore` 补 `*.lock` 等。
`1.20.0` chagee 全量改名为 meituan：移除 `CHAGEE_` 旧环境变量前缀，只保留 `MEITUAN_`；
新增 `adaptive_lead`（预热 RTT 自适应开火提前量）、`early_stop_all_soldout`（首波全抢光
确认一波后提前收工）、`wait_until` 跨零点保护、预热并行化；新增 `cookies.example.json`。
`1.19.0` 新增 `single_run_snipe_only`（单次执行只处理目标券）、汇总页改为按账号列出全部券与状态、
账号 label 优先取自 cookie 里的手机号。
`1.18.0` 项目主体改为美团，接入 `resend` 通知通道。
`1.17.0` 新增 `resend` 通道，收件人字段统一为 `notify_to_mails`。
`1.16.0` 账号级通知路由与 `--notify-test` 自检。
`1.15.0~1.10.0` 多账号单文件与按条目回写、自适应并发、`send_ts` 精度、`--fire-lead`。
更早版本见 `git log`。

## 17. 边界与免责

- 只在**你自己的账号**上使用，并遵守网易大神的服务条款与频率约束；节奏参数刻意保守
  （单波 4~6 请求、命中限流退避 60s），不要改成高频压测形态。
- 不绕过登录、不伪造会话、不提取他人凭据；`--verify-session` 有真实领取副作用，
  help 与文档已明示。
- 接口是逆向复刻的私有接口，随时可能变更；签名或字段漂移时先看 `--ping` 是否 `reachable`，
  再对比页面请求头。
- 开启通知会把「哪些账号、领到了什么、什么时候」推给第三方服务。默认已掩掉 label 中的
  手机号等长数字；若你希望连账号标识也不外泄，用「老号/小号」这类中性 label
  （`notify_mask_labels` 只影响通知，不影响本地日志与报告）。
