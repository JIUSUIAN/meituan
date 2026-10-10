# 网易大神 · 霸王茶姬优惠券自动领取（chagee）

直调接口领取「大神会员 partner-perks」页面的霸王茶姬超级券：复刻页面的请求签名，
多账号并发、整点定时开抢、限流退避、会话凭据自动跟随，并把结果输出成可管道解析的 JSON。

- 语言/依赖：Python ≥ 3.9，`requests`（Windows 另需 `tzdata`；邮件走标准库 `smtplib`）
- 版本：`1.13.0`（真源 `chagee/__init__.py:__version__`）
- 测试：201 个，全部 mock，不访问真实第三方接口（通知通道用假 session / 假 SMTP）
- 节奏与参数以**实测成功日志**为准（2026-10-09 23:59 那次整点抢：4 张券全中、响应 1.78~3.17s）

---

## 1. 工作原理

页面 JS 用 axios 带一组 `GL-*` 头访问接口，本项目在 `chagee/api_client.py` 里等价复刻：

| 接口 | 方法/体 | 用途 |
|---|---|---|
| `/v1/web/exp-vip/external/super-coupon/info` | `POST {}` | 券列表（**不校验登录**，只用于取阵容和探活） |
| `/v1/web/exp-vip/external/super-coupon/grant` | `POST {brandId, superCouponId[, phoneBizType:"VIP"]}` | 领取（有业务副作用） |
| `/v1/web/exp-vip/external/super-coupon/grant-status` | `POST {superCouponIds:[...]}` | 查询已领状态（只读，可证明登录态） |

签名与身份：

```
GL-CheckSum    = SHA1( JSON.stringify(body) + GL-XSRF-TOKEN 的 cookie 值 )
GL-X-XSRF-TOKEN= GL-XSRF-TOKEN      GL-Uid = GOD_UUID cookie
GL-DeviceId    = localStorage 的 ds-website-uuid      GL-ClientType: 60
```

`JSON.stringify` 的对齐是关键：body 由代码手工序列化（`separators=(",", ":")`、
`ensure_ascii=False`、按插入顺序），**签名用的字节与实际发送的字节完全一致**，
否则校验失败。Cookie 头由 `CookieStore` 单点合成，且保证签名用的
`GL-XSRF-TOKEN` 与头部同值（顶层鉴权字段为权威，防止漂移）。

---

## 2. 安装

```bash
cd meituan
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e .                                  # 或 pip install -r requirements.txt
```

三种等价入口：`chagee ...`（控制台脚本）、`python claim.py ...`、`python -m chagee.cli ...`。

---

## 3. 凭据准备

凭据文件放在**项目根目录**（`chagee/` 的上一级），文件名由 `auth_files` 配置，
默认 `("cookies.json", "cookies-new.json")`——存在哪个就用哪个，都不存在则报错退出。

### 3.1 单账号（对象格式）

```json
{
  "label": "老号",
  "GL-XSRF-TOKEN": "...",
  "GOD_UUID": "...",
  "device_id": "...",
  "cookies": { "JSESSIONID": "..." }
}
```

### 3.2 多账号（一个文件放账号数组，推荐）

```json
[
  { "label": "老号", "GL-XSRF-TOKEN": "...", "GOD_UUID": "...",
    "device_id": "...", "cookies": { "JSESSIONID": "..." } },
  { "label": "小号", "...": "..." }
]
```

加载规则（`security.load_auths`）：

- 顶层是对象 = 一个账号；是数组 = 多个账号，逐条独立校验。
- 三条鉴权字段可省略，会从 `cookies` 反推（`device_id` 兼容 `ds-website-uuid`
  cookie）；`cookies` 也支持浏览器扩展导出的数组形态 `[{name, value}, ...]`。
- `label` 缺失时用 `文件名#序号`；**重复的 label 一律加序号去重**——label 是
  客户端字典、退避表与报告的键，重复会静默顶掉账号。
- 缺必填字段只报**文件名 + 条目下标 + 字段名**，绝不输出任何凭据值。
- POSIX 下文件权限对组/其他用户可读会打一条警告；Windows 依赖目录 NTFS ACL。

### 3.3 从浏览器导出（JSESSIONID 是 HttpOnly）

页面 JS / 书签栏脚本读不到 HttpOnly 的 JSESSIONID，**只能用浏览器扩展**
（Cookie-Editor、EditThisCookie 等）导出，再用工具转换：

```bash
# 整体写成单对象文件
python tools/import_cookie_export.py export.json --domain 163.com -o cookies-new.json

# 并入已有的多账号数组文件：同 label 替换该条，否则追加，其他账号原样不动
python tools/import_cookie_export.py export.json --domain 163.com \
    --merge --label 小号 -o cookies.json
```

工具只做格式转换与完整性校验（校验不过会回滚，不毁掉同文件其他账号），
**不生成、不猜测任何凭据值**。

### 3.4 安全红线（代码强制）

- `GL-XSRF-TOKEN` / `GOD_UUID` / `device_id` / 所有 cookie 值：登记进脱敏表，
  日志、异常信息、stdout 报告输出前统一 `redact()`；另有 `KEY=value` 形态兜底正则。
- `cookies*.json`、`*.log`、`*.jsonl`、`*.tmp` 全部 gitignore；CI 有「凭据入库守卫」，
  检测到 `cookies*.json` 被跟踪就直接失败。凭据一旦入库按已泄露处理，重新获取。
- 会话 ID 只跟随服务端下发，绝不本地生成/伪造。
- HTTP 错误正文截断 200 字符并脱敏后才进异常对象。

---

## 4. 命令与四种运行模式

```bash
chagee                              # 单次执行（默认）
chagee --loop [--minutes 10] [--interval 2.0]
chagee --loop --fire-at 23:59:59.70 --fire-lead 0.3
chagee --ping                       # 只读健康检查
chagee --verify-session             # 会话验证（有副作用）
chagee --loop --accounts 小号        # 只跑指定账号（label 或文件名，逗号分隔）
chagee --loop 2>/dev/null > result.json   # stdout 只有 JSON，日志在 stderr
```

| 模式 | 做什么 | 副作用 | 报告状态 | 退出码 |
|---|---|---|---|---|
| 单次（默认） | 拉列表 → 查已领状态 → **逐张尝试所有可领券** | 会真领 | 每账号一组 `{coupon, status, detail}` | 任一账号执行异常 → 1 |
| `--loop` | 只抢目标券（默认两张 5 折），波次重试直到全有结论或超时 | 会真领 | 同上 + `grant_status` | 任一 `auth_expired`/`error` → 1 |
| `--ping` | 只调 info + grant-status 两个只读接口 | 无 | `reachable` / `expired` / `unknown` / `error: ...` | 任一 `expired`/`error` → 1 |
| `--verify-session` | 用探针券试领一次，证明登录态 | **有**（当天探针券未领会领掉一张） | `authenticated` / `expired` / `unknown` / `error: ...` | 有任一非 `authenticated` → 1 |

- `--ping` 与 `--verify-session` 互斥。
- 只读接口不校验登录，所以 `--ping` **不会**谎报 `authenticated`；想确认登录态用
  `--verify-session`（已领过返回 803 仍判 `authenticated`，幂等）。
- 单次模式与 loop 的目标不同：单次覆盖品牌下全部可领券（不怕阵容变化），
  loop 只打 `snipe_keyword` 命中的券，把第一波火力留给目标。

---

## 5. 抢券行为细节（`--loop`）

### 5.1 时间线

1. 装配：每账号一个 `ApiClient`（独立 CookieStore + 连接级重试）+ 一套节奏控制器；
   目标券直接来自配置（**不等列表，第一波零延迟**）。
2. 时钟校验：Linux 查 `timedatectl`（空输出会附带 rc/stderr 便于诊断），其他平台记「跳过」。
3. 预热（仅指定 `--fire-at` 时）：每账号打一次只读请求，把 TCP+TLS 握手做完。
4. 精确等待：`sleep` 到只剩 5ms，最后用 `perf_counter` 单调钟忙等（Windows 上
   `time.time` 分辨率约 15ms，会整体偏移）。
5. 波次循环（deadline = `minutes`）：
   - 第一波结束后、以及每 `refresh_every` 秒，提交一次列表刷新，**只增量合并**
     新出现的 `snipe_keyword` 券，不删已有目标；
   - 每波任务 = 各账号未 settled 的目标券，优先券排前；
   - 第一波打完自动切「安全模式」（`sustained_gap` / `sustained_inflight`），
     压测时 `CHAGEE_BURST_TEST=1` 跳过切换；
   - 所有目标都有结论 → 提前结束；否则 sleep `interval` 进下一波。
6. 收尾：统计 → 事件明细落 JSONL → 用 `grant-status` 再核一次真实领取状态 → 输出报告。

### 5.2 节奏参数（实测值，改前先看 JSONL 数据）

| 参数 | 默认 | 说明 |
|---|---|---|
| `first_wave_gap` | 0.05s | 第一波任意两次 grant 的最小间隔 |
| `first_wave_inflight` | 6 | 第一波同时在飞上限（账号数 × 2 张券；实测 2 账号 4、3 账号 6 都不触发 40007） |
| `sustained_gap` / `sustained_inflight` | 0.5s / 2 | 后续波次安全模式 |
| `rate_limit_backoff` | 60s | 命中 40007 后该账号退避 |
| `soldout_stop_after` | 3 | 同一张券连续 60001 达到次数即停 |
| `refresh_every` | 30s | 抢券期间列表刷新间隔 |
| `fire_lead` | 0.0 | 开火提前量（整点抢建议 0.3，补偿 1.8~3.2s 的首波响应） |
| `api_timeout` / `refresh_timeout` / `ping_timeout` | 20 / 8 / 15 | 超时按用途分档，抢券期间快速失败 |

线程池规模 = `账号数 × (目标券数 + 1) + 1`（2 账号 → 7，3 账号 → 10）；
真正的领取并发由「限速器 + 在飞闸门」双重限制，与线程数无关。

### 5.3 单张券的状态机

| 业务码 | 领域状态 | 之后怎么做 |
|---|---|---|
| 200 | `granted` | 该券收工 |
| 803 | `already_claimed` | 收工 |
| 40007 | `rate_limited` | 该账号退避 60s，保留重试 |
| 873 | `auth_expired` | **停止重试**（重试无意义），报告里标出 |
| 60001 | `out_of_stock` | 连击计数，达 `soldout_stop_after` 才停 |
| 其他码 | `failed`（detail 保留原码） | 保留重试；文案命中「不存在/已下架/已失效」才停 |

未知业务码一律记 `failed` 并保留原码，**不做字符串猜测、不误分类**。
本地预检：`leftStock == 0` → `out_of_stock`（未知按未抢光，与历史行为一致）；
`PLACEHOLDER` → `skipped`；`DIRECT_LINK` → `direct_link`。

`send_ts`（实际发出 POST 的时刻，百分之一秒）在限速等待与在飞闸门都等到之后才采集，
收尾统计里的「第一波发送时刻」因此能真正反映错峰效果。

---

## 6. 输出

### 6.1 stdout（可管道解析）

```json
{
  "老号": [
    {"coupon": "【5折外卖券】立减20", "status": "granted",
     "detail": "{'winPrizeInfo': {...}}", "grant_status": "GRANTED"},
    {"coupon": "【5折外卖券】立减25", "status": "out_of_stock",
     "detail": "code=60001: 已抢光"}
  ],
  "小号": [ ... ]
}
```

`grant_status` 来自收尾的 `grant-status` 复核，是服务端记录的最终事实；
`detail` 一律脱敏且限长 200。日志、进度、警告全部走 stderr。

### 6.2 文件产物

| 文件 | 位置 | 内容 |
|---|---|---|
| 运行日志 | `run_log_dir/claim-<时间>.log`、`claim-single-<时间>.log` | 与 stderr 同源（UTF-8） |
| 事件明细 | 同目录同名 `.jsonl` | 每次 grant 一行：`send_ts / label / coupon_name / status / elapsed`，无凭据 |
| 保活日志 | `keepalive_log` | `--ping`/`--verify-session` 每账号一行 |

默认 `run_log_dir` / `keepalive_log` 指向 `~/workspace/goals/goal/hidden_files`，
用 `CHAGEE_RUN_LOG_DIR`、`CHAGEE_KEEPALIVE_LOG` 或配置文件改。

复盘建议：`jsonl` 里能算出第一波实际错峰间隔与耗时分布，是调参的唯一依据。

---

## 7. 会话与 JSESSIONID

实测确认 JSESSIONID 是大神登录态载体，因此内置「跟随层」：

- **能做的**：任意响应（含 4xx/5xx 与业务错误）的 `Set-Cookie` 里出现跟踪名单内的
  名字且值变化 → 更新内存 → 登记脱敏 → **按条目原子回写认证文件**（数组文件只动
  自己那条，读-改-写持锁）→ 触发 `on_rotate` 回调（只传 cookie 名，不传值）。
  `single_run` 与 `--loop` 会为此记一行日志；`--ping`/`--verify-session` 目前
  同样跟随并回写，但不传回调，因此**不留日志**。
- **名单可配**：`session_cookie_names`（默认 `("JSESSIONID",)`）；名单外的字段
  不接受服务端改写，`GL-XSRF-TOKEN` 等签名依赖字段由本地掌控。
  `persist_rotated_cookies=False` 可关回写（仅内存跟随）。
- **不做的**：不生成、不猜测、不改写会话 ID。Servlet session 是服务端状态，
  本地造的串只会被当无效会话。
- **过期后**：873 → 标记 `auth_expired` 并停止；重建 = 人工登录 → 扩展导出 →
  `import_cookie_export.py --merge --label ...` → `--verify-session` 确认。

---

## 8. 消息通知

配置里填了 `notify_targets` 才启用；通道可选：

| 通道 | 需要的配置 | 载荷 |
|---|---|---|
| `telegram` | `telegram_bot_token` + `telegram_chat_id` | Bot API `sendMessage` |
| `feishu` | `feishu_webhook` | 自定义机器人 text |
| `dingtalk` | `dingtalk_webhook`（+ 可选 `dingtalk_secret` 加签） | text + HMAC-SHA256 签名 |
| `serverchan` | `serverchan_send_key` | Server酱 `SCTxxx.send` 表单 |
| `email` | `email_smtp_host`（可带端口）+ `email_to`，鉴权用 `email_user`/`email_password` | 标准库 `smtplib`，465 SSL 或 587 STARTTLS |
| `temp_email` | `temp_email_api_url` + `temp_email_to_mails` + 鉴权二选一（`temp_email_admin_auth` / `temp_email_jwt`），管理员模式另需 `temp_email_from_mail` | 自建 [cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email)：`POST /admin/send_mail`（`x-admin-auth` 头）或 `POST /api/send_mail`（`Bearer JWT`） |
| `webhook` | `notify_webhook_url` | 通用 `POST {event, title, text}` |

自建 [cloudflare_temp_email](https://github.com/dreamhunter2333/cloudflare_temp_email)
的接法（它跑在 Cloudflare Workers 上，收信靠 Email Routing，发信需要为该域名开启
Email Sending 绑定）：

```json
{
  "notify_targets": ["temp_email"],
  "temp_email_api_url": "https://temp-mail.你的域名.com",
  "temp_email_admin_auth": "管理密码（后台设置里的那个）",
  "temp_email_from_mail": "notice@你的域名.com",
  "temp_email_to_mails": ["you@example.com"]
}
```

`temp_email_from_mail` 必须是该服务里已存在的地址；若不想用管理密码，就把该地址
登录得到的 JWT 填进 `temp_email_jwt`（走 `/api/send_mail`，发件人即该地址，
不需要 `from_mail`）。多个收件人逐个发。`is_html` 固定 false，正文是纯文本。

配好后先自检连通与送达：

```bash
chagee --notify-test      # 先 GET /health_check，再按通道发一条测试消息
```

```json
{
  "notify_targets": ["telegram", "feishu"],
  "notify_events": ["result", "account_result", "auth_expired", "health"],
  "notify_mask_labels": true,
  "telegram_bot_token": "123456789:AA...",
  "telegram_chat_id": "我的 chat id",
  "feishu_webhook": "https://open.feishu.cn/open-apis/bot/v2/hook/..."
}
```

**什么时候发**（`notify_events` 过滤，默认发这四类，其他一律不打扰）：

| 事件 | 触发点 | 内容 |
|---|---|---|
| `result` | `--loop` 收尾、单次执行结束 | 汇总一条：状态分布 + 每账号结果 + 波次/请求数 + 事件明细路径 |
| `account_result` | 同上，**每个账号一条** | 该账号的领取详情：每张券一行（券名、状态、发送时刻、耗时、服务端最终状态、失败原因） |
| `auth_expired` | 报告里出现 873 | 哪些账号会话失效，以及「重新登录 → 导出 → `--merge` → `--verify-session`」的恢复步骤 |
| `health` | `--ping` / `--verify-session` **有异常账号时** | 异常账号与状态；全部正常时不打扰 |

单账号详情条的实样（三账号就是三条，外加一条汇总）：

```
CHAGEE 账号领取详情
177****89
【5折外卖券】立减20: granted（发送 23:59:59.70，耗时 1.78s） 服务端 GRANTED
【5折外卖券】立减25: out_of_stock | code=60001: 已抢光
```

嫌逐条太吵就把 `account_result` 从 `notify_events` 去掉，只留汇总那条；
`send_ts`/耗时来自 JSONL 同源的事件表，同一张券多次尝试时取最后一次的时刻。

三条实现边界：

- **旁路失败不影响抢券**：任何通道异常都被吞掉，只在 stderr 记一行
  `通知[result] telegram: 失败 ...`；HTTP 200 但业务失败（`ok:false` /
  `errcode!=0` / `code!=0`）也会判失败，不会把没送达当成功。
- **通知凭据同等保密**：bot token、webhook URL（含 query 里的 token）、sendkey、
  加签 secret、SMTP 密码一律登记进脱敏表，日志与异常里只会出现 `***`。
- **默认掩码账号标识**：`notify_mask_labels=true` 时把 label 里的长数字
  （多为手机号）掩成 `177****89` 再推给第三方；`email_subject_prefix` 只作用于邮件标题。

```bash
chagee --loop --no-notify      # 本次运行不推送（cron 调试用）
chagee --ping --notify         # 强制打开（仍要求配置了通道）
CHAGEE_NOTIFY_TARGETS=telegram,feishu chagee --loop
```

测试时可以自问一句「真发出去了吗」：模块用假 session / 假 SMTP 覆盖了每个通道的
URL 与载荷形状，`Notifier.targets` 为空时 `enabled=False`，一次网络调用都不会发生。

---

## 9. 配置

优先级：`Config` 默认值 < `claim.config.json` < `CHAGEE_<字段名大写>` 环境变量 < CLI。

```bash
chagee --config /path/to/claim.config.json      # 指定配置文件
CHAGEE_LOOP_MINUTES=5 CHAGEE_FIRE_LEAD=0.3 chagee --loop --fire-at 10:00:00
```

- 配置文件键名必须是 `Config` 字段名，未知键直接报错（防手滑拼错）；
  下划线开头的键视为注释忽略；JSON 数组会自动转成 tuple 字段。
- 环境变量只能表达标量；`CHAGEE_FIXED_COUPONS` 这类嵌套结构会被明确拒绝并提示改配置文件。
- **通知凭据别提交**：`claim.config.json` 里写 token 会被 gitignore 之外的方式泄露，
  推荐用环境变量注入：`CHAGEE_NOTIFY_TARGETS=telegram`、
  `CHAGEE_TELEGRAM_BOT_TOKEN=...`、`CHAGEE_EMAIL_PASSWORD=...`（`email_to` 是 tuple，
  可用逗号分隔一次给多个收件人）。
- 完整可调项见 `claim.config.example.json`（复制为 `claim.config.json` 生效），
  字段真源见 `chagee/config.py`。

---

## 10. 保活与调度

会话靠「被访问」续命，定时打一次只读请求即可延长有效期，同时给服务端一次换发
JSESSIONID 的机会（本项目会自动跟随回写）。

```cron
# 每 10 分钟只读探活；退出码 1 = 失效或网络异常，可接告警
*/10 * * * * cd /path/to/meituan && python3 claim.py --ping >> keepalive.cron.log 2>&1 || notify-send "CHAGEE 会话异常"
```

想连登录态一起确认，把 `--ping` 换成 `--verify-session`。Windows 用「任务计划程序」，
操作填 `C:\...\meituan\.venv\Scripts\chagee.exe --ping`。间隔务必小于服务端 session
空闲超时。

配好通知通道后就不用自己写告警脚本了：`--ping`/`--verify-session` 发现有异常账号
会直接推 `health` 事件（全部正常时不发），cron 行里的 `|| notify-send` 可以省掉。

---

## 11. 故障排查

| 现象 | 原因与处理 |
|---|---|
| `没有任何账号 Cookie 文件（...）` | 认证文件不在**项目根目录**，或 `auth_files` 名字写错 |
| `cookies.json[1] 缺少字段: GOD_UUID` | 数组里第 2 条凭据不全，重新导出（值不会被打印） |
| `认证文件不是合法 JSON: ...（第 N 行第 M 列）` | 手工编辑漏了逗号/引号 |
| 配置里写的账号没跑，却没报错 | 看 stderr 的「已跳过」警告：只有配置显式写了却不存在的文件才警告，默认清单里的可选项缺失是静默的 |
| `--fire-at` 报 `格式应为 HH:MM[:SS[.毫秒]]` | 例：`10:00`、`10:00:00`、`23:59:59.700` 合法；`25:00` 越界 |
| 第一波就 `rate_limited` | 高频跨波才会撞 40007；确认没开 `CHAGEE_BURST_TEST`，必要时降 `first_wave_inflight` |
| 一直 `out_of_stock` | 库存真的为空是常态；连击 3 次自动停，可增大 `soldout_stop_after` 延长追抢 |
| `抢券目标为空（关键词 '5折' 未匹配...）` | `snipe_keyword` / `fixed_coupons` 改坏了，启动即失败而不是空转到超时 |
| Windows 中文日志乱码 | 控制台是 GBK，设 `PYTHONIOENCODING=utf-8`；日志文件本身是 UTF-8 |
| zoneinfo 报找不到 `Asia/Shanghai`（Windows） | 缺 `tzdata` 包：`pip install -r requirements.txt` |
| 收尾 `[x] 收尾校验失败` | 报告仍给出领取尝试结果，只是缺 `grant_status`；多为收尾时刻网络抖动 |
| 一条通知都没发 | `notify_targets` 为空即整体禁用（`enabled=False`）；或事件不在 `notify_events` 里；或用了 `--no-notify` |
| `通知[x] telegram: 失败 缺少配置: telegram_chat_id` | 只报缺的字段名；把值补进配置或环境变量 |
| `通知[x] dingtalk: 失败 通道返回失败 errcode=310000` | 钉钉机器人安全设置不匹配（加签没填 `dingtalk_secret`，或关键词/IP 段受限） |
| `通知[x] email: 失败 ...` | QQ/163 要用**授权码**而不是登录密码；465 走 `email_use_ssl`、587 走 `email_use_tls` |
| `通知[x] temp_email: 失败 HTTP 400 ...` | 该域名没开 Email Sending 绑定、`temp_email_from_mail` 不是服务里已存在的地址，或管理密码错（先跑 `chagee --notify-test` 看 health_check） |
| `通知[x] temp_email: 失败 需要 temp_email_admin_auth 或 temp_email_jwt` | 两种鉴权都没填；填管理密码（配 `from_mail`）或地址 JWT（不配 `from_mail`） |

---

## 12. 开发

```
claim.py                 薄启动器（用法摘要）
pyproject.toml           包元数据 / 依赖 / console_scripts（chagee = chagee.cli:main）
chagee/
  cli.py                 参数解析、配置装配、账号筛选、分发、退出码
  config.py              Config dataclass + 四层配置合并
  security.py            凭据加载与归一化（单对象/数组）、按条目回写、脱敏登记
  errors.py              ApiError / ApiTransportError / ApiParseError + 业务码映射
  cookies.py             CookieStore：Cookie 头唯一出口 + 跟踪名单 + 线程安全
  models.py              Coupon / GrantEvent（API 边界即转模型，raw 透传）
  api_client.py          签名、POST、错误分层、JSESSIONID 跟随
  pacing.py              RateLimiter + InflightGate（容量可运行时调整）
  notify.py              Notifier：Telegram/飞书/钉钉/Server酱/邮件/通用 webhook
  flows.py               ping / verify_session / single_run / LoopRunner（步骤方法化）
tools/import_cookie_export.py  扩展导出 -> 认证文件（支持并入数组）
tests/                   201 个 unittest（全部 mock）
.github/workflows/ci.yml 多版本 Python 测试 + compileall + 凭据入库守卫
```

```bash
python -m unittest discover -s tests -t . -v      # 全套测试
python -m compileall -q chagee tests tools claim.py
```

代码不变量（改动时请保持）：

1. 业务层不直接碰 `requests`，一切经 `ApiClient`；错误按结构化 `code` 分类，不猜字符串。
2. 任何输出（stdout/stderr/日志/异常 detail）先过 `redact()`；凭据只报字段名。
3. 运行期可变状态挂在实例上（LoopRunner / GrantPacing / CookieStore），不用模块级全局。
4. 服务端 `Set-Cookie` 只能改跟踪名单内的字段；session ID 只跟随不生成。
5. 多账号单文件的回写必须按条目更新，不得整体覆盖。
6. 测试一律 mock，禁止访问真实第三方接口。
7. 节奏参数以实测为依据，调整前先拿 JSONL 事件数据说话。
8. 通知是**旁路**：任何通道异常都不许冒泡影响抢券主流程；通知凭据（token、
   webhook、sendkey、SMTP 密码）与业务凭据同等脱敏；「HTTP 200 但业务失败」
   必须判为失败。

---

## 13. 边界与免责

- 只在**你自己的账号**上使用，并遵守网易大神的服务条款与频率约束；节奏参数
  刻意保守（单波 4~6 请求、命中限流退避 60s），不要改成高频压测形态。
- 不绕过登录、不伪造会话、不提取他人凭据；`--verify-session` 有真实领取副作用，
  help 与文档已明示。
- 接口是逆向复刻的私有接口，随时可能变更；签名或字段漂移时先看 `--ping` 是否
  `reachable`，再对比页面请求头。
- 开启通知会把「哪些账号、领到了什么、什么时候」推给第三方服务。默认已掩掉
  label 中的手机号等长数字；若你希望连账号标识也不外泄，用「老号/小号」这类
  中性 label（`notify_mask_labels` 只影响通知，不影响本地日志与报告）。

## 14. 版本与演进

`1.13.0` 新增 `temp_email` 通道（自建 cloudflare_temp_email 发信：管理密码或地址 JWT
两种鉴权）与 `chagee --notify-test` 自检；
`1.12.0` 通知支持单账号领取详情逐条推送（`account_result` 事件，含发送时刻/耗时/服务端状态）；
`1.11.0` 消息通知模块（Telegram/飞书/钉钉/Server酱/邮件/通用 webhook）与四模式接入；
`1.10.0` 多账号单文件与按条目回写、自适应并发、`send_ts` 精度、`--fire-lead`；
`1.9.0` 凭据 `.tmp` 加固、退出码、CLI 前置校验、探针券单一真源、JSONL、pyproject+CI；
`1.8.0` 及更早：P0（脱敏/只读 ping/结构化错误）→ P1（模块拆分、消除全局状态、
LoopRunner、配置分层）→ P1.5~P1.8（JSESSIONID 跟随、运维收尾、领域模型、CookieStore）。
完整过程见 `git log`。
