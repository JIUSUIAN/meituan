# 美团外卖优惠券自动领取（Rust 版）

网易大神「大神会员 partner-perks」页面美团外卖券的自动领取工具：复刻页面 JS 的请求签名，
直调领券接口、跳过浏览器。支持多账号并发、整点定时开抢、限流退避、会话凭据自动跟随，
结果输出为可管道解析的 JSON，并可推送富文本报告邮件。

**本仓库当前在 `rust` 分支**：Python 原版保留在 `legacy-python/`（`main` 分支仍是 Python），
两者模块一一对应，便于逐文件对照。

| 项 | 值 |
|---|---|
| 版本 | `1.21.0`（真源 `Cargo.toml` 的 `version`） |
| 语言 / 工具链 | Rust ≥ 1.89（2021 edition） |
| 测试 | 60 项（54 单元 + 6 集成），全部只访问本地桩服务 |
| 代码质量 | `cargo fmt --check` 与 `cargo clippy --all-targets` 均零告警 |
| 当前活动商家 | 霸王茶姬（`brand_keyword`） |
| 抢券目标 | 两张 5 折外卖券（`snipe_keyword="5折"`） |

架构设计、模块划分、错误处理策略与依赖选型理由见 **[ARCHITECTURE.md](ARCHITECTURE.md)**。

---

## 1. 环境要求

- **Rust ≥ 1.89**：文件锁用 std 的 `File::try_lock`（1.89 起稳定），因此不再需要 `fs2` 之类的第三方锁库。
- 依赖全部是纯 Rust 或系统自带实现（TLS 走 `native-tls` → Windows SChannel / macOS Security.framework / Linux OpenSSL），
  **不需要额外的 C 编译器**——有一个例外见下。

### 1.1 Windows 上使用 `*-pc-windows-gnu` 工具链时

`windows-sys`（`native-tls` → SChannel 的传递依赖）在构建期要用 `dlltool` 生成导入库，
而 `dlltool` 又会调用汇编器 `as`。rustup 的 GNU 工具链自带 `dlltool` 但**不含 `as`**，
所以直接 `cargo build` 会报：

```
error: error calling dlltool 'dlltool.exe': program not found
```

三种解决办法，任选其一：

1. **换 MSVC 工具链**（推荐，装了 Visual Studio Build Tools 的话）：
   `rustup default stable-x86_64-pc-windows-msvc`
2. **给 GNU 工具链补一个 `as.exe`**：从 MSYS2 的 `mingw-w64-x86_64-binutils` 包里取出
   `mingw64/bin/as.exe`，放进 PATH 即可（本次开发就是这么做的）。
3. 使用已配置好的环境（见下文「构建」一节的 PATH 提示）。

macOS 与 Linux 没有这个问题。

---

## 2. 构建

```bash
cargo build --release
```

产物：`target/release/meituan`（Windows 为 `meituan.exe`）。

如果你在 Windows + GNU 工具链下构建，并且按上面第 2 条准备了 `as.exe`，需要把它加进 PATH：

```bash
export PATH="/path/to/mingw-binutils:$HOME/.rustup/toolchains/stable-x86_64-pc-windows-gnu/lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained:$HOME/.cargo/bin:$PATH"
cargo build --release
```

安装到 PATH（可选）：

```bash
cargo install --path .
```

---

## 3. 快速开始

```bash
cargo run -- --ping                              # 只读健康检查（cron 保活用）
cargo run -- --verify-session                    # 验证登录态（有副作用！）
cargo run -- --loop --fire-at 23:59:59.700       # 整点抢（自动算开火提前量）
cargo run -- --loop --accounts 177****7689       # 只跑某个账号
cargo run -- --loop 2>/dev/null > result.json    # stdout 只有 JSON 报告
cargo run -- --notify-test                       # 按通道 + 账号路由各发一条自检
```

首次使用请先准备凭据：把 `cookies.example.json` 复制为 `cookies.json` 并填入值
（见第 5 节）。

---

## 4. 命令与四种运行模式

| 模式 | 做什么 | 副作用 | 报告状态 | 退出码 |
|---|---|---|---|---|
| 单次（默认） | 拉列表 → 查已领状态 → 逐张尝试可领券（`single_run_snipe_only=true` 时只处理目标券） | 会真领 | 每账号一组 `{coupon, status, detail}` | 任一账号执行异常 → 1 |
| `--loop` | 只抢目标券（两张 5 折），波次重试直到全有结论或超时 | 会真领 | 同上 + `grant_status` | 任一 `auth_expired`/`error` → 1 |
| `--ping` | 只调 info + grant-status 两个只读接口 | 无 | `reachable` / `expired` / `unknown` / `error: ...` | 任一 `expired`/`error` → 1 |
| `--verify-session` | 用探针券试领一次，证明登录态 | **有**（当天探针券未领会领掉一张） | `authenticated` / `expired` / `unknown` / `error: ...` | 有任一非 `authenticated` → 1 |

参数：

| 参数 | 说明 |
|---|---|
| `--loop` | 循环抢券模式（并发 + 错峰） |
| `--minutes <N>` | 循环持续分钟数（默认 10） |
| `--interval <N>` | 每轮间隔秒数（默认 2.0） |
| `--fire-at <HH:MM[:SS[.毫秒]]>` | 开火时刻；越界值（如 `25:00`）会被**拒绝**而不是钳位 |
| `--fire-lead <N>` | 固定开火提前量（`adaptive_lead` 关闭时生效） |
| `--config <PATH>` | JSON 配置文件路径（默认当前目录 `claim.config.json`，存在才读） |
| `--accounts <A,B>` | 只运行指定账号（按 label 或认证文件名匹配） |
| `--notify` / `--no-notify` | 强制开 / 关本次通知 |
| `--notify-test` | 按配置的通道发测试消息后退出 |
| `--ping` / `--verify-session` | 互斥 |

- `--ping` 只证明「网络与签名可用」（只读接口不校验登录），不会谎报 `authenticated`。
- 单次与 loop 的目标不同：单次默认覆盖品牌下全部可领券；loop 只打 `snipe_keyword`
  命中的券，把第一波火力留给目标。想让单次也只处理目标券，开 `single_run_snipe_only`。

---

## 5. 凭据准备

凭据文件放在**当前工作目录**（可用 `MEITUAN_BASE_DIR` 指定其他目录），
文件名由 `auth_files` 配置，默认 `("cookies.json", "cookies-new.json")`——存在哪个用哪个。

`cookies.example.json` 是模板（会入库）。桌面 Chrome 获取方式：
打开领券页并保持登录 → F12 → Application → Cookies → 取 `vip.ds.163.com` / `.163.com`
域下的 `GL-XSRF-TOKEN` 与 `GOD_UUID`；同面板 Local Storage → 取 `ds-website-uuid` 作为 `device_id`。

多账号（一个文件放账号数组，推荐）：

```json
[
  { "label": "177****7689", "GL-XSRF-TOKEN": "...", "GOD_UUID": "...",
    "device_id": "...", "cookies": { "JSESSIONID": "..." },
    "notify": { "targets": ["email"], "to": ["boss@example.com"] } },
  { "label": "193****6704", "...": "..." }
]
```

- 三条鉴权字段可省略，会从 `cookies` 反推（`device_id` 兼容 `ds-website-uuid`）；
  `cookies` 字段支持浏览器扩展导出的数组形态 `[{name, value}, ...]`。
- 没写 `label` 时：**优先从 cookie 里解析手机号**（`P_INFO` / `S_INFO` / `NTES_YD_PASSPORT`），
  脱敏成 `前3****后4`（如 `177****7689`）；解析不到才退回 `文件名#序号`。
- `label` 重复会加序号去重——label 是客户端字典、退避表与报告的键。

### 5.1 安全红线（代码强制）

- 三条鉴权字段、全部 cookie 值、全部通知凭据登记进脱敏表；
  stdout / stderr / 日志 / 异常 detail / 通知正文输出前统一 `redact()`，另有 `KEY=value` 形态兜底正则。
- `cookies*.json`、`claim.config.json`、`*.log`、`*.jsonl`、`*.tmp`、`*.lock`、`target/` 全部 gitignore。
- 会话 ID 只跟随服务端下发，绝不本地生成/伪造。
- 凭据回写有**跨进程锁**（旁路锁文件 `<认证文件>.lock`，10 秒超时），
  两个实例同时跑时不会互相覆盖对方刚轮换的会话。
- SMTP 未启用 TLS 时**拒绝发送凭据**。

---

## 6. 配置

优先级：`Config` 默认值 < `claim.config.json` < `MEITUAN_<字段名大写>` 环境变量 < CLI。

```bash
MEITUAN_LOOP_MINUTES=5 cargo run -- --loop --fire-at 10:00:00
MEITUAN_BASE_DIR=/path/to/conf cargo run -- --ping     # 指定凭据/配置查找目录
```

- 配置文件键名必须是 `Config` 字段名，**写错直接报错并列出全部合法字段名**；
  下划线开头的键视为注释忽略。
- 环境变量只能表达标量；`MEITUAN_FIXED_COUPONS` 这类嵌套结构会被明确拒绝并提示改配置文件。
- 布尔值无法识别（如 `maybe`）会报错，而不是静默按 false 处理。
- 完整可调项见 `claim.config.example.json`，字段真源见 `src/config.rs`。

节奏参数（实测值，改前先看 JSONL 数据）：

| 参数 | 默认 | 说明 |
|---|---|---|
| `first_wave_gap` | 0.05s | 第一波任意两次 grant 的最小间隔 |
| `first_wave_inflight` | 6 | 第一波同时在飞上限（账号数 × 2 张券） |
| `sustained_gap` / `sustained_inflight` | 0.5s / 2 | 后续波次安全模式 |
| `rate_limit_backoff` | 60s | 命中 40007 后该账号退避 |
| `soldout_stop_after` | 3 | 同一张券连续 60001 达到次数即停 |
| `refresh_every` | 30s | 抢券期间列表刷新间隔 |
| `fire_lead` | 0.0 | 固定开火提前量 |
| `adaptive_lead` | true | 用预热 RTT 自适应提前量（中位数×0.2，钳制 0.2~0.6s） |
| `early_stop_all_soldout` | true | 首波全抢光时确认一波后提前收工 |

---

## 7. 输出

stdout 是可管道解析的 JSON（日志、进度、警告全部走 stderr）：

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

`grant_status` 来自收尾的 `grant-status` 复核，是服务端记录的最终事实；`detail` 一律脱敏且限长 200。

文件产物：

| 文件 | 位置 | 内容 |
|---|---|---|
| 运行日志 | `run_log_dir/claim-<时间>.log` | 与 stderr 同源（UTF-8） |
| 事件明细 | 同目录同名 `.jsonl` | 每次 grant 一行：`send_ts / label / coupon_name / status / elapsed`，无凭据 |
| 保活日志 | `keepalive_log` | `--ping`/`--verify-session` 每账号一行 |

---

## 8. 消息通知

配置里填了 `notify_targets` 才启用；通道可选 `telegram` / `feishu` / `dingtalk` /
`serverchan` / `email` / `resend` / `webhook`。默认只发四类事件：

| 事件 | 触发点 |
|---|---|
| `result` | loop 收尾、单次执行结束（汇总一条） |
| `account_result` | 同上，每账号一条详情 |
| `auth_expired` | 报告里出现 873 |
| `health` | `--ping` / `--verify-session` 有异常账号时 |

一次运行会发 `1 + 账号数` 封（1 封汇总 + 每账号 1 封详情）；嫌吵就把 `account_result`
从 `notify_events` 去掉。

邮件类通道（`email` / `resend`）会用 `report_html.rs` 生成 HTML 报告页：
账号详情页是「双券卡」版式（未抢到的一侧变灰、中间裂一条缝），
汇总页按账号列出**全部券 + 状态**。动态文本先脱敏再转义，与纯文本正文同一口径。

---

## 9. 保活与调度

```cron
# 每 10 分钟只读探活；退出码 1 = 失效或网络异常，可接告警
*/10 * * * * cd /path/to/meituan && /path/to/meituan --ping >> keepalive.cron.log 2>&1 || notify-send "美团 会话异常"
```

想连登录态一起确认，把 `--ping` 换成 `--verify-session`。Windows 用「任务计划程序」。
间隔务必小于服务端 session 空闲超时。

配好通知通道后，`--ping`/`--verify-session` 发现异常账号会直接推 `health` 事件
（全部正常时不发），cron 行里的 `|| notify-send` 可以省掉。

---

## 10. 测试

```bash
cargo test                      # 60 项：54 单元 + 6 集成
cargo fmt --check               # 格式检查
cargo clippy --all-targets      # 静态检查（当前零告警）
```

测试全部只访问 `127.0.0.1` 上的本地桩服务，**不触碰任何真实第三方接口**。

---

## 11. 故障排查

| 现象 | 原因与处理 |
|---|---|
| `error calling dlltool 'dlltool.exe'` | Windows GNU 工具链缺 `as`，见 1.1 节 |
| `没有任何账号 Cookie 文件（...）` | 凭据不在当前工作目录，或 `auth_files` 名字写错；用 `MEITUAN_BASE_DIR` 指定目录 |
| `cookies.json[1] 缺少字段: GOD_UUID` | 数组里第 2 条凭据不全，重新导出（值不会被打印） |
| `配置字段有误（...）: unknown field` | 配置键名拼错，错误信息里会列出全部合法字段名 |
| `等待凭据文件锁超时` | 有两个实例在并发写同一份认证文件；确认没有重叠运行 |
| `开火时刻超出合法范围` | 时/分/秒越界（如 `25:00`），直接拒绝而不是钳位 |
| 第一波就 `rate_limited` | 高频跨波才会撞 40007；确认没开 `MEITUAN_BURST_TEST`，必要时降 `first_wave_inflight` |
| `SMTP 未启用 TLS ... 拒绝发送凭据` | 开 `email_use_ssl`（465）或 `email_use_tls`（587） |
| 一条通知都没发 | `notify_targets` 为空即整体禁用；或事件不在 `notify_events` 里；或用了 `--no-notify` |

---

## 12. 与 Python 版的关系

| | Python（`legacy-python/`，`main` 分支） | Rust（本分支） |
|---|---|---|
| 入口 | `python claim.py ...` / `meituan ...` | `meituan ...` |
| 依赖管理 | `pyproject.toml` + `pip install -e .` | `Cargo.toml` + `cargo build --release` |
| 配置/凭据查找基准 | 包目录的上一级 | 当前工作目录（`MEITUAN_BASE_DIR` 可覆盖） |
| 环境变量前缀 | `MEITUAN_*` | `MEITUAN_*`（一致） |
| 配置文件与凭据格式 | `claim.config.json` / `cookies.json` | **完全一致**，可直接复用 |
| 通知通道与事件 | 7 通道 / 4 事件 | 一致 |
| 测试数 | 267 | 60（覆盖关键路径与全部已知回归） |

命令行参数、配置字段名、退出码语义、报告页版式都保持一致，
因此已有的 cron 配置与凭据文件可以原样迁移。

---

## 13. 边界与免责

- 只在**你自己的账号**上使用，并遵守网易大神的服务条款与频率约束；节奏参数刻意保守，
  不要改成高频压测形态。
- 不绕过登录、不伪造会话、不提取他人凭据；`--verify-session` 有真实领取副作用。
- 接口是逆向复刻的私有接口，随时可能变更；签名或字段漂移时先看 `--ping` 是否 `reachable`。
- 开启通知会把「哪些账号、领到了什么、什么时候」推给第三方服务。默认已掩掉 label 中的
  手机号等长数字；若你希望连账号标识也不外泄，用「老号/小号」这类中性 label。
