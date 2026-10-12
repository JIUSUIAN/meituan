# 架构说明（Rust 版）

本文说明 Rust 重写的整体架构、模块划分、错误处理策略与依赖选型理由。
Python 原版保留在 `legacy-python/`，两者模块一一对应，便于逐文件对照。

---

## 1. 整体架构

### 1.1 分层

```
                ┌──────────────────────────────────────────────┐
   CLI 层       │  src/main.rs（clap）                          │
                │  参数解析 → 配置装配 → 账号筛选 → 分发 → 退出码  │
                └───────────────┬──────────────────────────────┘
                                │
                ┌───────────────▼──────────────────────────────┐
   业务层       │  flows.rs                                    │
                │  ping / verify_session / single_run /         │
                │  LoopRunner（波次调度、并发、退避、收尾）       │
                └───────┬──────────────────────┬───────────────┘
                        │                      │
        ┌───────────────▼──────┐   ┌───────────▼──────────────┐
        │ api_client.rs        │   │ notify.rs                │
        │ 签名 / POST / 错误分层│   │ 7 通道 / 账号级路由       │
        │ Cookie 轮换跟随       │   │ HTML 报告页（旁路）       │
        └───────┬──────────────┘   └───────────┬──────────────┘
                │                              │
   ┌────────────▼────────────┬─────────────────▼──────────────┐
   │ cookies.rs CookieStore  │ report_html.rs 报告页渲染       │
   │ pacing.rs 限速+在飞闸门  │ security.rs 凭据/脱敏/文件锁     │
   └────────────┬────────────┴────────────────────────────────┘
                │
   ┌────────────▼─────────────────────────────────────────────┐
   │ config.rs（四层配置）  models.rs（领域模型）  errors.rs     │
   └──────────────────────────────────────────────────────────┘
```

依赖方向单向向下，无环：`main → flows → {api_client, notify} → {cookies, security, models} → {config, errors}`。
唯一需要说明的“回边”是 `notify` 调 `flows::beijing_ts`（只为取时间戳），属于工具函数复用，
不构成状态依赖——Python 版也是同样的结构。

### 1.2 与 Python 版的三个有意差异

| 差异 | 原因 |
|---|---|
| **无进程级可变全局**。脱敏表是 `SecretsRegistry` 实例，用 `Arc` 显式传递 | Python 用 `GLOBAL_SECRETS` 单例；Rust 里全局可变状态要么 `unsafe` 要么 `OnceLock<Mutex>`，两者都比显式传递更难推理。显式传递也让单测可以各自持有独立实例，互不干扰 |
| **查找基准是当前工作目录**（可用 `MEITUAN_BASE_DIR` 覆盖） | Python 按「包目录的上一级」解析（`__file__.parent.parent`），这在 `pip install` 后指向 `site-packages`，二进制分发时不可靠。改成显式基准 + 环境变量覆盖 |
| **`ApiFailure` 单枚举聚合三层错误** | Python 用三个异常类 + 继承（`ApiParseError < ApiTransportError`）。Rust 用枚举 + `From` 转换，`?` 直接可用，且 `match` 时编译器强制穷尽所有分支 |

### 1.3 并发模型

`LoopRunner` 的运行状态集中在一个 `Mutex<LoopState>`：

```rust
struct LoopState {
    done:           Vec<HashSet<String>>,        // 每账号已搞定的 couponId
    final_:         Vec<HashMap<String, Value>>, // 每账号 券名 -> 最终条目
    events:         Vec<GrantEvent>,             // JSONL 同源的事件表
    backoff_until:  Vec<f64>,                    // 限流退避（单调钟）
    soldout_streak: Vec<HashMap<String, usize>>, // 抢光连击计数
    targets:        Vec<Vec<(String, Coupon)>>,  // 可增量合并的目标
}
```

- 波次派发用 `std::thread::scope`：每个任务一个作用域线程，`scope` 退出即全部 join
  （语义等价于 Python 的 `as_completed`，但不需要线程池的生命周期管理）。
- 真正的并发上限由 `GrantPacing`（限速器 + 在飞闸门）控制，与线程数无关——
  这一点与 Python 版一致：线程池只是调度手段，**节奏由 pacing 单点决定**。
- 锁的粒度刻意收窄：网络请求在锁外进行，只在读写共享状态时短暂持锁，
  避免「一个账号的慢请求阻塞其他账号记账」。

---

## 2. 关键模块划分

| 模块 | 职责 | 对应 Python |
|---|---|---|
| `errors.rs` | 三层错误类型 + `grant_code_status` 集中映射 | `errors.py` |
| `config.rs` | `Config`（59 字段）+ 四层合并；`deny_unknown_fields` 让拼错键名立刻报错 | `config.py` |
| `security.rs` | 凭据加载/归一化、`SecretsRegistry` 脱敏、`FileLock` 跨进程锁、原子写 | `security.py` |
| `cookies.rs` | `CookieBag` 有序集合 + `CookieStore`（跟踪名单 + 内部 `Mutex`） | `cookies.py` |
| `models.rs` | `Coupon` / `GrantEvent`；API 边界即转模型，`raw` 透传未知字段 | `models.py` |
| `api_client.rs` | 手工序列化 + SHA1 签名、错误分层、`Set-Cookie` 轮换跟随 | `api_client.rs` |
| `pacing.rs` | `RateLimiter` + `InflightGate`（`Condvar` + RAII guard） | `pacing.py` |
| `notify.rs` | 7 通道分发、账号级路由、HTML 侧统一脱敏 | `notify.py` |
| `report_html.rs` | 双券卡详情页 + 全部券汇总页（纯表格内联样式） | `report_html.py` |
| `flows.rs` | `RunLogger`、`ping`、`verify_session`、`single_run`、`LoopRunner` | `flows.py` |
| `main.rs` | clap 参数、配置装配、退出码 | `claim.py` + `cli.py` |

### 2.1 两个值得单独说明的设计点

**`CookieStore` 自己解析 `Set-Cookie`**，不启用 `reqwest` 的 `cookies` feature。
原因：只需要 `name=value` 第一段 + 跟踪名单过滤，自己解析反而更可控，
也少一个 feature（及其传递依赖）。跟踪名单外的字段（`GL-XSRF-TOKEN` 等签名依赖字段）
一律不接受服务端改写。

**`GrantPacing::slot()` 的顺序是先闸门、后限速**：

```rust
pub fn slot(&self) -> PacingGuard<'_> {
    let gate = self.gate.slot();   // 先取并发容量
    self.limiter.wait();           // 再在持闸期间卡最小间隔
    PacingGuard { _gate: gate }
}
```

反过来（先限速、后等闸门）会让多个已错峰的线程在闸门放开的瞬间挤在一起发出，
把配置的 0.5s 安全间隔打成 ~0s。这是 Python 版修复过的问题，Rust 版直接内置正确顺序，
并有回归测试（`pacing::tests::slot_holds_gate_then_limiter`）。

---

## 3. 错误处理策略

### 3.1 三层错误，禁止字符串猜测

```rust
pub enum ApiFailure {
    Business(ApiError),        // HTTP 200 但 code != 200
    Transport(ApiTransportError), // 连接失败 / 超时 / 非 2xx / TLS 失败
    Parse(ApiParseError),      // HTTP 成功但响应不是合法 JSON
}
```

业务码到领域状态的映射是**唯一真源**（`errors::grant_code_status`）：

| 业务码 | 领域状态 | 后续动作 |
|---|---|---|
| 200 | `granted` | 该券收工 |
| 803 | `already_claimed` | 收工 |
| 40007 | `rate_limited` | 该账号退避 60s，保留重试 |
| 873 | `auth_expired` | **停止重试** |
| 60001 | `out_of_stock` | 连击计数，达阈值才停 |
| 其他 | `failed`（保留原码） | 保留重试 |

未知码一律 `failed` 并保留原始 code——**不做字符串匹配、不误分类**。

### 3.2 业务失败 vs 执行失败

这是退出码语义的关键区分：

- `failed` = 服务端给了答复，只是不是成功（例如未知业务码）。**不算执行失败**。
- `error` = 传输/解析失败，这一轮根本没抢成。**计入退出码**（`any_error` / `_loop_has_error`）。

否则 cron 会把「网络断了」当成「今天没抢到」而静默通过。

### 3.3 错误信息永不泄露凭据

- 所有对外消息（stdout / stderr / 日志 / 异常 detail / 通知正文）先过 `SecretsRegistry::redact`。
- 脱敏表登记：三条鉴权字段、全部 cookie 值、全部通知凭据（token / webhook / 加签 secret / SMTP 密码），
  外加 webhook URL 里 query 参数的值。
- 兜底正则处理「未经登记就以 `KEY=value` 形态出现」的情况。
- 凭据加载报错**只报文件名 + 条目下标 + 字段名**，绝不回显字段值。
- HTTP 错误正文截断 200 字符并脱敏后才进异常对象。

### 3.4 best-effort 边界

通知是**旁路**：任何通道异常都被 `send_one` 的 `Result` 吸收，转成
`(channel, false, detail)` 返回，绝不向上传播影响抢券主流程。
Cookie 轮换回写同理——失败只影响本次落盘，下次轮换再试。

---

## 4. 依赖选择理由

| 依赖 | 用途 | 为什么选它 |
|---|---|---|
| `reqwest`（`blocking` + `native-tls`） | API 请求 + webhook | `blocking` 版语义与 Python 的 `requests` 最接近，业务层不必 async 化。TLS 选 `native-tls` 而非 `rustls`：Windows 上走 SChannel，不需要 C 工具链编译 `ring` |
| `serde` / `serde_json` | 配置与 API 的 JSON | Rust 生态事实标准；`deny_unknown_fields` 正好满足「配置键名写错要报错」 |
| `clap`（derive） | CLI | derive 宏让参数定义与 `--help` 文本同源，避免文档漂移 |
| `sha1` | `GL-CheckSum = SHA1(body + xsrf)` | RustCrypto 纯 Rust 实现，无 C 依赖 |
| `hmac` + `sha2` | 钉钉机器人加签 | 同上，且与 `sha1` 同属 RustCrypto，版本兼容性好 |
| `base64` | 钉钉签名编码 | 只用到 `Engine::encode`，官方实现 |
| `lettre`（`smtp-transport`） | 邮件通道 | 唯一维护活跃的纯 Rust SMTP 客户端；显式区分 `relay`（隐式 TLS 465）/ `starttls_relay`（587）/ `builder_dangerous`（明文） |
| `chrono` + `chrono-tz` | 北京时间、开火时刻解析 | 需要真正的 `Asia/Shanghai` 时区（不是固定 +8），`chrono-tz` 提供 IANA 时区库 |
| `regex` | 券名解析、脱敏兜底、手机号提取 | 标准选择。**注意**：它不支持 lookaround，手机号正则用「非数字边界」等价实现 |
| `percent-encoding` | 手机号 URL 解码、钉钉签名编码 | 轻量，无需引入完整 URL 解析 |

**刻意没有引入的依赖**：

- `tokio` / `async-std`：抢券的并发模型是「少量线程 + 严格节奏控制」，
  异步运行时的调度粒度与「精确错峰」的目标相冲突，且会显著增加代码复杂度。
- `fs2` / `file-lock`：std 的 `File::try_lock` 自 1.89 稳定，已覆盖
  Unix `flock` 与 Windows `LockFileEx` 两种实现，无需额外依赖（因此 MSRV 定为 1.89）。
- 日志框架（`log` / `tracing`）：日志只有「控制台 + 可选文件」两种出口，
  且每条都要过脱敏，自己写 20 行的 `RunLogger` 比引入框架再包一层更直接。

---

## 5. 测试策略

| 层次 | 位置 | 覆盖 |
|---|---|---|
| 单元测试 | 各模块内 `#[cfg(test)] mod tests` | 54 项：错误映射、配置四层合并、脱敏、凭据加载/去重/路由、Cookie 跟踪、限速与闸门、报告页渲染、通知脱敏与掩码、时间与自适应提前量 |
| 集成测试 | `tests/integration.rs` | 8 项：本地 HTTP 桩服务上的 `single_run` 全链路、`snipe_only` 跳过探针券、传输失败计入退出码、webhook 分发、缺配置只报字段名、loop 目标校验，外加两项**协议级**断言（必需请求头齐全、`GL-CheckSum` 公式可手工复算） |

关键回归（都在测试里有对应断言）：

1. **HTML 报告页与纯文本同一口径脱敏**——`safe_items_redacts_every_dynamic_field`
2. **详情页 >2 张券不丢券/不重复、失败券不显示祝贺**——`three_coupons_none_lost_or_duplicated`
3. **闸门容量 1 下真实发送间隔仍被强制执行**——`slot_holds_gate_then_limiter`
4. **跨进程锁互斥**——`file_lock_is_exclusive`
5. **越界开火时刻被拒绝而非钳位**（`25:99` 曾会被钳成 23:59 从而等近 24 小时）——`wait_until_rejects_bad_format_without_panicking`
6. **请求头齐全**（漏发 `Content-Type` 时服务端 WAF 返回业务码 417，
   表现为 `--ping` 全部 `unknown` 且不报错——**这个 bug 是真实调用才发现的**，
   单测与常规集成测试都覆盖不到）——`request_carries_all_required_headers`
7. **签名公式可复算**——`signature_is_sha1_of_body_plus_xsrf`

全部测试只访问 `127.0.0.1` 上的桩服务，不触碰任何真实第三方接口。

### 5.1 真实调用验证（本地桩覆盖不到的部分）

自动化测试之外，还对本项目做过一轮**真实接口**验证（只读 + 幂等操作）：

| 项目 | 结果 |
|---|---|
| `--ping`（只读） | 3 个账号全部 `reachable`，退出码 0 |
| 单次执行 | 与 Python 版逐字段对比**完全一致**（账号集合、每张券的 `status` / `detail` / `grant_status`） |
| `--loop --minutes 0.25` | 7 波 14 请求，首波后正确切安全模式，JSONL 事件落盘，退出码 0 |

对比时需注意**服务端限流**：Rust 与 Python 连续跑会互相触发 40007，
必须间隔 ≥60s 再对比，否则会误判成实现差异。
