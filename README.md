# claim.py 重构产出（P0 + P1）

按 `claim_P0_refactor_plan.md` 完成 P0（T01/T02/T03）与 P1（架构拆分）。
并发、限流与抢券节奏参数保持原值不变。

## 模块结构（已收敛为 chagee/ 包）

```
claim.py                 薄启动器（用法文档在此）
pyproject.toml           包元数据 + 依赖 + console_scripts（chagee = chagee.cli:main）
chagee/
  cli.py                 命令行入口：参数解析、配置装配、分发到 flows
  config.py              配置分层：dataclass 默认值 < claim.config.json < CHAGEE_* 环境变量 < CLI
  security.py            T01：凭据加载（load_auth，支持浏览器导出格式）、登记与统一 redact
  errors.py              T03：ApiError / ApiTransportError / ApiParseError + 业务码集中映射
  cookies.py             CookieStore：单账号 Cookie 单一真源 + 服务端更新跟踪名单
  models.py              领域模型：Coupon / GrantEvent（API 边界转换，raw 透传）
  api_client.py          签名、POST、错误分层转换、JSESSIONID 轮换跟随（单账号客户端）
  pacing.py              RateLimiter + InflightGate（容量可动态调整，替代“换全局 Semaphore”）
  flows.py               业务流程：RunLogger、ping（只读）、verify_session（显式副作用）、
                         single_run、LoopRunner（原 200 行 loop_run 拆为步骤方法）
tools/
  import_cookie_export.py  浏览器 Cookie 导出文件 -> 认证文件（会话重建闭环）
tests/
  test_claim_p0.py         P0 回归测试（33 个）
  test_claim_p1.py         P1 测试（26 个：闸门/配置分层/LoopRunner 冒烟/single_run/模型）
  test_cookie_rotation.py  Cookie 跟踪与归一化测试（20 个）
  test_review_batch.py     评审第 2 批测试（38 个：tmp 加固/退出码/CLI 校验/JSONL/导出工具）
.github/workflows/ci.yml  CI：多版本 Python 跑全套 mock 测试 + 凭据入库守卫
```

数据文件位置不变：`claim.config.json`、`cookies.json`、`cookies-new.json`
仍在项目根目录（chagee/ 的上一级）。三种入口等价：
`python claim.py ...`、`python -m chagee.cli ...`、`chagee ...`（`pip install -e .` 后）。

## P0 要点回顾

- **T01 脱敏**：`SecretsRegistry` 登记凭据值 + 兜底正则；`RunLogger`/keepalive/
  异常 detail 输出前统一 `redact()`；HTTP 错误正文截断 200 且脱敏；`load_auth`
  逐级校验（存在→JSON→字段→POSIX 权限警告），报错只报字段名。
- **T02 语义**：`--ping` 只读（info+grant-status），状态 reachable/expired/
  unknown/error；有副作用的探针验证独立为 `--verify-session`，help 明确标注；
  两者互斥。
- **T03 错误模型**：传输/解析/业务三层异常；`GRANT_CODE_STATUS` 集中映射
  803/40007/873/60001；未知 code 保留原码标记 failed；`grant_status` 失败抛
  异常（调用方可区分“失败”与“空”）；循环中 873 直接停止重试。

## P1 要点

- **API Client 拆分**：签名/请求/错误转换收敛到 `ApiClient`，业务层不再接触
  requests 细节；session 可注入（测试/复用），自建则负责关闭。
- **消除全局可变状态**：`GRANT_LIMITER`/`GRANT_SEMAPHORE` 模块级全局删除，
  改为 `GrantPacing` 实例随 `LoopRunner` 创建；安全模式切换用
  `InflightGate.set_max()` 动态调容量，修复了 P0“替换 Semaphore 时在途请求
  仍持旧闸”的竞态。
- **大函数拆分**：`loop_run` → `LoopRunner`（`_refresh_one` / `_grant_one` /
  `_check_clock` / `_preheat_and_wait` / `_build_wave_tasks` / `_all_settled` /
  `_log_summary` / `_finalize`）；`single_run`/`loop_run` 的重复日志闭包统一为
  `RunLogger`。
- **配置分层**：所有节奏/超时/路径常量收敛到 `Config` dataclass；支持
  `claim.config.json`（同目录，存在才读，未知字段报错）与 `CHAGEE_*` 环境变量；
  `CHAGEE_BURST_TEST=1` 语义保留（映射到 `burst_test` 字段）。

## JSESSIONID 轮换跟踪（P1.5）

实测确认 JSESSIONID 是大神登录态的载体，因此 `ApiClient` 内置会话 Cookie
变化检测层（只跟随服务端下发，绝不本地生成/伪造）：

- 任意响应（含 4xx/5xx 与业务错误响应）带 `Set-Cookie` 轮换时：
  更新内存 `auth["cookies"]` → 新值登记进脱敏表 → 原子回写来源认证文件
  （tmp+rename，剔除 `_auth_file`/`label`，POSIX 下 chmod 600）→ 触发
  `on_rotate` 回调（只传 Cookie 名，不传值），loop/single_run 记一行日志。
- 同账号并发请求经每客户端小锁保护；Cookie 头合成保证基础对
  （GL-XSRF-TOKEN、GOD_UUID）恒在，扩展项（JSESSIONID 等）叠加。
- 名单可配：`session_cookie_names`（默认 `("JSESSIONID",)`，可用
  `CHAGEE_SESSION_COOKIE_NAMES=A,B` 或配置文件扩展）；
  `persist_rotated_cookies=False` 关闭回写（仅内存跟随）。
- Session 失效（873）仍走既有路径：标记 `auth_expired` → 停止依赖旧会话；
  重建会话需人工重新登录后由 load_auth/回写流程搬运新凭据，脚本不自动重登。

测试：`tests/test_cookie_rotation.py`（20 个）。全套见「运行」一节的
`python -m unittest discover -s tests -t .`（当前 117 个）。

## 评审遗留项收尾批次（P1.6）

- **stdout/stderr 分离**：`RunLogger` 日志全部走 stderr，stdout 只输出最终
  JSON 报告，外部可管道解析（`python claim.py --loop 2>/dev/null > result.json`）。
- **Ctrl+C 优雅收尾**：loop/single 模式捕获 `KeyboardInterrupt`，跳过剩余波次
  但照常执行收尾统计与 grant-status 状态校验，已有战果不丢。
- **连接级重试**：自建 Session 挂载 `Retry(connect=2, read=0, status=0)`——
  仅在请求尚未发出时重试，grant 等非幂等 POST 安全；读超时/状态码重试仍由
  波次逻辑负责。注入的测试替身自动跳过挂载。
- **时钟校验平台化**：`timedatectl` 仅在 Linux 执行，其他平台明确记录跳过。
- **忙等缩短**：`wait_until` 最后自旋从 100ms 降到 5ms，精度不变、CPU 更省。
- **import 清理**：`subprocess/sys/datetime/zoneinfo/Counter` 等提至模块顶层。

测试：全套 66 个（当时）。

## 领域模型层（P1.7）

- `models.py`：`Coupon`（frozen dataclass，`from_api`/`to_dict`，未知字段经
  `raw` 透传不丢；`sold_out()` 仅在 `leftStock==0` 为真，未知按未抢光——与
  历史行为一致）、`GrantEvent`（收尾统计事件）。
- API 边界转换：`find_brand_coupons` 返回 `[Coupon]`，业务层（try_grant、
  LoopRunner、single_run）全部属性访问，杜绝 `couponId` 键名手写漂移；
  输出报告 JSON 键名保持原样。
- 顺带覆盖 PLACEHOLDER/DIRECT_LINK/售罄的 try_grant 分支测试。


## Cookie 逻辑优化（P1.8）

- **`cookies.py` CookieStore**：单账号 cookie 的单一真源——大小写不敏感、
  保留原始拼写；`header()` 是 Cookie 头唯一出口；进 store 的值自动登记脱敏；
  自带锁，支撑同账号并发请求。
- **鉴权字段防覆盖**：`apply_response()` 只接受「跟踪名单」（默认 JSESSIONID）
  内的服务端更新；GL-XSRF-TOKEN 等签名依赖字段不允许被 Set-Cookie 静默改写。
- **签名/头部不漂移**：ApiClient 以顶层鉴权字段为权威覆盖 store 中的同名项
  （配合 load_auth 归一化，双保险）。
- **`load_auth` 入口归一化**：支持浏览器插件导出格式（cookies 为
  `[{name,value},...]`）；GL-XSRF-TOKEN/GOD_UUID/device_id 可从 cookies 反向
  推导（device_id 兼容 `ds-website-uuid` cookie）；顶层与 cookies 字典自动对齐。
- 轮换后 `auth["cookies"]` 与 store 同步并原子回写（行为同 P1.5，路径改为
  经 store）。

测试：全套 77 个（当时）。

## 评审第 2 批（1.9.0）

针对整体复审意见的修复与增强：

- **凭据中转文件加固**：`save_auth` 中转文件名带 pid（`cookies.json.1234.tmp`），
  多进程并发保存互不覆盖；写入失败即清理，绝不留带凭据的半成品；`load_auth`
  顺手清掉 60 秒前的孤儿 `.tmp`（在途写入不误删）；`.gitignore` 补 `*.tmp`、
  `*.jsonl`、打包产物。
- **退出码不再骗人**：loop 模式退出码从报告推导（任一账号 `auth_expired`/`error`
  即返回 1），cron 等自动化层能真正感知失败。
- **CLI 校验前置**：`--fire-at` 格式与取值范围在 argparse 层校验（支持
  `HH:MM[:SS[.毫秒]]`），不再等到 `wait_until` 抛 traceback；抢券目标为空
  （关键词写错）时启动即报错，不会空转十分钟；配置里显式写了却不存在的认证
  文件会警告一行——静默跳过会让人以为在双账号并发。
- **探针券单一真源**：删除 `flows.PING_PROBE_ID` 硬编码，改由
  `Config.probe_coupon` 从 `fixed_coupons` 推导（券 ID 只在一处定义）。
- **`--accounts` 子集过滤**：按 label 或认证文件名（含/不含扩展名）匹配，
  验证新导出的 `cookies-new.json` 时不必改配置。
- **事件明细 JSONL**：收尾把 `GrantEvent` 追加写 `<run_log>.jsonl`，人读日志之外
  多一份机器可读副本，供事后复盘发送时刻/耗时分布（不含任何凭据）。
- **`--verify-session` 闭环回显**：验证通过的账号回显认证文件路径（stderr）。
- **环境变量覆盖守卫**：`CHAGEE_FIXED_COUPONS` 这类嵌套结构字段明确拒绝并给
  可读报错，不再让 `Config(**values)` 炸出难懂的 TypeError。
- **开火等待精度**：`wait_until` 的 sleep 段与最后 5ms 忙等改用 `perf_counter`
  单调钟锚定（Windows 上 `time.time` 分辨率约 15ms，会整体偏移一个 tick）。
- **工程化**：`pyproject.toml`（依赖单一真源 + `chagee` 控制台脚本，`claim.py`
  保留为兼容 shim）；测试归位 `tests/`；GitHub Actions CI 跑多版本 Python 全套
  mock 测试，并带「凭据文件绝不入库」守卫。
- **会话重建工具**：`tools/import_cookie_export.py` 把浏览器扩展导出的 cookie
  数组转成认证文件并做完整性校验（缺字段只报字段名）。JSESSIONID 是 HttpOnly，
  页面 JS/书签栏脚本读不到，必须走扩展导出——工具只做格式转换，不生成任何值。

测试：全套 117 个（P0 33 + P1 26 + rotation/cookies 20 + 评审批次 38）。

## 运行

```bash
# 安装（依赖单一真源在 pyproject.toml）
pip install -e .            # 或 pip install -r requirements.txt

# 全套测试（全部 mock，不访问真实接口）
python -m unittest discover -s tests -t . -v

# 日常
chagee --ping                                    # 只读健康检查（cron 保活）
chagee --verify-session --accounts cookies-new   # 验证新导出的凭据（有副作用）
chagee --loop --fire-at 14:00:00.000             # 定时开抢
chagee --loop 2>/dev/null > result.json          # stdout 只有 JSON 报告

# 会话重建（873 之后）：浏览器扩展导出 cookie -> 认证文件
python tools/import_cookie_export.py export.json --domain 163.com

# Windows 本目录 .venv
.venv\Scripts\python.exe -m unittest discover -s tests -t .
.venv\Scripts\python.exe claim.py --ping

# 可选：CHAGEE_LOOP_MINUTES=5 python3 claim.py --loop
```

保活建议（cron / Windows 任务计划）：

```cron
# 每 10 分钟只读探活；退出码 1 = 登录态失效或网络异常，可接告警
*/10 * * * * cd /path/to/meituan && python3 claim.py --ping >> keepalive.cron.log 2>&1 || notify-send "CHAGEE 会话异常"
```

注意：
- Windows 控制台为 GBK 时中文日志显示乱码，属终端编码问题，可设
  `PYTHONIOENCODING=utf-8`；日志文件本身是 UTF-8。
- `zoneinfo` 在 Windows 需要 `tzdata` 包（已作为平台条件依赖写入 pyproject）。
- `timedatectl` 时钟校验为 Linux 专用，其他平台记录“跳过”。
- Windows 上认证文件没有 chmod 600 等价收紧，依赖所在目录的 NTFS ACL。

## Plan 验收对照（2026-10-10 终审）

T01 认证与日志安全：凭据不入库（.gitignore）✔ / 缺字段、非法 JSON 安全报错 ✔ /
stdout、日志、异常均脱敏 ✔（含 wait_until 提示语死角修复）—— 7 项测试。
T02 --ping 语义：不进领取路径（URL 级断言）✔ / 网络异常明确 error ✔ /
不谎报 authenticated ✔ / help-doc-常量一致 ✔ —— 7 项测试。
T03 错误体系：测试矩阵 7/7 ✔（transport/http/business/unknown/parse/脱敏/
verify_status 失败与空可区分），业务码零字符串猜测。
P1 四目标：API Client 拆分 ✔ / 全局可变状态清零（Gate/Pacing/LoopRunner 实例化）✔ /
巨型函数拆分（LoopRunner 步骤方法 + RunLogger）✔ / 配置分层（config 四级 + 示例文件）✔。
Git：本目录已 `git init`，按 plan 精神分 2 个提交（代码 / 测试；4 段粒度无法在
合并后的最终树上忠实重放，已在提交信息注明）。
明确不做：启动时交叉校验固定券 ID（与第一波零等待冲突，由波后增量刷新+失效停止覆盖）；
自动重登（失效走人工登录 + load_auth 搬运）。
日常保活建议：cron 每 10~15 分钟 `claim.py --ping`（间隔务必小于服务端 session
空闲超时；JSESSIONID 轮换会自动跟随回写）。
