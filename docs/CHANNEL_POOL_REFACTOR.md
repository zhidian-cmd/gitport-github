# 通道池重构实施方案

> 状态：待实施。本方案由 v0.5.5 发布后的完整代码审计产出，所有文件行号基于 `32c19a9`。
> 目标：把散落在 `get_direct`/`try_cached`/`dial_h2_race`/`serial_dial_skip` 四层里的
> 通道获取、建造、健康检查、溢出处理全部收进通道池，请求路径变成一行调用。

## 背景与动机

v0.5.5 删除了仲裁器、熔断器、保活 PING、自愈补拨之后，通道管理逻辑仍然散落在四个
函数三层锁里。实测暴露的问题：

1. **并发雷群**：页面同时发起 15 个 .js 请求 → 全部 try_cached NoChannel（池还是空的）
   → 全部排队 dial_lock → 逐个拨号占满 12 IP → 第 13 个起报 `候选均已有通道` → DNS 兜底
2. **死通道发现慢**：内容域通道黑洞后，要等下一个请求骑上去 4s 超时才知道——期间
   后续请求继续撞同一条死通道
3. **职责散落**：通道获取逻辑在 mitm/mod.rs（请求层），拨号逻辑在 pool/mod.rs（池层），
   两者通过 skip_ips / occupied / ERR_NO_FREE_IP 字符串匹配耦合——改一处容易漏另一处

## 目标架构

```
请求路径（mitm/mod.rs）——一行调用，不管通道细节:
    let up = pool::get_or_build(host, &log).await?;

通道池（pool/mod.rs）——拥有通道的完整生命周期:
    get_or_build(host)
        ├─ 1. 骑池：pick(ips, want_slot, None) → 有 → 返回
        ├─ 2. 池空 → 建造机器人 serial_build(host)
        │       ├─ 挑 IP：死亡退避滤掉坏 IP → 游标定起点 → 按延迟排序
        │       ├─ 拨号：TCP → TLS(伪装 SNI) → h2 握手
        │       ├─ 失败 → note_dead(ip) 记死亡退避 → 换下一个 IP
        │       ├─ 全部 IP 死亡 → 返回 Err
        │       └─ 成功 → store_h2 入库 → 返回
        └─ 3. 溢出（所有通道 inflight ≥ cap）→ 同 IP 另开通道
               ├─ 内容域：并存（赌 IP 能扛多通道）
               └─ 会话域：上限 2 条（超出排队）

探活（ConnDriver 内部，零额外任务）:
        select! {
            conn → 断开自摘
            ping_req → 会话域代答 PONG
            probe_tick → 内容域 idle >10s：开 stream 发 GET Range:bytes=0-0
                         2s 无响应 → conn 已黑洞 → 自摘出池
        }
```

## 与现状的差异

| 机制 | v0.5.5 现状 | 重构后 |
|---|---|---|
| 通道寿命 | 批窗 30s，过窗 evict_stale 惰性摘除 | 持续存在，探活保证健康，死了立即出池 |
| 内容域探活 | 无（死靠请求结果，4-8s 才发现） | 极小真实请求（2-3s 发现） |
| 会话域探活 | ping 闸（闲置 >10s） | 不变（30s 周期改为探活计时器驱动） |
| 通道不够时 | ERR_NO_FREE_IP → 报错交兜底 | 同 IP 另开通道（会话域上限 2 条） |
| host 级熔断 | 已删除 | 不恢复（死亡退避逐 IP 记账够用） |
| 拨号链路 | mitm → dial_h2_race → serial_dial_skip | mitm → pool::get_or_build → serial_build |
| host 拨号锁 | host_dial_lock (per-host Mutex) | 移入通道池内部（建造锁） |

## 逐文件改动清单

### 1. `src/pool/mod.rs` — 新增通道池统一入口 + 建造机器人

**新增 `get_or_build`**（~80 行，吸收 get_direct 的通道获取逻辑）：

```rust
/// 通道获取统一入口。骑池 → 没有 → 建造。溢出另开。全灭交 Err。
/// 请求路径只调这一个函数，不管通道怎么来的。
pub async fn get_or_build(
    host: &str,
    want_slot: Option<u8>,
    log: &LogFn,
) -> Result<crate::server::upstream::H2Upstream, String> {
    let ips = dial_targets_ips(host)?;          // 路由表候选
    let class = host_class_of(host);             // Session / Content / Other

    // 1) 骑池：keeper::pick 的占用率 × 延迟公式
    if let Some(up) = pick_channel(&ips, want_slot, &class) {
        return Ok(up);
    }

    // 2) 池空 → 建造（per-host 建造锁防雷群，双检）
    let _build = build_lock(host).lock().await;
    //    双检：等锁期间别的请求可能刚建好
    if let Some(up) = pick_channel(&ips, want_slot, &class) {
        return Ok(up);
    }

    // 3) 建造机器人：串发拨号（死亡退避跳过坏 IP，游标定起点）
    let (conn, ip, sni) = serial_build(host, &class, log).await?;

    // 4) h2 握手 + 入库
    let up = h2_handshake(host, conn, &ip, log).await?;
    let up = store_channel(&ip, up, &class);
    Ok(up)
}
```

**新增 `serial_build`**（改造自现有 `serial_dial_skip`，~60 行变化）：
- 死亡退避表（note_dead / note_dead_node）留在建造机器人里——TCP/TLS/h2 拨号失败
  是建造过程的事
- 游标（cursor_note / dial_order）留在建造机器人里——串发排序是拨号策略
- crew 同组互斥保留——同一次建造的主副腿不重复试同一 IP
- 删除：`inflight` 相关（已在仲裁器退役时删了）、`ERR_NO_FREE_IP`（不再需要——
  全部候选可拨，没有"被占"的概念）

**删除 `evict_stale`**（~25 行）——探活替代了批窗职能。

**删除 `REUSE_WINDOW_SECS`** 常量。

**新增溢出逻辑**（~15 行，在 get_or_build 里）：
- 所有现存通道 `inflight >= max_streams` 时：
  - 内容域：在同 IP 上另开（上限 3 条/IP，超出排队等释放）
  - 会话域：同 IP 上限 2 条（超出排队等释放）
- 已有建造在途 → 等待（上限 3s，30ms 步进）→ 超时交 Err

**新增 `build_lock(host)`**（替代 host_dial_lock，per-host Mutex）：
- 防止同 host 并发建造（雷群去重）
- 保留双检模式：拿锁后再 pick 一次

### 2. `src/server/mitm/mod.rs` — 请求路径大幅简化

**删除 `get_direct`**（~220 行）——职责全部移入 pool。

**删除 `try_cached`**（~60 行）——"骑池"步骤变成 pool::get_or_build 内部的 pick。
"复用失败"处理（drop + 挪游标 + reuse_failed 标记）移入 pool 的失败上报。

**mitm_http 里的调用变成：**
```rust
// 替代原来的 get_direct + try_cached + attempt loop (~220 行)
let up = pool::get_or_build(&host, want_slot, &log).await?;
let resp = match stream_on(&up, &out, &body, budget).await {
    Ok(r) => r,
    Err(e) => {
        // 通道失败：上报给池（摘通道 + 记账），池会给一条新的
        pool::report_failure(&up, &host, &e);
        let up2 = pool::get_or_build(&host, want_slot, &log).await?;
        stream_on(&up2, &out, &body, budget).await?.0
    }
};
```

**保留不变：**
- mirror_or_direct（大文件镜像链，在 get_or_build 之前判断）
- direct_split（README 大图切片，在 get_or_build 之前判断）
- gh_defuse（主站 Whoa 化解，在拿到响应之后判断）
- page_cache / redirect_memo / 遥测拦截 / codeload 别名（前置快道不变）

**删除 `CONTENT_BREAKER` 相关**（如果尚未删除）：
- `pool/mod.rs` 的 `pub static CONTENT_BREAKER`
- mitm/mod.rs 的 set / clear / open 调用

### 3. `src/server/upstream.rs` — ConnDriver 加探活

**ConnDriver struct 增加字段：**
```rust
struct ConnDriver<T> {
    ip: String,
    id: u64,
    conn: h2::client::Connection<T, Bytes>,
    session: bool,           // 会话域 = PING 探活，内容域 = 极小请求探活
    ping: Option<Arc<Mutex<PingPong>>>,
    ping_rx: Option<mpsc::Receiver<oneshot::Sender<bool>>>,
    send: SendRequest<Bytes>, // 驱动自己持有 clone，探活用
    log: LogFn,
}
```

**select! 增加探活分支：**
```rust
enum Step {
    ConnEnd,
    Ping(Option<oneshot::Sender<bool>>),
    Probe,
}
// 内容域：idle >10s 时 tick 触发 Probe
// 会话域：idle >30s 时 tick 触发 Probe（走 PING 而非极小请求）
let step = tokio::select! {
    _ = &mut conn => Step::ConnEnd,
    _ = probe_tick.tick(), if probe_due => Step::Probe,
    req = rx.recv() => Step::Ping(req),
};
```

**Probe 分支（内容域）：**
```rust
Step::Probe => {
    // 在现有 h2 连接上开 stream 发 GET Range:bytes=0-0
    // 2s 没收到响应头 → 连接已黑洞 → 自摘出池
    // 收到了 → 通道活着，更新 last_used
}
```

**注意**：探活 stream 的 ResponseFuture 需要在 select! 里与 conn.poll 竞争，
否则 conn 不被 poll 时响应收不到。实现方式与现有 Ping 分支相同。

### 4. `src/server/upstream.rs` — store_h2 按类设上限

```rust
pub fn store_h2(ip: &str, up: H2Upstream) -> H2Upstream {
    let cap = max_conns_per_ip(host_class_of_owner(&up));
    // 会话域 cap=1（去重），内容域 cap=3（溢出另开的通道并存），其他 cap=3
    ...
}
```

### 5. `src/config.rs` — 常量变化

```rust
// 删除
pub const REUSE_WINDOW_SECS: u64 = 30;

// 新增
pub const PROBE_INTERVAL_SECS: u64 = 10;      // 内容域探活间隔
pub const PROBE_TIMEOUT_SECS: u64 = 2;        // 探活响应超时
pub const SESSION_PROBE_INTERVAL_SECS: u64 = 30; // 会话域 PING 间隔
pub const MAX_CONNS_CONTENT: usize = 3;       // 内容域同 IP 通道上限
pub const MAX_CONNS_SESSION: usize = 2;       // 会话域同 IP 通道上限
```

### 6. 测试更新

| 测试 | 变化 |
|---|---|
| `one_ip_one_channel_and_slot_filter` | 改为测试会话域 cap=1（owner 设为 github.com） |
| `content_ip_allows_multiple_channels` | 新增：内容域同 IP 两条并存 |
| `concurrent_hosts_never_share...` | 改为测试内容域并存（不再断言去重） |
| `evict_stale_removes_only_expired_idle_conns` | 删除（evict_stale 不存在了） |
| `session_pick_gates_on_ping_end_health` | 改为测试探活计时器驱动的 PING |
| `empty_entry_is_not_an_occupied_channel` | 改为测试 pool::get_or_build 的空条目处理 |
| 新增 `probe_detects_blackhole` | 测试：通道黑洞 → 探活发现 → 自摘 |
| 新增 `overflow_builds_additional_channel` | 测试：全部忙 → 另开通道 |

### 7. 文档同步

- `docs/GLOSSARY.md`：删批窗行，加探活行（内容域极小请求 / 会话域 PING）
- `docs/ROUTING.md`：第④节按新架构重写
- `docs/ARCHITECTURE.md`：通道生命周期描述更新
- `README.md`：连接复用描述更新

## 实施顺序

```
1. pool/mod.rs: 新增 get_or_build + serial_build + build_lock（不动现有代码）
2. upstream.rs: ConnDriver 加探活 + store_h2 按类设 cap
3. mitm/mod.rs: get_direct 替换为 pool::get_or_build 调用
4. 删 evict_stale + REUSE_WINDOW_SECS + 旧 get_direct + try_cached
5. 测试更新 + 全绿
6. 编译部署
```

每步做完跑 `cargo test`，绿了再做下一步。

## 风险与缓解

| 风险 | 缓解 |
|---|---|
| 探活 stream 在 select! 里与 conn.poll 竞争 | 参照现有 Ping 分支的实现模式 |
| 内容域多通道并存导致连接数暴涨 | MAX_CONNS_CONTENT=3 上限 + 批窗清理改探活清理 |
| 建造机器人并发雷群 | per-host build_lock + 双检 |
| 探活本身被 GFW 识别 | 1 字节 Range 是正常 HTTP 请求，与真实流量无异 |
| 迁移期间新旧机制并存 | 一次性切换，不做双轨 |

## 不做的事

- 不做"隐藏动态路由"——keeper::pick 的占用率 × 延迟打分 + 死亡退避逐 IP 记账
  已经覆盖了动态路由的需求，加一层是重复
- 不做 PING 探活内容域——PING 帧被 GFW 放行但数据被丢，探不了黑洞
- 不做自适应探活频率——固定 10s 起步，有数据再调
