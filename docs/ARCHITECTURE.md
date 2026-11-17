# 技术文档

面向要读这份代码的人：先看结构，再看数据流，最后看每张文件表。

> 行号会随代码漂移，文档里的引用以文件与函数名为准。

---

## 1. 模块关系

```mermaid
flowchart LR
    subgraph 进程入口
        MAIN[main.rs]
    end
    subgraph 配置与桌面
        SET[settings.rs]
        LOG[logger.rs]
        WEB[webui.rs]
        DESK[desktop.rs]
        FSX[fsx.rs]
    end
    subgraph 代理服务
        SRV[server/mod.rs]
        PROTO[server/protocol.rs]
        UP[server/upstream.rs]
        ST[server/status.rs]
    end
    subgraph 解密与纠错
        MITM[server/mitm/mod.rs]
        SWB[server/mitm/switchboard.rs]
        MIR[server/mitm/mirror.rs]
        DSP[server/mitm/direct_split.rs]
        MRG[server/mitm/merge.rs]
        PC[server/mitm/page_cache.rs]
        AST[server/mitm/asset_store.rs]
        DEF[server/mitm/defuse.rs]
        QUIET[server/mitm/quiet.rs]
        RM[server/mitm/redirect_memo.rs]
    end
    subgraph 选路与通道
        ROUTE[pool/route.rs]
        EDGES[pool/edges.rs]
        POOL[pool/mod.rs]
        DIAL[pool/dial.rs]
        LAT[pool/latency.rs]
        SPD[pool/speed.rs]
    end
    subgraph 其他
        CA[certgen.rs]
        WIN[winsec.rs]
        UTIL[util.rs]
    end

    MAIN --> SET
    MAIN --> LOG
    MAIN --> CA
    MAIN --> SRV
    MAIN --> WEB
    MAIN --> DESK
    SRV --> ROUTE
    SRV --> UP
    SRV --> MITM
    MITM --> SWB
    MITM --> PC
    PC --> AST
    SWB --> MIR
    SWB --> DSP
    SWB --> DEF
    MIR --> MRG
    DSP --> MRG
    UP --> POOL
    POOL --> DIAL
    POOL --> EDGES
    POOL --> ROUTE
    POOL --> LAT
    POOL --> SPD
    SET --> WIN
    CA --> WIN
    WEB --> SET
    DESK --> SET
```

`util.rs` 是最底层（日志回调、毫秒时间、锁自愈），不依赖任何业务模块；`protocol.rs` 是两个子系统的公共类型（`BoxBody`、请求预算），让 `mitm` 与 `upstream` 不必互相引用实现。

## 2. 启动时序

```mermaid
sequenceDiagram
    autonumber
    participant U as 用户/系统
    participant M as main
    participant S as settings
    participant P as pool
    participant C as certgen
    participant R as server
    participant W as webui
    participant D as desktop

    U->>M: 启动（可选 -port/-webui/-tray/-headless）
    M->>M: 单实例判定（已有实例则 POST /api/show 唤窗口）
    M->>M: 切工作目录到 exe 目录，建 .cache
    M->>S: load() 读 settings.json
    M->>P: serial_load() 装 routes.json
    M->>C: load_or_generate() 载/建 CA（ACL 失败则禁用 MITM）
    M->>R: start_proxy_with() 绑定 127.0.0.1:7810
    M->>S: ensure_system_proxy()（开关全关时是 no-op）
    M->>W: 起工作台 127.0.0.1:7811
    alt -headless
        M->>M: park 住，不起窗口
    else 正常
        M->>D: run() 起 tao 窗口 + wry WebView2 + 托盘
    end
    Note over M: 退出时：save_routes_now() → remove_system_proxy() → stop_proxy()
```

## 3. 一次请求怎么分流

```mermaid
flowchart TB
    A[客户端 CONNECT] --> B{命中 routes.json?}
    B -- 否 --> C{端口 443?}
    C -- 否 --> C1[502 拒绝]
    C -- 是 --> C2[透明隧道<br/>真名 + 系统 DNS<br/>bogon 过滤]
    B -- 是 --> D{MITM 开关?}
    D -- 关 --> E[CONNECT 隧道<br/>按路由表选 IP<br/>会话域串发 / 内容域 TCP 竞速]
    D -- 开 --> F[本地终结 TLS<br/>CA 签发叶子证书]
    F --> G[switchboard 按 URL 分诊]
    G -- big / 附件 --> H[mirror_or_direct<br/>直连腿 + 镜像腿 ECT 竞速]
    G -- 静态资源白名单 --> I[direct_split<br/>多段 Range 并发]
    G -- 其余 --> J[get_direct<br/>通道池 + 建连]
    H --> K[merge 按偏移合成单条流]
    I --> K
    J --> K
    K --> L[回写客户端]
    L --> M[page_cache 落盘<br/>仅 github.com HTML 列表页]
```

分诊的"谁去哪个科室"只写在 `server/mitm/switchboard.rs`；`mitm/mod.rs` 只管缓冲与响应善后（缓存失效、写路由）。这是刻意的分层。

## 4. 路由表是一张二部图

```mermaid
graph LR
    subgraph IP 节点
        N1["140.82.112.3<br/>sni=空 verify=github.com"]
        N2["185.199.108.154<br/>sni=空 verify=githubassets.com"]
        N3["20.205.243.165<br/>sni=空"]
    end
    subgraph 路由键
        H1["github.com"]
        H2["*.github.com"]
        H3["objects.githubusercontent.com<br/>content+big"]
        H4["api.github.com<br/>session"]
    end
    N1 --> H1
    N1 --> H2
    N2 --> H3
    N3 --> H3
    N1 --> H4
```

- 边 = 节点 `hosts` 列表里出现该键。**没有边就不能服务**，这是数据约束，不是运行时判断。
- `session` 键（`github.com`、`*.github.com`、`api.github.com`）走"固定同一 IP、不开第二条通道"。
- `content`/`big` 键可竞速、可切片、可挂镜像链。
- `direct` 键不进代理，直接进 PAC 的 DIRECT 名单。

边还带状态：`pool/edges.rs` 存 `(ip, 域名键) → 冷却到期时刻`，三档冷却（421/证书不匹配 4 小时、超时 120 秒、风控页 600 秒），风控冷却只能到期自愈。

## 5. 通道池与拨号

```mermaid
sequenceDiagram
    autonumber
    participant Q as 请求
    participant POOL as pool::get_or_build
    participant CH as 通道池（按 IP）
    participant D as dial/boring
    participant H2 as h2 连接

    Q->>POOL: 要一条能服务该域名的通道
    POOL->>CH: cached_h2（会话域只认自己的，内容域可借共享）
    alt 有可用通道
        CH-->>POOL: 返回通道（按 在途/上限 占用率挑最闲）
    else 无可用
        POOL->>D: 串发选 IP（会话域）或 TCP 竞速（内容域）
        D->>D: TCP 1.15s → TLS 1.35s → h2 SETTINGS 5s
        D->>H2: 建连成功
        H2->>CH: store_h2（同 IP 已有则丢弃新拨的）
        CH-->>POOL: 返回通道
    end
    POOL-->>Q: 通道
    Q->>H2: 开流（流窗 1MB / 连接窗 4MB）
    H2-->>Q: 响应
```

通道生命周期：

```mermaid
stateDiagram-v2
    [*] --> 拨号中
    拨号中 --> 在池: 握手成功
    拨号中 --> 死亡退避: TCP/TLS/h2 失败
    在池 --> 在途: 开流
    在途 --> 在池: 流结束（在途归零）
    在池 --> 焚毁: 闲置 10 秒
    在途 --> 焚毁: 连接断开
    在池 --> 暂缓: 判黑（60 秒后由真实流量复验）
    暂缓 --> 在池: 到期
    焚毁 --> [*]
```

关键约束：**每 IP 恒 1 条通道**（会话域与内容域都是 1）；候选 IP 全占时不开溢出通道，骑在满载通道上排队，由 h2 服务端配额兜。

## 6. 镜像 + 切片 + 合并

```mermaid
sequenceDiagram
    autonumber
    participant C as 客户端
    participant SW as switchboard
    participant M as mirror_or_direct
    participant D as 直连腿（通道池）
    participant X as 镜像腿（1..5 家）
    participant G as merge

    C->>SW: GET 大文件/Release（可带 Range）
    SW->>M: 交给镜像科室
    M->>M: 按候选数等分区间（零重叠）
    M->>D: 段 1 直连
    M->>X: 段 2..n 各家并发（剥 Cookie/Auth/Referer/UA）
    D-->>G: 段数据 + 206 起点
    X-->>G: 段数据 + 206 起点
    G->>G: 校验 206 起点 == 请求起点、终点不越界
    G->>G: 慢段缩边界让位、断点续拉（连续 6 次无进展才判死）
    G-->>C: 按偏移拼成单条流
```

三条要说清的边界：

1. 合并层**只按偏移校验**，不比内容。
2. `split_even` 是等分零重叠，段可缩不可重叠。
3. 镜像链上限 5 家，硬错误降权 45 秒、超时降权 15 秒；全败才回落直连。

## 7. 失败分级

```mermaid
flowchart LR
    F1[流失败] --> A1[重试同通道 / 换段]
    F2[通道判黑] --> A2[暂缓 60s<br/>不杀在途流<br/>到期由真实流量复验]
    F3[边失败<br/>421 / 证书 / 风控页] --> A3[边冷却<br/>4h / 120s / 600s<br/>风控只到期自愈]
    F4[IP 失败<br/>TCP / TLS / h2] --> A4[死亡退避<br/>所有 host 串发跳过]
```

四层的区别在于"影响面"：流影响一次请求，通道影响一条 IP 上的所有键，边影响某个 (IP, 域名) 组合，IP 影响全部域名。混用会出两种事故——把抖动当死亡（永久踢掉好 IP），或把风控当成功（并发把冷却洗掉）。

## 8. MITM 的 TLS 面

```mermaid
sequenceDiagram
    autonumber
    participant B as 浏览器
    participant MI as 本地 MITM
    participant CA as GitPort Root
    participant GH as GitHub（按路由表选 IP）

    B->>MI: CONNECT github.com:443
    MI->>MI: 检查是否受管域名（否则 fatal alert）
    MI->>CA: 按 SNI 取/签叶子证书（365 天，358 天重签）
    MI-->>B: 出示叶子证书链（ALPN h2, http/1.1）
    B->>MI: h2 请求
    MI->>GH: boring 握手（伪装 SNI + verify 锚点）→ h2 开流
    GH-->>MI: 响应
    MI->>MI: 分诊 / 纠错 / 缓存
    MI-->>B: 回写
```

- 只为受管域名签发；SNI 不在表内直接 `ALERT_FATAL`。
- 会话票据与缓存禁用（schannel 的恢复票据与本服务端互操作会报 bad record MAC）。
- `ca.key` 权限收紧失败 → 删私钥、禁用 MITM，不降级硬跑。

## 9. 系统写入与还原

```mermaid
flowchart TB
    A[打开分流接管] --> B{当前 AutoConfigURL 是谁的?}
    B -- 用户自己的 --> C[备份原值到 settings.json]
    B -- 上次自己写的残留 --> D[不备份，直接覆盖]
    C --> E[写 PAC + 置 WinINet 标志位]
    D --> E
    E --> F[git: 备份 http.proxy/https.proxy<br/>写 6 个域的 sslCAInfo]
    F --> G[关闭开关 / 退出程序]
    G --> H{当前值 == 我们写的?}
    H -- 是 --> I[有备份则还原，无备份则 unset]
    H -- 否 --> J[不动（别家中途接管了）]
```

三条判定缺一不可：认出自己的（`lastPAC` 精确比较）、放过别人的（当前值不是自己写的就不动）、有备份优先还原。git 侧同理，只写 URL 作用域的键，不碰全局 `sslVerify`。

## 10. 目录结构与各文件职责

```
gitport-github/
├─ Cargo.toml              依赖与 release profile（fat LTO、strip）
├─ build.rs                Windows 资源（图标、版本信息）
├─ .cargo/config.toml      BoringSSL 构建约定（clang-cl / Ninja / nasm / 工具集路径）
├─ assets/
│   ├─ app.rc              资源脚本
│   └─ icon.ico            托盘与窗口图标
├─ tools/                  排障脚本（缓存检查、变体对比、计时探针），非基准测试
├─ docs/
│   └─ architecture.md     本文件
└─ src/
   ├─ main.rs              启动顺序、命令行参数、退出钩子
   ├─ config.rs            端口与全部超时/阈值常量、内容域域名表
   ├─ certgen.rs           本地 CA：生成/加载、叶子签发、装当前用户根
   ├─ settings.rs          开关持久化、PAC 接管/还原、git 接管/还原、自启、镜像注册表
   ├─ webui.rs             工作台：静态页、状态/日志接口、PAC 生成、开关接口
   ├─ desktop.rs           tao 窗口 + wry(WebView2) + 托盘、单实例 mutex
   ├─ logger.rs            环形日志（2000 条）+ crash.log / tray.log
   ├─ fsx.rs               原子写盘（临时文件 + rename）
   ├─ winsec.rs            ca.key / settings.json 的 DACL 收紧
   ├─ util.rs              LogFn、now_ms、锁中毒自愈
   ├─ pool/
   │   ├─ route.rs         二部图装载与键匹配、PAC 名单、master_route 分诊
   │   ├─ edges.rs         边状态机：(ip,键) 冷却
   │   ├─ mod.rs           取通道入口 get_or_build、串发/竞速、死亡退避、种子表
   │   ├─ dial.rs          TCP/TLS 握手执行器（boring：Chrome 指纹、SNI 与校验名解耦）
   │   ├─ latency.rs       建连延迟表（实测回流，落 routes.json）
   │   ├─ speed.rs         通道暂缓与换血账本（60s 复验、60s 重建冷却）
   │   └─ seeds.json       内嵌最小路由表（只做首启引导与补边）
   ├─ server/
   │   ├─ mod.rs           监听、CONNECT 分流、明文 HTTP、bogon 过滤、隧道
   │   ├─ protocol.rs      BoxBody/Incoming 类型与请求预算
   │   ├─ upstream.rs      h2 通道：池、配额、选路、请求/响应
   │   ├─ status.rs        30s 通道账本（在途/上限、暂缓剩余）
   │   └─ mitm/
   │       ├─ mod.rs       MITM 主流程：缓冲、善后、缓存失效、写路由
   │       ├─ switchboard.rs  URL 级分诊（唯一政策点）
   │       ├─ mirror.rs    镜像链、ECT 竞速、身份头剥除、失败降权
   │       ├─ direct_split.rs 直连多段（媒体白名单）
   │       ├─ merge.rs     段合并、让位、补发、偏移校验
   │       ├─ page_cache.rs 页面缓存（列表页/首页骨架 + 白名单 XHR；仓库页零转换直出，html 永不缓存）
   │       ├─ asset_store.rs githubassets 资产库（immutable 资产一存永逸，本地透明回放，时代中立）
   │       ├─ defuse.rs    风控页识别（403 restricted / 400 Whoa）与换 IP
   │       ├─ redirect_memo.rs 头像 302 记忆（6 小时 TTL）
   │       └─ quiet.rs     日志降噪（同 host 只留首条 / 按分钟聚合）
   └─ tests/               对齐各模块的单元与集成测试
```

## 11. 建议的读码顺序

1. `main.rs` → `config.rs`：先知道进程起来了什么、有哪些硬阈值。
2. `pool/route.rs` → `pool/mod.rs` → `server/upstream.rs`：路由图怎么变成一条连接。
3. `server/mod.rs`：CONNECT 的四条出口。
4. `server/mitm/mod.rs` → `switchboard.rs`：解密后按 URL 分诊。
5. `mirror.rs` → `direct_split.rs` → `merge.rs`：内容域的三件套。
6. `settings.rs`：系统写入与还原的判定（这里出错最容易被用户察觉）。
7. `certgen.rs` + `winsec.rs`：安全边界。

## 12. 改代码前必须知道的不变量

1. 每 IP 恒 1 条通道；会话域固定同一 IP、不开第二条。
2. 通道闲置 10 秒焚毁——这是替代探活的机制，不要加回探活。
3. 段合并只按偏移校验，不按内容；任何"镜像内容可信"的假设都不成立。
4. 镜像请求必须剥身份头（Cookie/Authorization/Referer/UA）。
5. 系统写入必须能认出"是不是自己写的"，否则还原会改坏用户配置。
6. CA 只为受管域名签发；ACL 收紧失败必须禁用 MITM。
7. 代理只绑 `127.0.0.1`；非受管域名只放行 443。
8. 风控冷却只能到期自愈，不能 `clear()`。
9. 仓库页 html 永不缓存且零转换直出；资产库逐 URL 回放、时代中立（URL 即内容指纹）——跨发版冻结/换装资产引用会让旧 JS 配新数据白屏（实测），禁止回加。

## 13. 改动影响面

| 想改 | 牵动 | 容易漏 |
| --- | --- | --- |
| 路由语义 | `pool/route.rs`、`routes.json` 兼容、PAC 名单 | `HostMeta`/`IpNode` 回写格式 |
| 通道策略 | `config.rs` 常量、`get_or_build`、`status.rs` | 常量是架构不是旋钮 |
| 镜像 | `mirror.rs` 校验与降权、`merge.rs` 段边界 | 新增信任假设必须同时给校验手段 |
| 缓存 | `page_cache.rs` 键与目录、清盘阈值；`asset_store.rs` 收录门 | 键含会话身份，跨账号串页是硬伤；禁止回加"html 缓存/引用冻结"（白屏教训，见 CACHE.md） |
| 系统写入 | `settings.rs` 备份/还原判定 | "只还原自己写的"不能松 |
| CA | `certgen.rs` 签发范围、`winsec.rs` ACL | ACL 失败必须禁用 MITM |
