# GitPort GitHub 路由表（实测版）

> 2026-10-19 实测。方法与原始数据见文末「实测方法与局限」。
> 代码唯一真相：`src/pool/route.rs`（总路由 + 池内族表）、`src/config.rs`（GROUPS / DIRECT_HOSTS）、`src/webui.rs`（PAC 生成）。
> 本文每行「实测」列均为当日对**运行中的代理**（127.0.0.1:7810，新二进制，MITM 开）的真实请求结果，日志佐证取自 `/api/logs`。

---

## 0. 总览：一条请求的四层决策

```
浏览器
  │  ① PAC（webui.rs pac_script）——池内域名 → PROXY 127.0.0.1:7810；白名单/其余 → DIRECT
  ▼
代理 7810
  │  ② master_route（route.rs）——System / Mirror / Pool{池,族} / Tunnel
  ▼
  │  ③ 池内族路由（route.rs POOL_ROUTES）——按 host 选族，按 IP 末段 + SNI 形态筛条目
  ▼
  │  ④ 兜底（Fallback）——族全灭后：content → 镜像链 → 系统 DNS 腿；其余 → 系统 DNS 腿
  ▼
上游（GitHub 边缘 / 镜像站 / 系统 DNS）
```

一句话版：**PAC 决定谁进代理；master_route 决定进代理后直连还是镜像；族路由决定用哪些 IP；兜底决定全灭之后找谁。**

---

## 1. 第一层：PAC（浏览器 → 代理 or 直连）

PAC 由工作台按开关实时生成（`GET /proxy.pac`）。判定顺序：**直连白名单先行**（会被 `*.githubusercontent.com` 通配符误吞，必须最先短路）→ 池内域名 → 其余 DIRECT。

| 域名形态 | PAC 决策 | 实测（node 跑线上真实 PAC，26 个主机） |
|---|---|---|
| `github.com` 及子域（gist / codeload / api 精确匹配优先） | PROXY 127.0.0.1:7810 | ✅ github.com / gist.github.com / codeload.github.com / api.github.com 全 PROXY |
| `*.githubapp.com`、`*.githubassets.com`、`*.github.io`、`*.githubusercontent.com` | PROXY | ✅ githubapp.com / api.githubapp.com / github.githubassets.com / github.io / octocat.github.io / raw+avatars+camo+objects+release-assets+media+user-images+private-user-images.githubusercontent.com 全 PROXY |
| `objects-origin.githubusercontent.com`（上传落点） | **DIRECT**（白名单） | ✅ DIRECT——且确实先于通配符短路，没被 `*.githubusercontent.com` 吞掉 |
| `uploads.github.com` | **DIRECT**（白名单） | ✅ DIRECT |
| `viewscreen.githubusercontent.com`（mermaid 渲染） | **DIRECT**（白名单） | ✅ DIRECT |
| 其余一切（example.com、githubstatus.com、fastly.com…） | DIRECT | ✅ |
| 边界：notgithub.com / xgithub.com / evilgithub.com / github.com.evil.com | DIRECT（不误吞） | ✅ 四个边界主机全 DIRECT |

> 注：池内条目实际返回 `PROXY 127.0.0.1:7810; DIRECT`——代理不可达时浏览器自动回落直连的保险链（2026-10-19 晚复核确认，不应视为路由偏差）。

**白名单为什么存在**（2026-10-17 逐 IP 实测的结论）：objects-origin 只由 GLB 族（140.82.11x.21/.22）服务，主站网页边缘对它一律 301 且无 CORS 头——走代理会把网页上传弄死；uploads 是 API 式上传源站；viewscreen 走代理真名 SNI 拨 .133 被 GFW 间歇掐断，浏览器直连反而"一进仓库就出图"。

---

## 2. 第二层：总路由 master_route（进代理之后）

判定顺序同样有硬约束：**白名单 → 镜像 only（GET/HEAD）→ 池 → 非池（Tunnel）**。

| host | 方法+路径 | 路由 | 实测结果 |
|---|---|---|---|
| objects-origin / uploads / viewscreen | 任意 | **System**（PAC 已 DIRECT，双保险） | ✅ 强制打代理 = 纯 TCP 隧道走 system-dns：405 / 302 / 404（各自 vhost 的真实响应，`[CONNECT] ... via system-dns`） |
| `codeload.github.com` | GET/HEAD 任意路径 | **Mirror** | ✅ 200（Range 206，`via cdn.gh-proxy.org`） |
| `release-assets.githubusercontent.com` | GET/HEAD 任意路径 | **Mirror** | ✅ 路由正确：无效 URL（/x）11 家镜像全试后 502，**不回落直连**（设计如此） |
| `objects.githubusercontent.com` | GET/HEAD 任意路径 | **Mirror** | ⚠️ 单测覆盖；e2e 同上形态（release-assets 域直连） |
| `github.com` | GET `/releases/download/<tag>/<asset>` | **Mirror** | ✅ 206 + `content-range: bytes 0-1023/4898992`，日志 `归属链 release-assets…（不用 github.com 自己的链）` |
| `github.com` | GET `/releases/latest/download/<asset>` | **Mirror** | ✅ 200 + `content-length: 132855191`，同样归属 release-assets 链（2026-10-19 补的漏洞，漏了它会落 core 直连） |
| `github.com` | GET `/archive/…`（源码包） | **Mirror** | ✅ 200，日志 `归属链 codeload.github.com` |
| `github.com` | **POST** `/releases/download/…` | **Pool core**（不镜像） | ✅ 422 + `x-gitport-route: direct` via 140.82.121.3——附件路径只对 GET/HEAD 镜像 |
| `github.com` | GET `/releases`（页面本身） | **Pool core** | ✅ 200 direct——只拦下载，不拦页面 |
| `github.com` 其余路径 | GET/HEAD | **Pool core** | ✅ 200 direct via 140.82.121.3 |
| `api.github.com` | 任意 | **Pool api** | ✅ 200 via **140.82.114.6**（API 专用边缘 .5/.6，与 core 的 .3/.4 互斥——两族按 IP 分服务，落错返 404/301） |
| `*.githubusercontent.com` | GET/HEAD | **Pool edge/content** | ✅ 见第 3 节 |
| `*.githubassets.com` | 任意 | **Pool edge/assets** | ✅ 见第 3 节 |
| `*.github.io` | 任意 | **Pool edge/io** | ✅ 见第 3 节 |
| `githubapp.com` 系 | 任意 | **Pool edge/auth** | ✅ 见第 3 节 |
| 非池域名 | 任意 | **Tunnel**（PAC 已 DIRECT，永不达代理；此分支是强制代理时的兜底） | 代码级 |

---

## 3. 第三层：池内族路由（edge 是重点）

core/api 各一个通配族；edge 四族。族 = **host 判据**（这个 host 归哪族）+ **条目判据**（哪些 IP 条目有资格服务它）。不对口不试不垫底——否则每类请求都把另一族 IP 试败沉底。

| 池 | 族 | host 判据 | 条目判据（IP 末段 / SNI 形态） | 全灭兜底 | 实测佐证 |
|---|---|---|---|---|---|
| core | all | 全部 | 非 Fastly 段 + 伪装 SNI | Dns | ✅ github.com/ → 140.82.121.3（core 网站边缘） |
| api | all | 全部 | 非 Fastly 段 + 伪装 SNI | Dns | ✅ api.github.com/ → 140.82.114.6 |
| edge | **content** | `*.githubusercontent.com` | **Fastly `.133` + 伪装 SNI**（2026-10-19 晚切换，默认证书 SAN 覆盖全系） | **MirrorDns**（先镜像链后 DNS 腿） | ✅ avatars → 185.199.110.133；raw 直连被 GFW RST 后走镜像（见第 4 节） |
| edge | **assets** | `*.githubassets.com` | Fastly `.154` / `.215` + 伪装 SNI | Dns | ✅ githubassets → 185.199.**108.154**（CSS/JS 200，root 404） |
| edge | **io** | `*.github.io` | Fastly `.153` + 伪装 SNI | Dns | ✅ octocat.github.io → 185.199.**108.153**，200 |
| edge | **auth** | `githubapp.com` 系；**兼 edge 未列族 host 的兜底族** | 非 Fastly 段 + 伪装 SNI | Dns | ✅ githubapp.com → **140.82.112.29**（非 Fastly），200 |

**实表快照**（当日 `/api/pools`，plans.json 演化值）：

| 池 | 条目数 | 构成 |
|---|---|---|
| core | 25 | 140.82.11x 网站边缘（.3/.4）+ Azure 20.x / 4.x / 172.x GLB 族 |
| api | 6 | 140.82.112-114 的 .5/.6（API 专用边缘） |
| edge | 19 | Fastly 12 条（.133×1 独苗 110.133 真名；.153×4、.154×4、.215×4 伪装）+ 非 Fastly 6 条（140.82.112-114.29/.30，auth 族） |

> 13 个实测死 IP 已退役不在表内（core 115/117-120 段 .3/.4；edge 108/109/111.133）。110.133 时通时断，留作 content 独苗。

---

## 4. 第四层：兜底与熔断

| 机制 | 规则 | 当日实测 |
|---|---|---|
| content 族全灭 | → 镜像链（host 有链才走，11 家串行逐家试）→ 系统 DNS 腿 | ✅ **实地触发**：raw.githubusercontent.com 直连 `TLS 握手失败 10054`（GFW 按域 RST）→ 全灭 → `via axisnow.gh-proxy.org 头 742ms` 拿到 README |
| 内容域直连熔断 | 该 host 直连失败一次，**120s** 内跳过直连直接走镜像 | ✅ **实地触发**：raw 第二次请求无任何直连尝试，83ms 直达镜像（省掉每次 4s 黑洞预算） |
| assets / io / auth / core / api 全灭 | → 系统 DNS 直连腿（按系统解析拿当下有效边缘，IP 漂移自愈） | ⚠️ 代码级+单测，当日未实地触发（需要整族死亡） |
| 镜像链全灭熔断 | 一条链整链烧完，**60s** 内同链请求快速失败 | ✅ **意外实地触发**：测试把一个无效 URL 打穿 release-assets 整链后，20s 内同链的真实下载请求 1.5s 快速失败（日志 `镜像链全灭`，无逐家重烧） |
| 镜像 only 路由全灭 | **502，不回落直连** | ✅ release-assets 无效 URL：11 家全试（404/403/假页拒）后 502 |
| 凭据查询串防护 | 镜像 URL 带 `token`/`sig`/`x-amz-*` 等参数 → 拒走镜像（防私库 signed URL 外泄） | 代码级（`has_credential_query`） |

---

## 5. 镜像链归属表

**链归属与请求 host 解耦**：镜像跟随 302 是镜像在自己直连落点，"用谁的链"在请求发起前就定了。这是 2026-10-19 DevSidecar 下载风暴的根因修复——release 附件必须用 release-assets 专属链（头部实测 3838KB/s 的 gh-proxy 系），不能用 github.com 链（头部 ghproxy.net 慢且中断）。

| 请求 | 归属链 host | 链头（链位 1） | 当日实测 |
|---|---|---|---|
| `github.com/…/releases/download/…` 与 `…/releases/latest/download/…` | release-assets.githubusercontent.com | **gh-proxy.org** | ✅ 日志 `归属链 release-assets…` + `via gh-proxy.org`（v3.5.1 zip 206 头 1900ms；DevSidecar latest 200 头 563ms） |
| `github.com/…/archive/…` | codeload.github.com | **cdn.gh-proxy.org** | ✅ `归属链 codeload.github.com` + `via cdn.gh-proxy.org 头 673ms` |
| codeload.github.com 域自身 | 自身 | cdn.gh-proxy.org | ✅ `via cdn.gh-proxy.org 头 1172ms` |
| release-assets.githubusercontent.com 域自身 | 自身 | gh-proxy.org | ✅ 路由正确（无效 URL 全灭见第 4 节） |
| objects.githubusercontent.com 域自身 | 自身 | v6.gh-proxy.org | 链表在位，未实地请求 |
| raw.githubusercontent.com | 自身 | **axisnow.gh-proxy.org** | ✅ 实测 `via axisnow 头 742ms`（GFW 窗口期） |
| avatars / media / user-images / gist / github.com | 自身 | v6 / v4 / gh-proxy.com / ghproxy.net | 链表在位；avatars 走直连快路径未触发链 |
| camo.githubusercontent.com | **无链**（9 个 host 有链，camo 不在内） | — | ✅ 直连通（403=URL 无效但 .133 边缘响应）；若直连全灭只走 DNS 腿，无镜像可落 |

> 内容域小文件（头像/图片/gist/media）镜像链限长前 5 家串行；大文件域与 github.com 归档/release 用全链 11 家。

---

## 6. 实测方法与局限

**方法**（全部对运行中的活实例，非单测）：

1. **PAC 层**：拉线上实时生成的 `http://127.0.0.1:7811/proxy.pac`，用 node 对其 `FindProxyForURL` 跑 26 个主机（18 池内 + 3 白名单 + 5 边界/非池）。
2. **路由层**：curl 打 `127.0.0.1:7810`，每个用例记录 `x-gitport-route` / `x-gitport-upstream` 响应头 + HTTP 状态 + 耗时；同时用 `/api/logs?after=<seq>` 抓该用例的日志切片（串发/族/归属链/兜底/熔断佐证）。
3. **代码级**：`cargo test` 40 个测试（含 master_route 全主机矩阵、族筛选、链归属、退休 IP 快照）。

**局限（没测到的，说清楚）**：

- 本机 curl 无 h2 支持，实测连接全是 h1（日志 `alpn=http/1.1` 行可见）；浏览器页面连接走 h2（用户实例日志 `alpn=h2` 佐证），IDM 下载走 h1（上次排查结论）。协议选择本身不影响路由结论。
- DNS 兜底腿**成功**的路径未实地触发（需要 assets/io/auth 整族死亡）。
- objects 域自身的镜像 e2e 未做（无法构造有效 signed URL；带凭据的 signed URL 按设计拒绝走镜像）。
- ~~Tunnel 分支的真实请求未出现~~ **2026-10-19 晚已实地触发**：强制经代理访问 example.com → 200 直通，响应无诊断头（端到端 TLS 隧道无法注入，属预期形态）。
- core/api 的「网站 IP 落 api 返 301」互斥现象本次只验证了各自命中正确边缘（114.6 vs 121.3），未构造落错场景。

---

## 7. 附：本次实测关键日志摘录

```
# content 族全灭 → 镜像兜底（MirrorDns 生效）
[10:33:45] [串发] raw.githubusercontent.com edge/content 全灭(1/1 候选, 累计 "TLS 握手失败 ... (os error 10054)"), 不冷却(有镜像兜底)
[10:33:45] [镜像拨号] axisnow.gh-proxy.org TLS 467ms alpn=h2
[10:33:46] [镜像] raw.githubusercontent.com/torvalds/linux/master/README via https://axisnow.gh-proxy.org (链位 1/11, 头 742ms)

# 内容域直连熔断 120s（第二次请求跳过直连）
[10:33:53] [镜像] raw.githubusercontent.com/... via https://axisnow.gh-proxy.org (链位 1/11, 头 83ms)   # 无串发行 = 熔断中直连未试

# release 附件链归属（f605eec 修复生效）
[10:40:46] [镜像] github.com/git-lfs/git-lfs/releases/download/v3.5.1/...zip 归属链 release-assets.githubusercontent.com（不用 github.com 自己的链）
[10:40:46] [镜像] ... 客户端 Range: bytes=0-1023                                    # 6151063 新增诊断行
[10:40:48] [镜像] ... via https://gh-proxy.org (链位 1/11, 头 1900ms)

# /releases/latest/download 也是镜像（曾是直连漏洞）
[10:40:52] [镜像] github.com/docmirror/dev-sidecar/releases/latest/download/DevSidecar-...exe 归属链 release-assets.githubusercontent.com
[10:40:53] [交付] github.com/.../releases/latest/download/DevSidecar-...exe 推了(0B/132855191B)后连接终止(客户端关闭或响应被弃)
          # 6151063 交付计数诊断：此为 HEAD 请求的假阳性（HEAD 本就无体），324faa6 已修——
          # HEAD 不再包计数体；GET 的真中断照常记录，与 IDM 连接关闭同形态一眼可判
```

---

## 8. 复查发现的已知边界（非路由错误，登记在案）

1. **HEAD 假阳性（已修，324faa6）**：交付计数体最初不区分 HEAD，HEAD 大文件请求会误报 `推了(0B/N)后连接终止`。HEAD 响应本就无体、hyper 弃体不轮询，Drop 逻辑误判为客户端中断。已修：HEAD 不包计数体，GET 真中断照常记录。
2. **裸域 PAC/路由不一致（无实际影响，不动）**：`githubassets.com` 与 `githubusercontent.com` 两个**裸域**（无子域）在 PAC 的 `fpMatch` 里 `h === d` 精确命中 → 送进代理；但代理内 `pool_for` 的通配符卡点号边界不认裸域 → 判 Tunnel（纯隧道直通）。这两个裸域没有业务、浏览器永远不会请求它们；即使被强制请求，纯隧道也能通，只是不走池/MITM。真实业务域的裸域（github.com / api.github.com / githubapp.com / github.io）两边判定一致。
3. **退役 IP 日内波动（2026-10-19 晚）**：185.199.108/109/111.133 当日午后两测 TCP 死、晚测复活且 raw 出 200——属封锁窗口假死而非真死。RETIRED_IPS 退役名单机制已据此整体删除（名单会覆盖文件数据，与数据驱动相悖）：IP 死活全凭串发实测动态裁决，死时自动垫底、活时自动置顶。140.82.115-120 段当日三测仍 TCP 死，不建议手写入表。另：web 族对其余 vhost 一律 301 重定向（接得住不交付），唯一全服务 IP 为 140.82.113.22；`.9` 段 codeload 专用边缘族为本次测绘新发现，详见 CONFIG.md 认 IP 速查。

---

*实测时间：2026-10-19 10:33-10:41（UTC+8）。代理：dist 新二进制（6151063），plans.json core 25 / api 6 / edge 19，镜像链 9 host × 11 家。*
