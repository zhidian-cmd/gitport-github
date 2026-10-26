# 高级配置

## settings.json 键位契约

位置固定：**exe 同目录**（与 plans.json 同级）。启动读一次，任一开关变更即整份重写。

```json
{
  "closeToTray": true,
  "mitm": true,
  "winRect": [641, 278, 1820, 1394],
  "githubPAC": true,
  "proxyBackup": "",
  "lastIp": {
    "core/all": "20.27.177.114",
    "api/all": "140.82.114.6",
    "edge/content": "185.199.110.133",
    "edge/assets": "185.199.108.154",
    "edge/io": "",
    "edge/auth": ""
  }
}
```

- `lastIp` 的 6 个键由 `pool::circle_keys()` 派生（`SERIAL_POOLS` × `POOL_ROUTES` 族表），**从上到下顺序固定、不可调换**；写盘恒为全量 6 位，未驻留的族写 `""`
- `""` / 缺键 / 整段 `lastIp` 缺失，三者行为等价：该族游标为空，串发从表序 0 号位起步。写空串的唯一意义是让 schema 一眼看全、diff 稳定
- 手改容错：漏键 → 该键回默认；某字段类型写坏（如 `winRect` 写成字符串）→ **只回退该字段**，不连坐整份配置；`lastIp` 读兼容对象与 `[[k,v],…]` 数组两种形态（写只写对象）
- 布尔键缺失 = `false`；`winRect` 缺失或宽高小于 400×300 时按默认位置开窗

## plans.json 手改指南

```json
{
  "core": [
    { "ip": "140.82.112.3", "sni": "baidu.com" },
    { "ip": "20.205.243.166" }
  ],
  "api":  [ { "ip": "140.82.112.5", "sni": "baidu.com" } ],
  "edge": [ { "ip": "185.199.108.133", "sni": "sni" } ],
  "mirrors": {
    "raw.githubusercontent.com": ["https://gh-proxy.com", "https://ghfast.top"]
  }
}
```

- 条目顺序 = 优先级，第一行是表头；**`sni` 原样透传进 TLS 握手，代理不解释**：带点域名 = 伪装（SNI=所写值，哪怕碰巧写真名）；`""` = 无 SNI（ClientHello 不带扩展）；要真名就把 host 名写进 sni。非法字符（防注入）该条剥除
- **表序固定、运行时零重排**：串发从 settings.json 记忆的游标（上次驻留 IP）起步，沿表顺序转圈——成功驻留、失败沿圈前进（dead 表跳过死位）；想让某条先被试，把它排到前面即可。运行时唯一写盘 = 故障转移时 settings.json 里几字节的游标更新
- 手改**重启生效**；运行中的轮换 2 秒内自动写回（手改请先关代理，避免被写回覆盖）
- 表会自愈：缺池/缺新边缘 IP 时启动自动从内置种子补齐（只追加尾部，不打乱你排的顺序）；池外镜像/未知 host 写了也会被剥掉
- 镜像链数据权威：**任何支持拼接的 https 镜像都可写**（含自部署），顺序 = 优先级；无白名单校验，坏镜像运行期自然失败沉底；缺链 host = 无镜像腿
- **seeds.json 是生成物**：plans.json 的全量快照（池 + 镜像链），仅用于全新安装引导和补缺，**勿手改**——更新方式 = 停代理后用调好的 plans.json 覆盖它

## 认 IP 速查

条目放哪个段**不影响行为**——代码按 IP 末段路由，段只是容器：

| 看到这种 IP | 它是谁 | 干什么活 | SNI 形态 |
|---|---|---|---|
| `140.82.x.3` / `.4` | 主站边缘 | github.com 网页 | 伪装 |
| `140.82.x.5` / `.6` | API 专用边缘 | api.github.com（与网站 IP 互斥） | 伪装 |
| `140.82.x.29` / `.30` | 授权边缘 | githubapp.com 登录/OAuth 回调 | 伪装 |
| `20.205.243.161` | 上传源站（alambic） | uploads.github.com（直连白名单，代理不拨它） | — |
| `20.x.x.x`、`4.237.x`、`172.182.x` 等杂段 | 主站边缘备选 | github.com 网页 | 伪装 |
| `185.199.x.133` | Fastly 内容边缘 | avatars / raw / gist / camo 等 | 伪装（2026-10-19 晚起，原真名） |
| `185.199.x.215` | Fastly 静态边缘（新） | githubassets 的 CSS/JS | 伪装 |
| `185.199.x.154` | Fastly 静态边缘（旧代，状态波动以实测为准） | 同上 | 伪装 |
| `185.199.x.153` | Fastly Pages 边缘 | github.io 站点 | 伪装 |
| `140.82.x.9`、`20.205.243.165`、`20.27.177.114` | codeload 专用边缘 | 源码包打包服务（GitPort 走镜像，直连腿未启用；2026-10-19 测绘发现） | 伪装 |
| `4.249.131.160` | Azure（Copilot 代理） | copilot-proxy.githubusercontent.com | **真名 + 分片**（wl_azure 族专用） |

> **白名单域名例外**：`docs` / `support` / `resources` / `desktop` / `pages` / `skills` / `archiveprogram` / `socialimpact` / `raw.github.com` 也落在上面这几个 Fastly 段，但它们**不用伪装**——走真名 SNI + ClientHello 分 3 片，由 edge 的 `wl*` 四族接管（见 [路由表](ROUTING.md) 第 3 节）。同一段 IP 被两组族共用，各按自己判据筛。

即：**末段 .3/.4 = 网页，.5/.6 = API，.29/.30 = 授权，.9 = codeload；185.199 段看末段——.133 = 内容（真名），.215 = 静态（新），.154 = 静态（旧），.153 = Pages**。此分工由边缘行为实测标定，plans.json 里的段位置改变不了它。

> 2026-10-19 晚全量测绘补充：① web 族（.3/.4 与 Azure 杂段）对其余 vhost 一律 301 正确重定向——接得住但不交付，不可当多面手使；**唯一的全服务 IP 是 140.82.113.22**（objects-origin 的 GLB 族，9/10 服务直出 200）。② Fastly 四段（.133/.153/.154/.215）服务互通：raw/avatars/io/assets 在四段上都有响应，按段分族是负载与历史划分，非服务边界。③ 伪装 SNI 在 .133 上亦出内容且**默认证书 SAN 覆盖 `*.githubusercontent.com`**（证书校验可过）——2026-10-19 晚 content 族已切换为伪装（当时真名反遭 RST）；若某窗口伪装失效，应急回退 = 手改 plans.json 该条 `"sni": "sni"`（关代理改，重启生效）。④ IP 退役清单机制已整体删除——死活全凭串发实测（失败沉底、成功置顶），plans.json 写什么就试什么，代码不再持有任何 IP 名单。

## 分流域名总表

| 流量 | 上游路径 |
|---|---|
| github.com 及其余子域 | core 池直连串发 + gh_defuse |
| api.github.com | api 池直连串发（API 专用边缘，与网站 IP 互斥） |
| uploads.github.com | **直连白名单**（DNS 直达 alambic .161） |
| viewscreen.githubusercontent.com | **直连白名单**（mermaid 渲染） |
| githubapp.com、githubassets、github.io | edge 池直连串发 |
| avatars/camo/gist/raw 等内容域 | edge 直连优先 → 熔断后镜像链 |
| codeload / objects / release-assets | 镜像 only |
| github.com 的 `/archive`、`/releases/download`（含 latest） | release-assets / codeload 专属镜像链，全灭 502 |
| objects-origin.* | **直连白名单**（该 vhost 仅 GLB 族服务，主站边缘对其 301 无 CORS） |
| docs / support / resources / desktop / pages / skills / archiveprogram / socialimpact / raw.github.com | **主路由白名单**：进 edge 池，真名 SNI + 首包分片；段内 IP 连不上自动换候选，全灭退回系统 DNS |
| copilot-proxy.githubusercontent.com | **主路由白名单**：同上，走 Azure `4.249.x` 段 |
| 其余一切域名 | 系统 DNS 直连，不经任何表 |

详细判据与实测数据见 [路由表](ROUTING.md)。
