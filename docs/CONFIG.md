# 高级配置

## settings.json 键位契约

位置固定：**exe 同目录**（与 routes.json 同级）。启动读一次，任一开关变更即整份重写。

```json
{
  "closeToTray": true,
  "mitm": true,
  "winRect": [641, 278, 1820, 1394],
  "githubPAC": true,
  "proxyBackup": "",
  "lastPac": "http://127.0.0.1:7811/proxy.pac",
  "workerMirrors": [],
  "lastIp": {
    "github.com": "140.82.121.3",
    "api.github.com": "20.200.245.245",
    "*.githubusercontent.com": "185.199.110.133",
    "*.githubusercontent.com_vice": "185.199.110.133"
  }
}
```

- `lastPac`：上次写进系统的 PAC 地址，用来区分“自己的残留”和别家同形态；手改无意义
- `workerMirrors`：自定义镜像注册表，工作台里增删镜像时维护。手改也认，三种写法都收：`["https://反代地址"]`（只写地址 = 默认启用）、`[{"url":"https://反代地址","on":true,"trusted":false}]`、单个字符串/对象（忘写数组括号也收）；键名写成 `worker_mirrors` 同样识别。只收 `https://` 开头且不含空格的地址，其余忽略；整段写坏只丢这一段，不影响其他开关。手写的启用镜像启动时会对齐进内存镜像链（**不重写 routes.json**）；只有界面保存才会按内存状态整份重写 settings.json

- `lastIp` 的键由 `pool::circle_keys()` 派生：每条非直连路由一把主键；**只有内容域再加 `_vice` 副键**（双通道各记各的起点），会话域固定单通道、不记副键。**顺序固定、不可调换**；写盘恒为全量键位，未驻留的写 `""`
- 旧版 `~2` 副键（0.5.4 及以前）读入时自动改名为 `_vice`，无需手工迁移
- `""` / 缺键 / 整段 `lastIp` 缺失，三者行为等价：该路由游标为空，冷启动串发从候选序 0 号位起步。写空串的唯一意义是让 schema 一眼看全、diff 稳定
- 手改容错：漏键 → 该键回默认；某字段类型写坏（如 `winRect` 写成字符串）→ **只回退该字段**，不连坐整份配置；`lastIp` 读兼容对象与 `[[k,v],…]` 数组两种形态（写只写对象）
- 布尔键缺失 = `false`；`winRect` 缺失或宽高小于 400×300 时按默认位置开窗

## routes.json 手改指南

v2 起是**二部图**：`hosts`（域名 → 开关位）× `ips`（IP 节点 → 伪装身份 + 服务哪些域名）。边只存一处（节点侧），"看 IP 知道支持谁、看 host 反查可用 IP"双向都成立。

```json
{
  "ips": [
    {
      "ip": "140.82.112-114.5-6",
      "sni": "baidu.com",
      "verify": "github.com",
      "hosts": ["api.github.com"],
      "latency": {"140.82.112.5": 188, "140.82.112.6": 201}
    },
    {
      "ip": "185.199.108.133",
      "sni": "baidu.com",
      "verify": "github.com",
      "hosts": ["*.githubusercontent.com"]
    }
  ],
  "hosts": {
    "*.githubusercontent.com": {"content": true, "fallback": "mirror"}
  },
  "mirrors_big": {
    "release-assets.githubusercontent.com": ["https://gh-proxy.com"]
  },
  "mirrors_small": {
    "raw.githubusercontent.com": ["https://gh-proxy.com", "https://ghfast.top"]
  }
}
```

**落盘顺序是 `ips` → `hosts` → `mirrors_*`**：先看出口，再看域名策略。`hosts` 块只写带属性的行——全是默认配置的域名（`{}`）不落盘，它们的域名由节点的 `hosts` 声明推出来，启动时自动补回。所以文件里只有一两行 `hosts` 是正常的，不代表其他域名没被代理。

- **hosts 行**（域名键）：`github.com` = 自己 + 任意级子域；`*.github.com` = 只认子域（裸域不命中）；多条同时命中取**最长的键**，不用操心书写顺序
  - `action: "direct"` 不进代理（缺省即进）；`content: true` 走内容域熔断与短响应预算；`fallback`：省略 = `dns`，`mirror` = 全灭后走镜像链
  - **PAC 名单 = 非 direct 行的路由键去 `*.` 的裸域名**，运行时派生、不落盘。`pac` 字段已经从数据结构里删掉，写了也不会读；想让某行不进 PAC，用 `action: "direct"`
- **ips 节点**：伪装身份与目标 host 解耦——`sni` 只骗墙（写放行域，如 baidu.com），`verify` 是证书校验锚点（只求证明"对面是真 GitHub"，写节点实际返回证书 SAN 内的域；留空 = 按目标 host 校验，兼容旧写法）。**业务路由全靠 h2 的 `:authority`，与 TLS 身份无关**——所以一条连接能服务多个 host，加域名 = 往某节点的 `hosts` 里添个键
  - `ip` 末段支持范围展开：`140.82.112-114.5-6` = 6 个 IP（多段范围做笛卡尔积，上限 64）
  - `latency` 键（WebUI「IP 建连测速」写入，不手改）：每个展开 IP 的建连毫秒数，失败项删旧值；串发候选按它升序换位（无值排最后）
  - 节点的 `hosts` 列表里写的是 **hosts 行的路由键**（不是逐个子域）
- **边状态机**（运行时实测，不落盘）：某 (IP, 路由键) 被服务端回 421 或 TLS 拒 → 该边长冷却（数小时）；请求超时 → 短冷却（2 分钟）；成功即清黑。全黑时该 host 走 fallback
- 旧格式仍能读（启动自动折算，原文件留 `.bak`）：0.5.4 的 `routes` 域名字典（`plans`/`realPlans`）、0.5.3 的 `routes` 数组 + `match` 正则、更早的三池 `core/api/edge`；`real`/`donor` 标志按 v2 语义处置（丢弃，原 real 域走伪装锚点）
- 镜像链分两个字典：`mirrors_big` = 大文件域（objects / release-assets，分片竞速），`mirrors_small` = 图片与文本资源域（raw / gist / avatars / user-images / media）；分类权在域名，条目放错字典启动时也会被归位
- **「自定义镜像」列表 = 镜像链的全部内容**（不是追加项）：手改进 routes.json 的条目重启后会被收编进列表，此后以列表为准；界面保存前会自动合并服务端最新清单，旧页面不会覆盖新收编条目
- 默认安装**不带任何镜像**（双字典为空）：小文件走直连兜底；大文件域无链时候选仅直连（伪装 SNI 直拨），直连也被阻断才 502——502 页面会指引补镜像
- 旧版单字典 `"mirrors"` 仍可读（启动自动按域名归类），下次落盘转为双字典
- 大文件域选谁不按链序硬排：代理按「预计最早下完」在镜像与直连之间动态分流（ECT 时间槽）；链序只决定失败时的顺延次序
- **物理顺序固定，拨号顺序不按表序**：文件里你怎么排就怎么存，程序不改你的顺序；但拨号时先从游标（上次驻留的 IP）起步，其余按 `latency` 实测升序试，没测过的垫底——想强制某条先试，把它写进游标或者跑一次测速
- 手改**重启生效**；启动只在 routes.json 缺失时才生成，**不再重写手改表**。运行时会写盘只有两种：点「IP 建连测速」落 `latency`、在工作台增删或启停镜像时同步镜像链——两种都会把表按内存状态整份重写（格式规范化）
- 表会自愈：缺节点/边时启动自动从内置种子补齐（只追加，不打乱你排的顺序）；池外镜像/未知 host 写了也会被剥掉
- 镜像链数据权威：**任何支持拼接的 https 镜像都可写**（含自部署），顺序 = 优先级；无白名单校验，坏镜像运行期自然失败沉底；缺链 host = 无镜像腿
- **内置种子是 `src/pool/seeds.json`**：编译进 exe，只在全新安装和「表缺节点/边」补缺时用到，一个 IP 一条记录。改它要重新编译发布版；平时手改请改 `dist/routes.json`，启动时不会被种子重写

## 认 IP 速查

条目放哪个段**不影响行为**——代码按 IP 末段路由，段只是容器：

| 看到这种 IP | 它是谁 | 干什么活 | SNI 形态 |
|---|---|---|---|
| `140.82.x.3` / `.4` | 主站边缘 | github.com 网页 | 伪装 |
| `140.82.x.5` / `.6` | API 专用边缘 | api.github.com（与网站 IP 互斥） | 伪装 |
| `140.82.x.29` / `.30` | 授权边缘 | githubapp.com 登录/OAuth 回调 | 伪装 |
| `20.205.243.161` | 上传源站（alambic） | uploads.github.com（v2 起进池，锚点 `githubusercontent.com`） | 伪装 |
| `20.x.x.x`、`4.237.x`、`172.182.x` 等杂段 | 主站边缘备选 | github.com 网页 | 伪装 |
| `185.199.x.133` | Fastly 内容边缘 | avatars / raw / gist / camo 等（锚点 `github.com` 宽证书） | 伪装 |
| `185.199.x.215` | Fastly 静态边缘（新） | githubassets 的 CSS/JS（锚点 `githubassets.com`） | 伪装 |
| `185.199.x.154` | Fastly 静态边缘（旧代，状态波动以实测为准） | githubassets / docs（锚点 `githubassets.com`） | 伪装 |
| `185.199.x.153` | Fastly Pages 边缘 | github.io / desktop / pages 等（锚点 `github.com` 宽证书） | 伪装 |
| `140.82.x.9`、`20.205.243.165`、`20.27.177.114` | codeload 专用边缘 | 源码包打包服务（v2 起 codeload 走主站池伪装通道） | 伪装 |
| `140.82.x.21` / `.22` | GLB 全服务族 | viewscreen / objects-origin / api.mcp（锚点 `actions.githubusercontent.com`） | 伪装 |
| `4.249.131.160` | Azure（Copilot 代理） | copilot-proxy.githubusercontent.com（锚点 `actions.githubusercontent.com`） | 伪装 |

> **v2 起白名单域全部转伪装**（2026-11-03 实测推翻"伪装会被上游判非法"）：`docs` / `support` / `resources` / `desktop` / `pages` / `skills` / `archiveprogram` / `socialimpact` / `raw.github.com` 在 Fastly 各段上伪装握手全通、HTTP 层零 421/403，TLS 身份（SNI+锚点）与目标 host 解耦，业务路由走 `:authority`。真名分片腿整体退役。

即：**末段 .3/.4 = 网页，.5/.6 = API，.21/.22 = GLB 全服务，.29/.30 = 授权；185.199 段看末段——.133 = 内容，.215 = 静态（新），.154 = 静态（旧），.153 = Pages**。此分工由边缘行为实测标定，routes.json 里的段位置改变不了它。

> 2026-10-19 晚全量测绘补充：① web 族（.3/.4 与 Azure 杂段）对其余 vhost 一律 301 正确重定向——接得住但不交付，不可当多面手使；**唯一的全服务 IP 是 140.82.113.22**（objects-origin 的 GLB 族，9/10 服务直出 200）。② Fastly 四段（.133/.153/.154/.215）服务互通：raw/avatars/io/assets 在四段上都有响应，按段分族是负载与历史划分，非服务边界。③ 伪装 SNI 在 .133 上亦出内容且**默认证书 SAN 覆盖 `*.githubusercontent.com`**（证书校验可过）——2026-10-19 晚 content 族已切换为伪装（当时真名反遭 RST）；若某窗口伪装失效，应急回退 = 手改 routes.json 该条 `"sni": "sni"`（关代理改，重启生效）。④ IP 退役清单机制已整体删除——死活全凭串发实测（失败沉底、成功置顶），routes.json 写什么就试什么，代码不再持有任何 IP 名单。

## 分流域名总表

| 流量 | 上游路径 |
|---|---|
| github.com 及其余子域（含 codeload） | 二部图池伪装串发 + gh_defuse（游标起点记忆） |
| api.github.com | api 专用边缘伪装串发 |
| uploads.github.com | 池伪装（alambic .161，锚点 `githubusercontent.com`） |
| viewscreen / objects-origin / api.mcp | GLB 池伪装（140.82.x.21/.22，锚点 `actions…`） |
| githubapp.com、githubassets、github.io | 池伪装串发 |
| avatars/camo/gist/raw 等内容域 | 池伪装 → 熔断后镜像链 |
| objects / release-assets | 镜像 + 直连分片竞速（直连占两份，ECT 时间槽派发） |
| github.com 的 `/releases/download`（含 latest） | release-assets 专属镜像链，全灭 502 |
| docs / support / resources / desktop / pages / skills / archiveprogram / socialimpact / raw.github.com | 池伪装（Fastly 段锚点制，原真名分片腿退役） |
| copilot-proxy.githubusercontent.com | 池伪装（Azure `4.249.131.160`） |
| 其余一切域名 | 系统 DNS 直连，不经任何表 |

详细判据与实测数据见 [路由表](ROUTING.md)。
