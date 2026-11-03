# 连接池 v2 设计：IP 二部图 + 伪装统一建连

> 状态：**已实施**（2026-11-03）。游标副键后缀为 `_vice`；白名单分片腿（ClientHello 分片）随 real 标志一并退役。实测证据见 §8。

## 1. 动机

v1 连接按 host 隔离：池 key = 请求域名，证书校验名恒等于目标 host，复用被卡死在"该 IP 返回的证书必须覆盖目标 host"。跨 host 复用只剩 `borrow_donor` 借道兜底，还要背 borrowed/borrow_cool 一整套记账。

v2 把借道扶正为主干：**伪装是纯粹的建连手段，通道建好谁都能搭**——TLS 层身份与目标 host 彻底解耦，业务路由全靠 h2 `:authority`。

## 2. 一次伪装握手，三方视角

| 方方 | 看到什么 | 说明 |
|---|---|---|
| 墙 | ClientHello 明文 SNI = baidu.com | 放行；目标域名不在任何明文里 |
| 本代理 | 对端证书 | 本地校验锚点（CA 链 + SAN），纯本地逻辑不上线 |
| 服务端 | 加密 h2 帧里的 `:authority` = 真实 host | GitHub 边缘按 Host 处理，不做证书匹配检查 |

推论：**SNI 永远用墙放行域**（github.com 的 SNI 会被干扰，绝不能当伪装值）；**校验锚点只求证明"对面是真 GitHub"**；两者都跟目标 host 无关。

## 3. 查询管线（五步）

```
① 收 host → ② 图推邻接 IP → ③ 滤黑边 → ④ 起点排序 → ⑤ 建连/复用
                                    │
                                    └─ 全黑 → fallback（镜像 / DNS）
```

- ⑤ 分叉：**热路径**（池里有活通道）EWMA 择优直接复用，` :authority` = 真实 host；**冷路径**（池空 / 重启后）从起点 IP 开始串发，成功驻留、失败前移，两个两个建通道（副键跳过主通道占用的 IP）
- 起点铁律：lastIp 是**排序建议不是直通卡**，必须先过 ②③ 两道关才准排最前——旧功臣不能绕过新实测的坏边

## 4. 路由表：二部图

落盘只存一个方向（IP→hosts），反向索引运行时构建，边永不双写。

```json
{
  "ips": [
    { "ip": "140.82.112-114.5-6", "sni": "baidu.com", "verify": "github.com",
      "hosts": ["github.com", "api.github.com", "codeload.github.com"] },
    { "ip": "185.199.108-111.133", "sni": "baidu.com", "verify": "raw.githubusercontent.com",
      "hosts": ["*.githubusercontent.com", "raw.github.com", "support.github.com"] }
  ],
  "hosts": {
    "github.com":              { "pac": "github.com", "fallback": "dns" },
    "*.githubusercontent.com": { "pac": "githubusercontent.com", "content": true, "fallback": "mirror" }
  }
}
```

- **属性分层**：`sni`（骗墙）/ `verify`（锚点）跟 IP 走；`real`/`content`/`fallback`/`pac` 跟 host 走
- **段展开**：`ip` 末段支持 `a-b` 范围（`140.82.112-114.5-6` = 6 节点，`185.199.108-111.133` = 4 节点），只做末段，解析三行
- **匹配语义保留**：`hosts` 里写的是路由键，裸键含子域、`*.` 仅子域、最长匹配胜——`hits()`/`rank` 原样平移
- **缺省即真**：host 没出现在任何 `ips[].hosts` 里 = 不走池（direct / 纯 real 域），不写 `pool: false`
- 运行时双索引：`ip → 节点`、`路由键 → [节点]`；WebUI 画二部图（IP 列 × host 列，坏边虚线）直接由索引合成

## 5. 边状态机（黑名单 = 边的坏态）

黑名单不单独建结构——每条边（ip ↔ 路由键）带状态和到期时间。

| 迁移 | 触发 | TTL |
|---|---|---|
| 活跃 → 拉黑 | **421** / TLS 握手拒 / 证书 SAN 不覆盖 | 长（数小时）——静态属性不会自愈 |
| 活跃 → 降权 | 拨号超时 / 连接断 | 短（几分钟）——网络波动 |
| 拉黑/降权 → 过期试探 | TTL 到 | — |
| 试探成功 | 回活跃，顺带清该边黑名单 | — |

**触发条件收窄（防误杀）**：只拉 421 和 TLS 层失败；**业务状态码 403/404/429 一律不碰**——那是 GitHub 在回答请求内容（私有仓库权限、rate limit），不是"这个 IP 不服务这个 host"。

## 6. 连接池重构

- **池 key：host → IP 节点**。通道的 TLS 身份统一（伪装 + 锚点），服务端视角"新建第一条"与"复用第一百条"不可区分——同 IP 同身份同 `:authority`
- 每 IP 节点两条连接，**一条连接混发多个 host 的流**（h2 协议原生允许）；一条 GOAWAY 打断多 host，靠双通道冗余 + 边状态机兜底
- EWMA 计速与 8 次一探索保留（v1 的 `ConnSlot` 逻辑平移）
- **退役清单**：`borrow_donor` + `borrowed`/`borrow_cool`/`borrow_poison` 记账、`DUAL_CONN_HOSTS` 白名单、`donor` 标志、`real` 标志（§8 实测推翻其存在理由；真名分片腿暂留 objects/release-assets，见 §9）

## 7. 起点记忆（settings.json `lastIp`）

- 格式不变：路由键两把钥匙（主 / `~2` 副键），值 = 上次成功的 IP，空串 = 未驻留
- 语义降级：从"串发驻留点"变为"**冷启动第一跳建议**"——热路径不消费它（EWMA 择优直接复用）
- 回写扩展：建连成功写回（v1 语义）+ **复用成功也回写**——起点跟着"最近功臣"漂移，重启恢复的是最近走通的 IP

## 8. 实测证据（2026-11-03）

方法：openssl s_client 伪装握手（SNI=baidu.com）+ 手工 HTTP/1.1 `Host:` 探测，本机直发。

**对照组**：140.82.121.3 + Host: github.com → 200 OK（脚本可信，基本盘确认）。

**real 腿 185.199.x 段**（v1 注释称"伪装会被上游判非法"）：

| IP | 返回证书 | Host 探测 |
|---|---|---|
| 185.199.108.153 / 110.133 | 宽证书：`*.github.com *.github.io *.githubusercontent.com` 六域 SAN | docs→404、desktop→301、raw.github→301、github.io→301 |
| 185.199.108.154 | 窄证书：仅 `*.githubassets.com` | —（v1 donor 注释的出处） |

**无一个 421/403 边缘拒绝**——"伪装判非法"被推翻，10 个 real 域可在伪装通道上服务。h2 层另有活体证据：v1 的 `borrow_donor` 本来就在生产中用窄证书连接改 `:authority` 服务内容域。

**direct 4 域 + copilot**：

| 域 | 解析 IP | 伪装证书 | Host 探测 |
|---|---|---|---|
| uploads.github.com | 20.205.243.161（CNAME alambic-origin） | *.githubusercontent.com | 302 |
| viewscreen.githubusercontent.com | 140.82.112.21（GLB） | *.actions.githubusercontent.com | 404 |
| objects-origin.githubusercontent.com | 140.82.114.21（GLB） | 同上 | 405（GET 不允许，正常） |
| api.mcp.github.com | **140.82.113.22（已在 github.com plans 里！）** | 同上 | **200** |
| copilot-proxy.githubusercontent.com | 4.249.131.160（Azure） | 同上 | 404 |

结论：被排除的 14 个域全部可进池；`real` 的存在理由不成立；direct 域不是"不能进"是旧架构懒得包容。

## 9. mirror 缩编

- **迁池**：codeload、raw/avatars/user-images/media 等内容域 → 走二部图伪装通道
- **保留 mirror 职责**：大文件分片竞速（objects / release-assets 302 落点）——多 IP 并行拉大文件，伪装单通道串流反而慢
- **待测**：objects / release-assets 是真 CDN（SNI 路由型），伪装大概率废，真名分片腿暂时保留给它们

## 10. 迁移计划

1. 新表落盘（文件名实施时定，建议沿用 routes.json + `.bak` 兼容惯例）；旧格式首启折算
2. `seeds.json` 102 条 plan 机械换算成 ip 节点 + hosts 边；sni 全线 baidu.com 收进 `ips[].sni`
3. 连接池改造（key 换 IP 节点）→ 删借道记账 → 删 real/donor 标志
4. WebUI 路由页改画二部图（节点 = IP/host，边状态染色）
5. 分阶段：先并行跑（v2 管线仅接管非 mirror 流量），边状态机积累一周数据后再收编 mirror

## 11. 风险与待实测

| 风险 | 兜底 / 验证 |
|---|---|
| h2 `:authority` 混发的大规模行为（h1 探测是点状证据） | 边状态机：421 → 拉黑 → fallback，上线即自动积累 |
| 一条连接 GOAWAY 波及多 host | 双通道冗余 + h2 自动重试 |
| 黑名单全灭 | 路由表 fallback（镜像 / DNS），黑名单只剔边不接管 |
| objects / release-assets 伪装可行性 | 上线前单独探测；不通则真名腿永驻 |
| 上传场景（uploads POST 大包）行为 | 迁池后首周重点观察 |
| 各 IP 证书锚点校准 | `verify` 按 §8 探测结果逐 IP 落值，新 IP 上线先探测后入表 |
