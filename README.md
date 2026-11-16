# gitport-github

Windows 本地 GitHub 加速代理：按 `routes.json` 给 GitHub 系域名选 IP，可选 MITM 纠错，可选接管浏览器 PAC 与 git。

## 不做什么

- 不写系统 hosts，不写 `http.sslVerify=false`
- 不做全局代理：非 GitHub 域名只放行 443 隧道，其余一律 `502`
- 不缓存 `github.com` 的 html（仓库页走"骨架胚 + 每次真拉"，列表页按会话短存）；githubassets 的 js/css/字体入库一份本地透明回放
- 不给镜像下载做内容校验（见下文"镜像"）
- 不需要管理员权限

## 跑起来

```
gitport-github.exe [-port 7810] [-webui 7811] [-tray] [-headless]
```

| 参数 | 含义 |
| --- | --- |
| `-port` | 代理端口，默认 7810 |
| `-webui` | 工作台端口，默认 7811 |
| `-tray` | 启动即最小化到托盘 |
| `-headless` | 无窗口无托盘，只跑代理与工作台 |

代理与工作台都只绑 `127.0.0.1`。第二次启动不会重复起进程，会把已在运行的窗口唤出。

**首启的接管开关都是关的**：程序会起代理，但不动系统设置。要么在界面上打开开关，要么自己把软件代理指到 `127.0.0.1:7810`。

## 开关

| 开关 | 默认 | 打开后写什么 | 怎么撤 |
| --- | --- | --- | --- |
| 分流接管 | 关 | `HKCU` 的 `AutoConfigURL` → 本地 `proxy.pac`；同时接管 git 全局 `http.proxy`/`https.proxy` 与 6 个 GitHub 域的 `sslCAInfo` | 关开关或退出程序：只还原自己写的那条，别家的不动 |
| MITM | 关 | 把 `ca.crt` 装进**当前用户**受信任根 | 证书管理器里删除 `GitPort Root`；`ca.key` 在 exe 目录 |
| 关窗到托盘 | 关 | 关窗口不退出 | 关掉即可 |
| 开机自启 | 关 | `HKCU\...\Run` 一项 | 关掉即删 |

`ca.key` 权限收紧到当前用户；收紧失败会删掉私钥并禁用 MITM，不会降级硬跑。

## 配置

与 exe 同目录。

- `settings.json`：开关、镜像注册表、串发游标、还原备份。某个值写坏只回退该字段，不连坐整份配置。
- `routes.json`：`ips`（IP + 伪装 SNI + 证书校验锚点 + 服务的域名）与 `hosts`（域名 + 四个开关位）构成二部图；可直接手改。
  - `session`：带登录态，固定同一 IP，不开第二条通道
  - `content`：可竞速、可切片、可挂镜像链
  - `big`：大文件/Release，单通道长流 + 大镜像链
  - `direct`：不进代理
- `mirrors` / `mirrors_big`：路由键 → 镜像链。
- 内置 `seeds.json` 只在全新安装建表、或给已有表补节点时用，不会新建域名行。

每 IP 恒 1 条 h2 连接（多通道就换 IP），闲置 10 秒焚毁；会话域固定同一 IP。这些是写死的常量，不是可调项。

## 镜像

首次安装内置 8 家（可按条停用）：

```
gh-proxy.org          gh-proxy.com          ghgo.de5.net       ghfile.geekertao.top
gh.meali.top          github.chenc.dev      gh.dpik.top        ghproxy.icu
```

- 只对 `GET`/`HEAD` 的大文件与 Release 路径生效；API 与会话域不走镜像。
- 发请求前剥掉 Cookie / Authorization / Referer / UA。账号凭据不外流。
- **校验只到结构**：状态码、非 HTML、206 起点、区间与总长。**没有内容哈希。**
- 后果：单家镜像只能污染自己负责的那段（压包解压会报 CRC 错，exe 可能不报）；只有一家可用时等于单源完整替换；全部段受控时与单源无异。

要彻底归零只有一条路：下载后自己核对官方 SHA256 / GPG。不核就把镜像停用，代价是跨洋大文件变慢。列表本身会过期——公共镜像随时失效，程序运行期会探针熔断。

## 文件

```
ca.crt / ca.key    本地 CA
settings.json      开关与备份
routes.json        路由表与镜像链
.cache/            页面缓存与资产库（明文）、crash.log、tray.log
```

启动会打一行分段耗时（配置 / 路由表 / CA / 代理），排障用。日志与页面缓存都落在 `.cache`。

## 构建

```
cargo build --release
cargo test
```

仅 Windows。`.cargo/config.toml` 里固化的是作者机器上的 BoringSSL 构建路径（clang-cl + Ninja + nasm + 指定工具集），换机器要改。

## 限制

1. 镜像无内容校验，流式转发无法既校验又实时交付。
2. 页面缓存明文落盘，隔离只靠 ACL。
3. 半开放 443 隧道：本机任意进程可把它当"任意公网 443"的转发器；内网与环回已被 bogon 过滤挡住。
4. 仅 Windows，依赖 BoringSSL 本地编译。
5. 仓库不附基准数据，代码注释里的实测数字都来自作者环境。

机制细节（分流矩阵、通道池、失败分级、切片与合并、解密面）见 `docs/architecture.md`；缓存体系全解（三层各管什么、胚与资产库怎么配合、日志判读）见 `docs/cache.md`。
