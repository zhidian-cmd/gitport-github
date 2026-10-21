# GitPort GitHub —— GitHub 加速器

[![支持](https://img.shields.io/badge/支持-请作者喝咖啡-orange)](#支持项目)

**中国大陆访问 GitHub 的本地加速器 —— 免插件、免服务器、后台约 12MB。**
clone / push / 网页 / Release 下载 / raw / 头像全场景加速，其余网站流量完全不受影响。
直连流量本机直达 GitHub 官方边缘；镜像链剥凭据，不外泄。

## 这是什么

本机跑一个代理（`127.0.0.1:7810`）+ 管理页面（`127.0.0.1:7811`），只接管 GitHub 系域名：

- **不查 DNS**：内置 GitHub 真实 IP 表（`plans.json`），DNS 污染免疫
- **连不上就换**：IP 按表逐个试，坏的垫底，单点故障只慢不掉
- **TLS 指纹是 Chrome 同款**：BoringSSL + 伪装 SNI，绕过针对明文域名的阻断
- **连接复用到极限**：高频 host 双 h2 连接 + 按实测耗时择优，GitHub 前端遥测本地拦掉（一个字节不发往上游）
- **大文件多一条路**：Release / 源码包走镜像串行链，直连全灭仍能下载

| 方案 | 免插件 | 免服务器/账号 | clone/push | 后台占用 | 只碰 GitHub |
|---|---|---|---|---|---|
| **GitPort GitHub** | ✅ PAC 一键 | ✅ | ✅ | ~12MB | ✅ |
| 改 hosts | ✅ | ✅ | 部分 | — | ✅ 但 IP 失效即瘫 |
| gh-proxy 网页镜像 | — | 靠第三方 | ✗ | — | — |
| Watt Toolkit | ✅ | ✅ | 部分 | 较高 | ✅（多站点） |
| 通用代理/VPN | 视工具 | ✗（需节点） | ✅ | 视工具 | ✗ 全部流量 |

## 快速上手

1. 双击 `gitport-github.exe`（或 `.\gitport-github.exe -tray` 驻留托盘）
2. 首次启动在 exe 同目录自动生成 `ca.crt`/`ca.key`、`plans.json`、`settings.json` —— 所有开关默认全关
3. 打开工作台：先开「GitHub 分流接管」（写系统 PAC）→ 需要内容域直连/流式直通再开「MITM」（一键装证书根）

不开 MITM 也能用（纯透传加速）。系统代理接管在退出时自动还原；强杀残留由下次启动自愈。

## 已知边界

| 做不到 | 原因 | 应对 |
|---|---|---|
| macOS / Linux | 桌面框架 Windows 专属 | macOS 推荐 Watt Toolkit / Clash Verge |
| 大文件上传快 | 伪装 SNI 链路每流限速（~119KB/s），push/单附件是单流协议 | 多附件并发；优先走 release 附件上传（直拨 ~1.3MB/s） |
| 一劳永逸 | GitHub 边缘 IP 会迁移 | 种子补缺 + DNS 兜底腿自愈；极端情况手改 `plans.json` |
| 零门槛 | MITM 需装本地根证书 | WebUI 一键安装；不装也能用 |
| 加速所有网站 | 只路由 GitHub 系域名 | 其他站点用通用代理 |
| 私库 release 附件走镜像 | 镜像链剥凭据 + 拒签名查询串（防外泄） | 公库无感；私库等直连恢复 |
| raw/头像偶发被掐 | GFW 对 Fastly 内容边缘间歇阻断 | 内容域熔断 + 镜像链自动接管 |
| schannel 系 CLI 走 MITM | 叶子证书无 OCSP/CRL，Windows 吊销检查硬失败 | `curl --ssl-no-revoke`；git 关 `schannelCheckRevoke`；浏览器无感 |

## 常见问题

- **push 大包慢？** 伪装 SNI 上行带宽有限（~115KB/s），与代理无关；流式直通保证不 502，中断后整体重传。
- **raw 偶发 6~8 秒？** 真名 SNI 被点名 RST；熔断+镜像兜底已就位，自动恢复。
- **浏览器报证书风险？** MITM 开了但根证书未装/浏览器未重启；WebUI 一键装根后重启浏览器。
- **端口冲突？** `.\gitport-github.exe -port 7812 -webui 7813`。
- **页面显示「暂时不可用」？** 封锁窗口期，8 秒自动刷新，窗口一过即恢复。

## 命令行

```powershell
.\gitport-github.exe            # 桌面壳 + 托盘
.\gitport-github.exe -headless  # 无窗口：只跑代理 + 管理页面
.\gitport-github.exe -tray      # 驻留托盘（开机自启用）
.\gitport-github.exe -port 7812 -webui 7813   # 换端口
```

## 文档

- [工作原理](docs/ARCHITECTURE.md) —— 请求全流程、串发拨号、连接复用、镜像链、流式直通
- [路由表](docs/ROUTING.md) —— 四层决策链全矩阵（2026-10-19 实测）
- [高级配置](docs/CONFIG.md) —— plans.json 手改指南、IP 认读、分流域名总表
- [术语速查](docs/GLOSSARY.md) —— 网络与封锁名词大白话

## 构建

```powershell
cargo build --release   # 产物 target\release\gitport-github.exe
cargo test
```

## Roadmap

- 多站点加速（HuggingFace 等）：拨号引擎、串发表、镜像链均为数据驱动，扩服务 = 加数据不改代码

## 支持项目

如果 GitPort GitHub 帮到了你，**点个 Star ⭐** 就是最好的支持——它能让更多人看到这个项目。

想再进一步，请作者喝杯咖啡（**完全自愿，不影响任何功能**）：

<p align="center"><img src="docs/qr-sponsor.png" width="280" alt="微信赞赏码"></p>

微信扫一扫 · 金额随缘。本项目没有付费版、也没有付费功能；捐赠与功能开放、版本更新、Issue 响应没有任何关系。

## 声明

- 仅供学习网络原理与个人自用提速，遵守所在地区法律法规，后果自负
- 与 GitHub 无任何隶属关系；第三方公共镜像可用性随其变化
