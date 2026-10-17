//! 串发拨号：plans.json 是唯一权威，纯粹按表重试。
//!
//! - 元素 {ip, sni}; sni 形态按 IP 族定(见 shape_for_ip)，SNI 与校验名解耦
//! - 排序: 成功(ok)置顶, 失败(拨号错/零回包/拦截页)垫底; 同 IP 重复置顶是
//!   no-op 不写盘不打日志 —— 否则每个成功响应都重写 plans.json
//! - 全灭: 冷却 30s 快速失败, 不自动拉源 —— 表内容只靠手改维护
//! - 仅顺序真变更才写盘(2s 内原子写回); 文件可随时手改(改完重启生效)
//! - 覆盖 core/api/edge 三池(均直连)。edge 混合池按 host 族对口选择
//!   (entry_serves)；uploads.github.com 与 objects-origin 已非池化(直连兜底)；
//!   codeload 与 releases 大文件仍全镜像无表
//! —— 见 config::GROUPS 与 server/mitm.rs。

pub mod dial;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// 日志回调（server/main 注入）。
pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

/// 配对表单条：一个连接方案 = IP × SNI 形态。顺序即优先级。
/// 形态按 IP 族定（shape_for_ip）；显式写法（sni/baidu.com）读入时保留。
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SerialPlan {
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
}

/// 串发覆盖的直连池：core（站点）/ api（api.github.com）/
/// edge（auth 主机 + Fastly 静态边缘，均不外泄镜像/镜像不路由）。codeload 与
/// releases 大文件全镜像、无表。此常量同时决定落盘/UI 顺序（两者恒一致）。
/// uploads.github.com 与 objects-origin（上传链路）2026-10-17 起非池化，
/// 系统 DNS 直连兜底（objects-origin 走 config::DIRECT_HOSTS，连代理都不进）。
pub const SERIAL_POOLS: &[&str] = &["core", "api", "edge"];

/// 内置种子：首次运行（无 plans.json）时展开成初始表。
const SEEDS_JSON: &str = include_str!("seeds.json");

/// 第三方镜像候选池（gh-proxy 系，URL 前缀代理：镜像域名 + "/" + 原始完整 URL）。
/// 域名是常量数组，随时可改。健康度要求（防误加假站）：只收能真返回 GitHub
/// 文件内容的前缀代理 —— ghproxy.link 之类返 200 + 自家 SPA 主页，永不启用
/// （mirror_do 假页拒判兜底）。镜像只路由文件内容域，CSS/JS 与 github.io 不过镜像。
pub const MIRRORS: &[&str] = &[
    "https://mirror.ghproxy.com",
    "https://gh-proxy.com",
    "https://gh-proxy.org",
    "https://v4.gh-proxy.org",
    "https://v6.gh-proxy.org",
    "https://cdn.gh-proxy.org",
    "https://axisnow.gh-proxy.org",
    "https://ghproxy.net",
    "https://ghfast.top",
    "https://github.moeyy.xyz",
    "https://cf.ghproxy.cn",
];

/// 有镜像的内容域 host（镜像链板块只覆盖这些 —— 镜像不路由 CSS/JS 与
/// github.io，它们归 edge 直连池，无链可记）。
pub const CONTENT_HOSTS: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "avatars.githubusercontent.com",
    "user-images.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "media.githubusercontent.com",
];

/// 默认镜像链（2026-10-15 沙箱实测 8 host × 11 镜像 TTFB 升序；失联镜像
/// 按池常量序排尾）。每 host 链序不同 —— 同镜像对不同资源差异巨大
/// （v4 拉 gist 641ms 最快但 codeload 1.4s 开外；cf.ghproxy.cn 独家路由
/// user-images/media）。校准后顺序以 plans.json mirrors 板块为准。
pub const DEFAULT_CHAINS: &[(&str, &[&str])] = &[
    (
        "github.com",
        &[
            "https://gh-proxy.org",
            "https://v6.gh-proxy.org",
            "https://cf.ghproxy.cn",
            "https://cdn.gh-proxy.org",
            "https://gh-proxy.com",
            "https://v4.gh-proxy.org",
            "https://axisnow.gh-proxy.org",
            "https://mirror.ghproxy.com",
            "https://ghproxy.net",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
    (
        "raw.githubusercontent.com",
        &[
            "https://axisnow.gh-proxy.org",
            "https://v4.gh-proxy.org",
            "https://cdn.gh-proxy.org",
            "https://gh-proxy.org",
            "https://ghproxy.net",
            "https://v6.gh-proxy.org",
            "https://gh-proxy.com",
            "https://cf.ghproxy.cn",
            "https://mirror.ghproxy.com",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
    (
        "gist.githubusercontent.com",
        &[
            "https://v4.gh-proxy.org",
            "https://axisnow.gh-proxy.org",
            "https://gh-proxy.com",
            "https://gh-proxy.org",
            "https://ghproxy.net",
            "https://cdn.gh-proxy.org",
            "https://v6.gh-proxy.org",
            "https://cf.ghproxy.cn",
            "https://mirror.ghproxy.com",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
    (
        "avatars.githubusercontent.com",
        &[
            "https://axisnow.gh-proxy.org",
            "https://gh-proxy.com",
            "https://v4.gh-proxy.org",
            "https://gh-proxy.org",
            "https://cdn.gh-proxy.org",
            "https://v6.gh-proxy.org",
            "https://cf.ghproxy.cn",
            "https://mirror.ghproxy.com",
            "https://ghproxy.net",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
    (
        "user-images.githubusercontent.com",
        &[
            "https://cf.ghproxy.cn",
            "https://mirror.ghproxy.com",
            "https://gh-proxy.com",
            "https://gh-proxy.org",
            "https://v4.gh-proxy.org",
            "https://v6.gh-proxy.org",
            "https://cdn.gh-proxy.org",
            "https://axisnow.gh-proxy.org",
            "https://ghproxy.net",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
    (
        "codeload.github.com",
        &[
            "https://gh-proxy.org",
            "https://v6.gh-proxy.org",
            "https://cf.ghproxy.cn",
            "https://cdn.gh-proxy.org",
            "https://gh-proxy.com",
            "https://v4.gh-proxy.org",
            "https://axisnow.gh-proxy.org",
            "https://mirror.ghproxy.com",
            "https://ghproxy.net",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
    (
        "objects.githubusercontent.com",
        &[
            "https://axisnow.gh-proxy.org",
            "https://gh-proxy.org",
            "https://cdn.gh-proxy.org",
            "https://v6.gh-proxy.org",
            "https://cf.ghproxy.cn",
            "https://ghproxy.net",
            "https://gh-proxy.com",
            "https://v4.gh-proxy.org",
            "https://mirror.ghproxy.com",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
    (
        "release-assets.githubusercontent.com",
        &[
            "https://gh-proxy.org",
            "https://v4.gh-proxy.org",
            "https://gh-proxy.com",
            "https://axisnow.gh-proxy.org",
            "https://ghproxy.net",
            "https://v6.gh-proxy.org",
            "https://cdn.gh-proxy.org",
            "https://cf.ghproxy.cn",
            "https://mirror.ghproxy.com",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
    (
        "media.githubusercontent.com",
        &[
            "https://cf.ghproxy.cn",
            "https://mirror.ghproxy.com",
            "https://gh-proxy.com",
            "https://gh-proxy.org",
            "https://v4.gh-proxy.org",
            "https://v6.gh-proxy.org",
            "https://cdn.gh-proxy.org",
            "https://axisnow.gh-proxy.org",
            "https://ghproxy.net",
            "https://ghfast.top",
            "https://github.moeyy.xyz",
        ],
    ),
];

/// 该池是否走串发。
pub fn serial_pool(name: &str) -> bool {
    SERIAL_POOLS.contains(&name)
}

/// IP → 默认 SNI 形态（2026-10-14 实测：Fastly 边缘对任意 SNI 都返本边缘
/// 主证书，推翻"按 SNI 路由证书"旧结论）。.133 伪装会被边缘挂起（握手 OK
/// 但零回包）只能真名；.153/.154/.215（assets 新代边缘）伪装可正常 HTTP 且
/// 抗 SNI 阻断（raw 真名被 RST 即前车之鉴）；主站/auth 边缘伪装。
/// 用于种子展开与旧表空/legacy 值归一；表内显式写法优先（Fastly 段除外
/// —— 形态由边缘行为决定，显式写法无意义）。
fn shape_for_ip(ip: &str) -> &'static str {
    if fastly_last_octet(ip) == Some("133") {
        dial::MODE_SNI
    } else {
        "baidu.com"
    }
}

/// Fastly 段 IP 的末段（108-111 段才认），非 Fastly 返回 None。
/// 末段即域族：133=githubusercontent 内容 / 153=github.io / 154=githubassets。
fn fastly_last_octet(ip: &str) -> Option<&str> {
    let mut o = ip.split('.');
    match (o.next(), o.next(), o.next(), o.next()) {
        (Some("185"), Some("199"), Some(n), Some(last))
            if matches!(n, "108" | "109" | "110" | "111") =>
        {
            Some(last)
        }
        _ => None,
    }
}

/// host 的 Fastly 域族（"" = 非 Fastly 域）。
/// 末段即域族：.133=githubusercontent 内容 / .153=github.io / .154=githubassets。
/// 三族边缘各服务各的域，打错边缘 Host 会被对端拒绝或 404 —— 条目必须与
/// host 域族对口。
fn host_family(host: &str) -> &'static str {
    if host.ends_with("githubusercontent.com") {
        "content"
    } else if host.ends_with("githubassets.com") {
        "assets"
    } else if host == "github.io" || host.ends_with(".github.io") {
        "io"
    } else {
        ""
    }
}

/// 条目是否服务该 host：Fastly 各族只认对应末段（.133 真名 / .153、.154、
/// .215 伪装；assets 族 2026-10 起认新边缘 .215，.154 保留兼容），其余
/// host（主站/auth）只认非 Fastly 伪装条目。不对口跳过（不试不垫底）——
/// 否则各类请求互相试败垫底，池序永远乒乓。
/// 注：objects-origin 是直连白名单（config::DIRECT_HOSTS），不经任何池。
fn entry_serves(host: &str, p: &SerialPlan) -> bool {
    match host_family(host) {
        "content" => fastly_last_octet(&p.ip) == Some("133"),
        "assets" => matches!(fastly_last_octet(&p.ip), Some("154") | Some("215")),
        "io" => fastly_last_octet(&p.ip) == Some("153"),
        _ => fastly_last_octet(&p.ip).is_none() && plan_mode(&p.sni) != plan_mode(dial::MODE_SNI),
    }
}

fn seed_db() -> HashMap<String, Vec<String>> {
    serde_json::from_str(SEEDS_JSON).unwrap_or_default()
}

const SERIAL_MAX_PLANS: usize = 512; // 防表无限膨胀

struct SerialTab {
    pools: HashMap<String, Vec<SerialPlan>>,
    cool: HashMap<String, Instant>, // 全灭冷却
    /// 镜像使用链：内容域 host -> 有序镜像列表（串行逐个用，禁并发竞速）。
    /// 顺序来源：内置默认(实测) / UI 校准半自动重排 / 手改。
    mirrors: HashMap<String, Vec<String>>,
    dirty: bool,
}

static SERIAL: Mutex<Option<SerialTab>> = Mutex::new(None);
static SERIAL_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
/// 表头轮换日志回调（serial_load 注入）：表头真变时打一行，让 plans.json
/// 的每次轮换可追溯（哪类事件把哪个 IP 顶上/沉下）。
static SERIAL_LOG: Mutex<Option<LogFn>> = Mutex::new(None);

/// plans.json 反序列化：直连池条目 + 镜像链板块（互不干扰，flatten 收纳
/// 未知键 —— 旧版 ghapp/assets 等残留键随 pools 读入后被按池名过滤）。
#[derive(serde::Deserialize)]
struct PlansFile {
    #[serde(default)]
    mirrors: HashMap<String, Vec<String>>,
    #[serde(flatten)]
    pools: HashMap<String, Vec<SerialPlan>>,
}

/// 全表快照（落盘/UI 用）。
pub fn plans_snapshot() -> HashMap<String, Vec<SerialPlan>> {
    let g = SERIAL.lock().unwrap();
    let tab = g.as_ref().unwrap();
    let mut out = HashMap::new();
    for name in SERIAL_POOLS {
        if let Some(plans) = tab.pools.get(*name) {
            out.insert(name.to_string(), plans.clone());
        }
    }
    out
}

/// 手工排版序列化：每条目压成单行 —— 表是给人看也给人改的。
/// 池按 UI 固定顺序输出，末尾附镜像链板块（每 host 一行数组）。
fn encode_plans(
    tab: &HashMap<String, Vec<SerialPlan>>,
    mirrors: &HashMap<String, Vec<String>>,
) -> String {
    let mut b = String::from("{\n");
    for (i, name) in SERIAL_POOLS.iter().enumerate() {
        if i > 0 {
            b.push_str(",\n");
        }
        b.push_str(&format!("  \"{name}\": ["));
        let ps = tab.get(*name).cloned().unwrap_or_default();
        if !ps.is_empty() {
            b.push('\n');
            for (j, p) in ps.iter().enumerate() {
                if j > 0 {
                    b.push_str(",\n");
                }
                // sni 恒非空（真名/伪装）；空值条目（旧表残留）落盘省略键
                if p.sni.is_empty() {
                    b.push_str(&format!("    {{\"ip\": {}}}", esc(&p.ip)));
                } else {
                    b.push_str(&format!(
                        "    {{\"ip\": {}, \"sni\": {}}}",
                        esc(&p.ip),
                        esc(&p.sni)
                    ));
                }
            }
            b.push_str("\n  ]");
        } else {
            b.push(']');
        }
    }
    // 镜像链板块：host 按 CONTENT_HOSTS 固定序（可读性稳定）
    let chains: Vec<(&str, &Vec<String>)> = CONTENT_HOSTS
        .iter()
        .filter_map(|h| mirrors.get(*h).map(|c| (*h, c)))
        .collect();
    if !chains.is_empty() {
        b.push_str(",\n  \"mirrors\": {");
        for (i, (host, chain)) in chains.iter().enumerate() {
            if i > 0 {
                b.push(',');
            }
            let items: Vec<String> = chain.iter().map(|m| esc(m)).collect();
            b.push_str(&format!("\n    {}: [{}]", esc(host), items.join(", ")));
        }
        b.push_str("\n  }");
    }
    b.push_str("\n}\n");
    b
}

/// JSON 字符串字面量（含引号，serde 全量转义）：控制字符/反斜杠/引号都不产
/// 坏 JSON。旧手写版只转 \ 和 "，值里混入控制字符会写出非法 plans.json，
/// 下次启动解析失败 → 用户手排表被种子覆盖。
fn esc(s: &str) -> String {
    serde_json::to_string(s).expect("字符串序列化不会失败")
}

/// 原子写 plans.json。
fn write_plans_file(
    path: &Path,
    tab: &HashMap<String, Vec<SerialPlan>>,
    mirrors: &HashMap<String, Vec<String>>,
) {
    let data = encode_plans(tab, mirrors);
    let tmp = path.with_extension("json.tmp");
    if let Ok(mut f) = std::fs::File::create(&tmp) {
        if f.write_all(data.as_bytes()).is_ok() {
            let _ = f.flush();
            drop(f);
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

fn plans_path() -> PathBuf {
    let dir = SERIAL_DIR
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join("plans.json")
}

/// 初始化：读 exe 同目录 plans.json；不存在则用内置种子写出。
/// 同时启动落盘 ticker（顺序变更 2s 内写回）。
pub fn serial_load(data_dir: &Path, log: Option<LogFn>) {
    *SERIAL_DIR.lock().unwrap() = Some(data_dir.to_path_buf());
    *SERIAL_LOG.lock().unwrap() = log.clone();
    let path = plans_path();
    let raw = std::fs::read_to_string(&path).ok();
    let parsed = raw.as_deref().and_then(|b| serde_json::from_str::<PlansFile>(b).ok());
    if let (Some(_raw), None) = (&raw, &parsed) {
        // 有文件但解析失败(2026-10-17 安全审计 F-006)：不许静默覆丢用户
        // 手排表 —— 先备份原文件, 再走种子重建, 日志留痕
        let bak = path.with_extension("json.bak");
        if std::fs::copy(&path, &bak).is_ok() {
            if let Some(l) = log.as_ref() {
                l("[串发] plans.json 解析失败, 原文件已备份为 plans.json.bak, 本次按种子重建");
            }
        }
    }
    let loaded: PlansFile = parsed.unwrap_or_else(|| PlansFile {
        pools: HashMap::new(),
        mirrors: HashMap::new(),
    });
    let plans_map = loaded.pools;
    let loaded_chains = loaded.mirrors;

    let mut tab = SerialTab {
        pools: HashMap::new(),
        cool: HashMap::new(),
        mirrors: HashMap::new(),
        dirty: false,
    };
    // 遍历已知池（而非文件里的键）：文件缺池/被旧 exe 误清时用种子补齐，
    // 防"串发表为空"。文件为准，不做
    // 种子归属剔除；种子结构变更时删 plans.json 重建（2026-10-13 决定）。
    for name in SERIAL_POOLS {
        let ps = plans_map.get(*name).cloned().unwrap_or_default();
        let mut plans = Vec::new();
        for p in ps {
            if p.ip.parse::<std::net::IpAddr>().is_err() || p.sni == "ech" {
                continue;
            }
            // ech: 边缘不发布 ECH 记录, 恒失败 —— 清除旧表遗留;
            // 形态: Fastly 三段(133/153/154)强制按 IP 族归一(形态由边缘行为
            // 决定, 显式写法无意义 —— 旧表 .153/.154 的真名条目随 2026-10-14
            // "伪装抗 SNI 阻断"实测结论统一迁移); 其余条目显式写法保留,
            // 空与旧值(real/nosni)按 IP 族归一; 表内存量统一为裸域名
            let sni = if fastly_last_octet(&p.ip).is_some() {
                shape_for_ip(&p.ip).to_string()
            } else {
                match p.sni.trim() {
                    "" | "real" | "nosni" => shape_for_ip(&p.ip).to_string(),
                    dial::MODE_SNI => dial::MODE_SNI.to_string(),
                    s => {
                        // 表层格式校验(2026-10-17 安全审计 F-003): sni 会进
                        // WebUI 与 ClientHello, 只认域名形态字符 —— plans.json
                        // 手改内容不得携带标记进前端
                        let bare = s.trim_start_matches(dial::MODE_FAKE_PFX);
                        if !bare.is_empty()
                            && bare
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                        {
                            bare.to_string()
                        } else {
                            shape_for_ip(&p.ip).to_string()
                        }
                    }
                }
            };
            plans.push(SerialPlan { ip: p.ip, sni });
        }
        // 文件里该池缺失/被旧版二进制清掉 → 用种子补齐(自愈, 防"串发表为空")
        if plans.is_empty() {
            if let Some(ips) = seed_db().get(*name) {
                for ip in ips {
                    if ip.parse::<std::net::IpAddr>().is_err() {
                        continue;
                    }
                    if plans.len() < SERIAL_MAX_PLANS {
                        plans.push(SerialPlan {
                            ip: ip.clone(),
                            sni: shape_for_ip(&ip).to_string(),
                        });
                    }
                }
            }
        }
        // 种子补缺：新版本引入的新边缘 IP（如 2026-10-14 的 .133 内容域）在
        // 用户现存表里没有 —— 追加到表尾并打一行日志，否则头像直连对老用户
        // 永远无候选。只追加不重排，用户手改的顺序原样保留。
        if let Some(ips) = seed_db().get(*name) {
            let mut added = 0usize;
            for ip in ips {
                if ip.parse::<std::net::IpAddr>().is_err()
                    || plans.iter().any(|p| p.ip == *ip)
                    || plans.len() >= SERIAL_MAX_PLANS
                {
                    continue;
                }
                plans.push(SerialPlan {
                    ip: ip.clone(),
                    sni: shape_for_ip(&ip).to_string(),
                });
                added += 1;
            }
            if added > 0 {
                if let Some(log) = log.as_ref() {
                    log(&format!(
                        "[串发] {name} 种子补缺 {added} 条(新边缘 IP 上线)"
                    ));
                }
            }
        }
        tab.pools.insert((*name).to_string(), plans);
    }
    // 镜像链归一：未知 host / 池外镜像丢弃；缺失 host 用内置默认链（实测
    // TTFB 序）；池内新增镜像追加到每条链尾部（对齐种子补缺思想）。
    for (host, chain) in loaded_chains {
        if !CONTENT_HOSTS.contains(&host.as_str()) {
            continue;
        }
        let vc: Vec<String> = chain
            .into_iter()
            .filter(|m| MIRRORS.contains(&m.as_str()))
            .collect();
        if !vc.is_empty() {
            tab.mirrors.insert(host, vc);
        }
    }
    for (host, def) in DEFAULT_CHAINS {
        let e = tab
            .mirrors
            .entry(host.to_string())
            .or_insert_with(|| def.iter().map(|m| m.to_string()).collect());
        let mut added = 0usize;
        for m in MIRRORS {
            if !e.iter().any(|x| x == m) {
                e.push(m.to_string());
                added += 1;
            }
        }
        if added > 0 {
            if let Some(log) = log.as_ref() {
                log(&format!("[镜像] {host} 链补缺 {added} 条(新镜像上线)"));
            }
        }
    }
    // 先设内存态，再统一重写一次（snapshot 读内存）：剥掉旧统计字段/补齐形态，
    // 文件与内存恒一致。测试场景：先前断言失败可能 poison 全局锁，恢复后再写。
    *SERIAL.lock().unwrap_or_else(|p| p.into_inner()) = Some(tab);
    let snap = plans_snapshot();
    let chains = mirror_chains_snapshot();
    write_plans_file(&path, &snap, &chains);
}

/// 顺序变更 2s 内写回实体文件（变更驱动 + 去抖）。
/// 必须在 tokio runtime 构建后调用（main 用 rt.spawn 挂起）。
/// 纯事件驱动：无变更时任务睡在 Notify 上，进程零周期唤醒（托盘态
/// "几乎无活动"裁定的一部分）—— 原 2s interval ticker 无变更也醒。
static PERSIST_KICK: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// dirty 置位后调用：踢醒落盘任务。无等待者时存许可证，语义安全。
fn kick_persist() {
    PERSIST_KICK.notify_one();
}

pub fn start_persist(rt: &tokio::runtime::Runtime) {
    rt.spawn(async move {
        loop {
            PERSIST_KICK.notified().await;
            // 2s 去抖：合并一串快速变更（页面加载时表头连续翻飞）为一次写盘
            tokio::time::sleep(Duration::from_secs(2)).await;
            let dirty = {
                let mut g = SERIAL.lock().unwrap();
                let dirty = g.as_ref().map(|t| t.dirty).unwrap_or(false);
                if dirty {
                    g.as_mut().unwrap().dirty = false;
                }
                dirty
            };
            if dirty {
                let snap = plans_snapshot();
                let chains = mirror_chains_snapshot();
                write_plans_file(&plans_path(), &snap, &chains);
            }
        }
    });
}

/// sni 形态 → dial_one 模式（裸域名 = 伪装，走 "fake:<sni>" 前缀；
/// 兼容旧表带 "fake:" 前缀的写法，两种格式行为一致）。
/// MODE_SNI = 真名形态（Fastly 边缘专用，按 SNI 路由证书）。
/// 旧表 "nosni" 由 serial_load 读入时按 IP 族归一，此处不再特判。
pub fn plan_mode(sni: &str) -> String {
    match sni {
        dial::MODE_SNI => dial::MODE_SNI.to_string(),
        _ => format!(
            "{}{}",
            dial::MODE_FAKE_PFX,
            sni.trim_start_matches(dial::MODE_FAKE_PFX)
        ),
    }
}

/// 命中条目整体移位：置顶（保持组内相对序）/垫底。why = 事件原因（进日志）。
/// 顺序没变（同 IP 重复置顶/已在尾）直接返回：不置 dirty、不打日志 ——
/// 每个成功响应都 no-op 置顶一次，若都写盘，plans.json 会被无意义地反复重写。
/// 表头真变了才打一行轮换日志，让"文件在轮换"始终有据可查。
fn serial_move(pool_name: &str, match_fn: impl Fn(&SerialPlan) -> bool, to_front: bool, why: &str) {
    let mut g = SERIAL.lock().unwrap();
    let tab = g.as_mut().unwrap();
    let Some(pool_plans) = tab.pools.get_mut(pool_name) else {
        return;
    };
    let mut hit = Vec::new();
    let mut rest = Vec::new();
    for p in &*pool_plans {
        if match_fn(p) {
            hit.push(p.clone());
        } else {
            rest.push(p.clone());
        }
    }
    if hit.is_empty() {
        return;
    }
    let new_plans = if to_front {
        let mut v = hit;
        v.extend(rest);
        v
    } else {
        let mut v = rest;
        v.extend(hit);
        v
    };
    if new_plans == *pool_plans {
        return; // 顺序没变：不写盘不打日志
    }
    let old_head = pool_plans.first().map(|p| p.ip.clone());
    let new_head = new_plans.first().map(|p| p.ip.clone());
    *pool_plans = new_plans;
    tab.dirty = true;
    drop(g); // 先放锁再踢醒: 被唤醒的落盘任务要抢同一把锁
    kick_persist();
    if old_head != new_head {
        if let Some(log) = SERIAL_LOG.lock().unwrap().as_ref() {
            log(&format!(
                "[串发] {pool_name} 表头 {} -> {} ({why})",
                old_head.as_deref().unwrap_or("(空)"),
                new_head.as_deref().unwrap_or("(空)")
            ));
        }
    }
}

/// 单串发：按表逐个试，失败条目垫底换下一个，绕表一圈全灭 → 冷却 30s
/// 报错。置顶只由数据层 ok（serial_note）认证 —— 拨号成功不算成功。
/// tls_handshake=false 时只做裸 TCP 拨号（透传 CONNECT 隧道）。ctx 到期只
/// 掐正在试的那条：没试完 ≠ 失败（不沉底）≠ 全灭（不冷却）。
/// 返回 (连接, 所用 IP, 所用形态)。混合池按 host 选形态（host_shape）。
pub async fn serial_dial(
    pool_name: &str,
    host: &str,
    ctx: CancellationToken,
    tls_handshake: bool,
    log: Option<&LogFn>,
) -> Result<(dial::Dialed, String, String), String> {
    // 全灭冷却期内快速失败
    {
        let g = SERIAL.lock().unwrap();
        let tab = g.as_ref().unwrap();
        if let Some(cool) = tab.cool.get(pool_name) {
            if Instant::now() < *cool {
                let remain = cool.duration_since(Instant::now()).as_secs();
                return Err(format!("串发冷却中(全灭后约 {remain}s), 快速失败"));
            }
        }
        if tab
            .pools
            .get(pool_name)
            .map(|p| p.is_empty())
            .unwrap_or(true)
        {
            return Err(format!("串发表为空({pool_name})"));
        }
    }

    let snapshot = {
        let g = SERIAL.lock().unwrap();
        g.as_ref().unwrap().pools.get(pool_name).unwrap().clone()
    };

    let mut last_err: Option<String> = None;
    let mut tried = 0usize;
    for p in &snapshot {
        // 按 host 选条目（形态 + Fastly 域族）：不对口的条目跳过 —— 不试也不垫底，
        // 否则每类请求都把另一类 IP 试败沉底，排序永久 ping-pong
        if !entry_serves(host, p) {
            continue;
        }
        tried += 1;
        let mode = plan_mode(
            p.sni
                .trim()
                .is_empty()
                .then_some("baidu.com")
                .unwrap_or(p.sni.trim()),
        );
        let attempt = dial::dial_one(host, &p.ip, &mode, tls_handshake);
        let result = tokio::select! {
            _ = ctx.cancelled() => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "请求预算到期")),
            r = attempt => r,
        };
        match result {
            Ok(conn) => return Ok((conn, p.ip.clone(), p.sni.clone())),
            Err(e) => {
                last_err = Some(e.to_string());
                if ctx.is_cancelled() {
                    break; // 请求预算到期：这条没试完，不算失败；没试完 ≠ 全灭，不冷却
                }
                // 拨号失败垫底：内容域豁免 —— GFW 对 raw 真名 SNI 的 RST 发生在
                // TLS 握手(dial 层)，会把健康的 .133(avatars 同 IP)连坐垫底，
                // 池序被按域干扰刷着轮换(2026-10-15 实锤)
                if !host.ends_with("githubusercontent.com") {
                    let target = p.clone();
                    serial_move(pool_name, |q| *q == target, false, "拨号失败");
                    // 真失败垫底(单条)
                }
                continue;
            }
        }
    }

    if ctx.is_cancelled() {
        return Err("请求预算到期".to_string());
    }
    if tried == 0 {
        // 一条都没试（全被形态过滤）：不是全灭，不冷却，快速失败
        return Err(format!("无对口 SNI 形态的候选({pool_name}, {host})"));
    }
    // 绕表一圈全灭（每条都真试过）：冷却 30s。githubusercontent 内容域例外
    // —— 它有镜像竞速兜底（mitm 侧回落），且全灭多为 GFW 按域干扰（raw 真
    // 名被 RST）而非 IP 死；冷却只会把同池其他内容域（avatars 等）连坐 30s。
    if !host.ends_with("githubusercontent.com") {
        let mut g = SERIAL.lock().unwrap();
        g.as_mut().unwrap().cool.insert(
            pool_name.to_string(),
            Instant::now() + Duration::from_secs(30),
        );
    }
    if let Some(log) = log {
        let tail = if host.ends_with("githubusercontent.com") {
            "内容域不冷却(有镜像竞速兜底)"
        } else {
            "冷却 30s; 表内容请手改 plans.json"
        };
        log(&format!(
            "[串发] {} 全灭({} 候选, 累计 {:?}), {tail}",
            pool_name,
            snapshot.len(),
            last_err.as_deref().unwrap_or("未知")
        ));
    }
    Err(last_err.unwrap_or_else(|| "串发全灭".to_string()))
}

/// 数据层回写真实结果并修正排序。kind: ok / 其他一切（noreply 零回包/block 错误页/…）。
/// 通的信号（ok）该 IP 整体置顶；死的信号垫底 —— IP 级移位。
pub fn serial_note(pool_name: &str, ip: &str, kind: &str) {
    serial_move(pool_name, |p| p.ip == ip, kind == "ok", kind);
}

/// 内容域 host 的镜像使用链（有序，串行逐个用）。无记录返回空。
pub fn mirror_chain(host: &str) -> Vec<String> {
    let g = SERIAL.lock().unwrap();
    g.as_ref()
        .unwrap()
        .mirrors
        .get(host)
        .cloned()
        .unwrap_or_default()
}

/// 写回一条镜像链（校准/手改入口）：未知 host 与池外镜像拒收，
/// 与现链相同则 no-op，真变更置 dirty + 一行日志。
pub fn set_mirror_chain(host: &str, chain: &[String], why: &str) -> bool {
    if !CONTENT_HOSTS.contains(&host) {
        return false;
    }
    let vc: Vec<String> = chain
        .iter()
        .filter(|m| MIRRORS.contains(&m.as_str()))
        .cloned()
        .collect();
    if vc.is_empty() {
        return false;
    }
    let mut g = SERIAL.lock().unwrap();
    let tab = g.as_mut().unwrap();
    if tab.mirrors.get(host).map(|c| c == &vc).unwrap_or(false) {
        return false;
    }
    tab.mirrors.insert(host.to_string(), vc);
    tab.dirty = true;
    drop(g); // 先放锁再踢醒: 被唤醒的落盘任务要抢同一把锁
    kick_persist();
    if let Some(log) = SERIAL_LOG.lock().unwrap().as_ref() {
        log(&format!("[镜像] {host} 链序更新({why})"));
    }
    true
}

/// 全部镜像链快照（UI/落盘用）。
pub fn mirror_chains_snapshot() -> HashMap<String, Vec<String>> {
    let g = SERIAL.lock().unwrap();
    g.as_ref().unwrap().mirrors.clone()
}

// ---------- 内容域直连熔断 ----------

/// 内容域直连熔断：githubusercontent 族（avatars/raw/...）的直连被 GFW 按
/// 域黑洞时，每个请求都会烧满直连预算才回落镜像 —— 头像页几十个请求就是
/// 几十个 8 秒。失败一次即熔断 120s（期间直接走镜像链），成功立即清除。
/// 120s 后给直连一次重试机会（GFW 状态会变，恢复时自动回到快路径）。
static CONTENT_BREAKER: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> =
    std::sync::OnceLock::new();

/// host 直连是否处于熔断期。粒度必须按 host —— 同族域直连状态不同
/// (camo/private-user-images 可通而 raw 被黑洞), 全局单值会让"别的域
/// 成功"反复清掉 raw 的熔断, 每张图重新烧 8s 黑洞预算(2026-10-15 实锤)。
pub fn content_direct_open(host: &str) -> bool {
    let g = CONTENT_BREAKER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    g.get(host)
        .map(|until| Instant::now() < *until)
        .unwrap_or(false)
}

/// 直连成功：清除该 host 熔断。
pub fn content_direct_ok(host: &str) {
    let mut g = CONTENT_BREAKER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    g.remove(host);
}

/// 直连失败：熔断该 host 120s。
pub fn content_direct_fail(host: &str) {
    let mut g = CONTENT_BREAKER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    g.insert(host.to_string(), Instant::now() + Duration::from_secs(120));
}

// ---------- 镜像链全灭熔断 ----------

/// 镜像链全灭熔断：链全灭一次后 60s 内同 host 的后续请求快速失败 —— 否则
/// README 塞二三十张图的仓库在全灭期间每张图都串行烧完整条链(11 家 × 失败
/// 延迟), 页面 spinner 转几分钟(2026-10-16 实锤: dev-sidecar 20+ 张 raw 图
/// 撞上直连+镜像双全灭窗口)。成功取回即清除; 60s 后放行一次真实探测。
static MIRROR_BREAKER: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> =
    std::sync::OnceLock::new();

/// 镜像链是否处于全灭熔断期。
pub fn mirror_breaker_open(host: &str) -> bool {
    let g = MIRROR_BREAKER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    g.get(host)
        .map(|until| Instant::now() < *until)
        .unwrap_or(false)
}

/// 镜像链全灭：熔断该 host 60s。
pub fn mirror_breaker_set(host: &str) {
    let mut g = MIRROR_BREAKER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    g.insert(host.to_string(), Instant::now() + Duration::from_secs(60));
}

/// 镜像链取回成功：清除该 host 熔断。
pub fn mirror_breaker_clear(host: &str) {
    let mut g = MIRROR_BREAKER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    g.remove(host);
}

/// 域名 → 所属池名（config 唯一路由真相，"" = 非池域名）。
pub use crate::config::pool_for;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TMP_SEQ: AtomicUsize = AtomicUsize::new(0);
    // SERIAL/SERIAL_DIR 是进程级全局态，测试并行会互相踩踏 → 需要全局态的测试串行
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn tmpdir() -> PathBuf {
        let n = TMP_SEQ.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("gitport_test_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn reset_state(dir: &Path) {
        serial_load(dir, None);
    }

    #[test]
    fn plan_mode_semantics() {
        // plan_mode 是形态唯一判定入口（dial_shape 已删, serial_dial 直呼）:
        // 空串返回残缺 "fake:" —— 调用方(serial_dial)对空值兜底 "baidu.com";
        // 裸域名/带 fake: 前缀均归伪装; MODE_SNI 直通
        assert_eq!(plan_mode(""), "fake:", "空串须由调用方兜底");
        // 旧表 "nosni" 由 serial_load 归一（shape_for_ip），plan_mode 不再特判
        assert_eq!(
            plan_mode("baidu.com"),
            format!("{}baidu.com", dial::MODE_FAKE_PFX)
        );
        assert_eq!(
            plan_mode("fake:baidu.com"),
            plan_mode("baidu.com"),
            "旧表带前缀写法行为一致"
        );
        assert_eq!(plan_mode(dial::MODE_SNI), dial::MODE_SNI);
    }

    #[test]
    fn edge_shape_by_ip_family() {
        // Fastly 三段(2026-10-14 实测): .133 伪装即被边缘挂起 → 真名;
        // .153/.154 伪装 SNI HTTP 正常(抗 GFW SNI 阻断) → 伪装
        assert_eq!(shape_for_ip("185.199.108.133"), dial::MODE_SNI);
        assert_eq!(shape_for_ip("185.199.111.133"), dial::MODE_SNI);
        for ip in ["185.199.108.154", "185.199.111.153"] {
            assert_eq!(shape_for_ip(ip), "baidu.com", "{ip} 应取伪装");
        }
        // GitHub 主站边缘段 → 伪装（任意 SNI 都返覆盖真名的证书）
        for ip in ["140.82.112.29", "20.205.243.167"] {
            assert_eq!(shape_for_ip(ip), "baidu.com", "{ip} 应取伪装");
        }
        // host 期望形态由条目形态决定（.133 真名 / .153/.154 伪装，host_shape 已废）
        // 域族 → 条目末段对口：.133/.153/.154 各服务各的域，打错边缘必拒
        let mk = |ip: &str, sni: &str| SerialPlan {
            ip: ip.into(),
            sni: sni.into(),
        };
        assert!(entry_serves(
            "avatars.githubusercontent.com",
            &mk("185.199.108.133", dial::MODE_SNI)
        ));
        assert!(!entry_serves(
            "avatars.githubusercontent.com",
            &mk("185.199.108.154", "baidu.com")
        ));
        assert!(!entry_serves(
            "avatars.githubusercontent.com",
            &mk("140.82.112.29", "baidu.com")
        ));
        assert!(entry_serves(
            "github.githubassets.com",
            &mk("185.199.108.154", "baidu.com")
        ));
        assert!(!entry_serves(
            "github.githubassets.com",
            &mk("185.199.108.133", dial::MODE_SNI)
        ));
        assert!(entry_serves(
            "octocat.github.io",
            &mk("185.199.108.153", "baidu.com")
        ));
        // .153 真名条目同样服务(形态跟随条目, 真名亦可用, 仅不抗 SNI 阻断;
        // 表内形态已由 serial_load 按族强制归一)
        assert!(entry_serves(
            "octocat.github.io",
            &mk("185.199.108.153", dial::MODE_SNI)
        ));
        // .215 新代 assets 边缘(2026-10 GitHub 迁移): 伪装, 只服务 assets 族
        assert_eq!(shape_for_ip("185.199.108.215"), "baidu.com");
        assert!(entry_serves(
            "github.githubassets.com",
            &mk("185.199.108.215", "baidu.com")
        ));
        assert!(!entry_serves(
            "avatars.githubusercontent.com",
            &mk("185.199.110.215", "baidu.com")
        ));
        // 非 Fastly 族 host 只认非 Fastly 段的伪装条目
        assert!(entry_serves(
            "githubapp.com",
            &mk("140.82.112.29", "baidu.com")
        ));
        assert!(entry_serves("github.com", &mk("140.82.112.3", "baidu.com")));
        assert!(!entry_serves(
            "github.com",
            &mk("185.199.108.133", dial::MODE_SNI)
        ));
        assert!(!entry_serves(
            "api.github.com",
            &mk("140.82.112.29", dial::MODE_SNI)
        ));
    }

    #[test]
    fn upload_hosts_never_pooled() {
        // 上传域名全部直连白名单(2026-10-17):
        // objects-origin 只由 GLB 族(140.82.11x.21/.22)服务, 主站边缘对其
        // 301 无 CORS → 跨域预检失败、上传必败; uploads.github.com 为 API 式
        // 上传源站, 直连等价 gh CLI 的已知可用路径。两者都不入池、不过代理。
        for host in [
            "objects-origin.githubusercontent.com",
            "uploads.github.com",
        ] {
            assert!(crate::config::is_direct(host), "{host} 应在直连白名单");
            assert_eq!(crate::config::pool_for(host), "", "{host} 不应归任何池");
        }
    }

    #[test]
    fn fastly_pools_no_longer_serial() {
        // fastly/codeload 全镜像不直连: 不再是串发池
        assert!(!serial_pool("fastly"));
        assert!(!serial_pool("codeload"));
        for p in ["core", "api", "edge"] {
            assert!(serial_pool(p), "{p} 应为串发池");
        }
        // uploads 池 2026-10-17 撤销: 当前网页上传流程不经 uploads.github.com
        // (objects-origin 已归 core), 非池化走系统直连
        assert!(!serial_pool("uploads"));
    }

    #[test]
    fn migrate_drops_stats_and_normalizes_shapes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        std::fs::write(
            &dir.join("plans.json"),
            r#"{
  "core": [
    {"ip": "1.2.3.4", "sni": "ech", "成功次数": "9/9", "分数": 99},
    {"ip": "5.6.7.8", "sni": "real"},
    {"ip": "bad-ip", "sni": "real"}
  ],
  "edge": [
    {"ip": "140.82.112.29", "sni": "real"},
    {"ip": "185.199.108.154", "sni": "sni"},
    {"ip": "185.199.109.153", "sni": "sni"}
  ],
  "ghapp": [{"ip": "9.9.9.9", "sni": "baidu.com"}],
  "assets": [{"ip": "8.8.8.8", "sni": "sni"}]
}"#,
        )
        .unwrap();
        reset_state(&dir);
        let ps = {
            let g = SERIAL.lock().unwrap();
            let tab = g.as_ref().unwrap();
            tab.pools.get("core").unwrap().clone()
        };
        // ech/非法被滤; 旧表 real 条目按 IP 族归一为伪装; 种子补缺追加在尾部
        assert_eq!(
            ps[0],
            SerialPlan {
                ip: "5.6.7.8".into(),
                sni: "baidu.com".into()
            },
            "用户条目保留在前且归一"
        );
        let core_seed_n = seed_db().get("core").map(|v| v.len()).unwrap_or(0);
        assert_eq!(
            ps.len(),
            1 + core_seed_n,
            "补缺后 = 用户条目 + 全部种子: {ps:?}"
        );
        // edge 混合池: Fastly 三段强制按族归一(旧表真名条目随新结论迁移)
        let edge_ps = {
            let g = SERIAL.lock().unwrap();
            let tab = g.as_ref().unwrap();
            tab.pools.get("edge").unwrap().clone()
        };
        // 种子补缺: .133 内容域条目是新版本边缘, 用户旧表没有 → 自动追加
        assert!(edge_ps.len() >= 3, "edge 至少含旧表 3 条: {edge_ps:?}");
        assert!(
            edge_ps.contains(&SerialPlan {
                ip: "140.82.112.29".into(),
                sni: "baidu.com".into()
            }),
            "ghapp 伪装条目保留: {edge_ps:?}"
        );
        assert!(
            edge_ps.contains(&SerialPlan {
                ip: "185.199.108.154".into(),
                sni: "baidu.com".into()
            }) && edge_ps.contains(&SerialPlan {
                ip: "185.199.109.153".into(),
                sni: "baidu.com".into()
            }),
            "Fastly .153/.154 旧表真名强制归一为伪装: {edge_ps:?}"
        );
        assert!(
            edge_ps
                .iter()
                .any(|p| fastly_last_octet(&p.ip) == Some("133") && p.sni == dial::MODE_SNI),
            "种子补缺应追加 .133 真名内容域条目: {edge_ps:?}"
        );
        // ghapp/assets 旧键不再是池: 落盘只剩 core/api/edge
        let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(!b.contains("成功次数") && !b.contains("分数"));
        let back: serde_json::Value = serde_json::from_str(&b).unwrap();
        for gone in ["fastly", "codeload", "ghapp", "assets"] {
            assert!(back.get(gone).is_none(), "{gone} 不应再落盘: {back}");
        }
        assert!(back.get("edge").is_some(), "edge 池应落盘: {back}");
    }

    #[test]
    fn seed_topup_appends_missing_and_keeps_order() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        // 用户手排的表: 只留 1 条 ghapp(排到最前), 其余种子缺失
        std::fs::write(
            &dir.join("plans.json"),
            r#"{ "edge": [{"ip": "140.82.112.29", "sni": "baidu.com"}] }"#,
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Some(log));
        let ps = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("edge").unwrap().clone()
        };
        assert_eq!(
            ps[0].ip, "140.82.112.29",
            "用户手排顺序保留, 补缺只追加尾部"
        );
        let seeds = seed_db();
        let seed = seeds.get("edge").unwrap();
        assert_eq!(ps.len(), seed.len(), "补缺后应覆盖全部种子: {ps:?}");
        assert!(
            seen.lock().unwrap().iter().any(|l| l.contains("种子补缺")),
            "补缺应打一行日志"
        );
        // 落盘含补齐条目
        let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(b.contains("185.199.108.133"), "补缺应落盘: {b}");
    }

    #[test]
    fn encode_plans_roundtrip() {
        let mut tab = HashMap::new();
        tab.insert(
            "core".into(),
            vec![
                SerialPlan {
                    ip: "1.2.3.4".into(),
                    sni: "baidu.com".into(),
                },
                SerialPlan {
                    ip: "5.6.7.8".into(),
                    sni: "baidu.com".into(),
                },
            ],
        );
        tab.insert(
            "api".into(),
            vec![SerialPlan {
                ip: "140.82.112.5".into(),
                sni: "baidu.com".into(),
            }],
        );
        tab.insert(
            "edge".into(),
            vec![
                SerialPlan {
                    ip: "185.199.108.154".into(),
                    sni: dial::MODE_SNI.into(),
                },
                SerialPlan {
                    ip: "140.82.112.29".into(),
                    sni: "baidu.com".into(),
                },
            ],
        );
        let mut mirrors = HashMap::new();
        mirrors.insert(
            "raw.githubusercontent.com".to_string(),
            vec![
                "https://axisnow.gh-proxy.org".to_string(),
                "https://v4.gh-proxy.org".to_string(),
            ],
        );
        let b = encode_plans(&tab, &mirrors);
        // 每条目压在单行内
        for line in b.lines() {
            let t = line.trim();
            if t.starts_with("{\"ip\"") && t.matches('{').count() != 1 {
                panic!("条目被展开成多行: {line:?}");
            }
        }
        // 镜像链板块落盘 + 可读回
        assert!(b.contains("\"mirrors\""), "镜像链板块应落盘: {b}");
        assert!(b.contains("raw.githubusercontent.com"));
        let back_file: PlansFile = serde_json::from_str(&b).unwrap();
        assert_eq!(
            back_file
                .mirrors
                .get("raw.githubusercontent.com")
                .map(|c| c.len()),
            Some(2),
            "镜像链应可读回: {:?}",
            back_file.mirrors
        );
        let back: HashMap<String, Vec<SerialPlan>> = back_file.pools;
        assert_eq!(back["core"].len(), 2);
        assert_eq!(back["core"][0].sni, "baidu.com");
        assert_eq!(back["edge"].len(), 2);
        assert_eq!(back["edge"][0].sni, dial::MODE_SNI);
        // 落盘只含 SERIAL_POOLS 三池 + mirrors
        assert!(!b.contains("fastly") && !b.contains("codeload"));
    }

    #[test]
    fn notify_persist_writes_on_change_and_skips_noop() {
        // 变更驱动落盘(42b7923): 真变更 → 去抖 2s 内写盘; no-op → 不写盘。
        // 静默失败形态的回归钉(2026-10-17 QA): kick/dirty 任一环回归都无报错,
        // 用户感知滞后到下次重启表序复原才爆发 —— 此测试就是防它
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        serial_load(&dir, None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        start_persist(&rt);
        let head_before = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap()[0].ip.clone()
        };
        let target = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap()[2].ip.clone()
        };
        assert_ne!(head_before, target, "测试前提: 目标条目不在表头");
        serial_note("core", &target, "ok");
        rt.block_on(async { tokio::time::sleep(Duration::from_secs(3)).await });
        assert_eq!(
            SERIAL.lock().unwrap().as_ref().unwrap().pools.get("core").unwrap()[0].ip,
            target,
            "置顶应已生效"
        );
        let file1 = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(file1.contains(&target), "变更应落盘");
        // no-op: 表头再置顶 = 顺序不变 → 不置 dirty → 不写盘
        let snap_before = plans_snapshot();
        serial_note("core", &target, "ok");
        rt.block_on(async { tokio::time::sleep(Duration::from_secs(3)).await });
        assert_eq!(plans_snapshot(), snap_before, "no-op 不应触发写盘");
    }

    #[test]
    fn mirror_chain_load_and_topup() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        // 用户手改链：含一个池外镜像（应被丢弃）；缺 media host（应用默认链）
        std::fs::write(
            &dir.join("plans.json"),
            r#"{
  "core": [{"ip": "140.82.112.3", "sni": "baidu.com"}],
  "mirrors": {
    "raw.githubusercontent.com": ["https://v4.gh-proxy.org", "https://evil.example.com"],
    "not-a-content.host": ["https://v4.gh-proxy.org"]
  }
}"#,
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Some(log));
        // 链：池外镜像被滤，其余保留；新镜像补缺追加尾部
        let raw_chain = mirror_chain("raw.githubusercontent.com");
        assert_eq!(raw_chain[0], "https://v4.gh-proxy.org", "用户手改链头保留");
        assert!(
            !raw_chain.iter().any(|m| m.contains("evil")),
            "池外镜像应被丢弃: {raw_chain:?}"
        );
        assert_eq!(raw_chain.len(), MIRRORS.len(), "补缺后应覆盖全池");
        // 未手改的 host 用默认链
        let media_chain = mirror_chain("media.githubusercontent.com");
        let def: Vec<String> = DEFAULT_CHAINS
            .iter()
            .find(|(h, _)| *h == "media.githubusercontent.com")
            .unwrap()
            .1
            .iter()
            .map(|m| m.to_string())
            .collect();
        assert_eq!(media_chain, def);
        // 未知 host 不落盘
        let b = std::fs::read_to_string(dir.join("plans.json")).unwrap();
        assert!(!b.contains("not-a-content.host"), "未知 host 应丢弃: {b}");
        assert!(b.contains("\"mirrors\""), "镜像链应落盘");
        // set_mirror_chain：链真变更置 dirty，同链 no-op
        let mut new_chain = raw_chain.clone();
        new_chain.reverse();
        assert!(
            set_mirror_chain("raw.githubusercontent.com", &new_chain, "测试"),
            "新链应写入"
        );
        assert!(
            !set_mirror_chain("raw.githubusercontent.com", &new_chain, "测试"),
            "同链应 no-op"
        );
        assert!(
            !set_mirror_chain("github.githubassets.com", &new_chain, "测试"),
            "非内容域 host 应拒收"
        );
    }

    #[test]
    fn noop_move_no_write_and_head_rotation_logs() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let log: LogFn = Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string()));
        serial_load(&dir, Some(log));
        let base_len = seen.lock().unwrap().len(); // 初始表日志条数
        let base = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap().clone()
        };
        let head = base[0].ip.clone();
        // 同 IP 重复置顶：顺序没变 → 不写盘、不打日志
        serial_note("core", &head, "ok");
        {
            let g = SERIAL.lock().unwrap();
            assert!(!g.as_ref().unwrap().dirty, "顺序没变不该置 dirty");
        }
        assert_eq!(seen.lock().unwrap().len(), base_len, "顺序没变不该打日志");
        // 换 IP 置顶：表头真变 → dirty + 一行轮换日志(带原因)
        let other = base[4].ip.clone();
        serial_note("core", &other, "ok");
        {
            let g = SERIAL.lock().unwrap();
            assert!(g.as_ref().unwrap().dirty, "表头轮换该置 dirty");
            let ps = g.as_ref().unwrap().pools.get("core").unwrap();
            assert_eq!(ps[0].ip, other, "新表头应是置顶 IP");
        }
        let lines = seen.lock().unwrap();
        assert!(
            lines[base_len..].iter().any(|l| l.contains("表头")
                && l.contains(&head)
                && l.contains(&other)
                && l.contains("ok")),
            "应打一行带原因的表头轮换日志: {:?}",
            &lines[base_len..]
        );
    }

    #[test]
    fn serial_moves() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmpdir();
        reset_state(&dir);
        let base = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap().clone()
        };
        assert!(base.len() >= 6, "初始表过小: {}", base.len());
        let key = base[3].clone();
        // 拨号层失败垫底（单条）
        serial_move("core", |p| *p == key, false, "test");
        let last = {
            let g = SERIAL.lock().unwrap();
            g.as_ref()
                .unwrap()
                .pools
                .get("core")
                .unwrap()
                .last()
                .unwrap()
                .clone()
        };
        assert_eq!(last, key, "失败条目应在表尾");
        // 数据层 ok 置顶（整 IP）
        let ip0 = base[0].ip.clone();
        serial_move("core", |p| p.ip == ip0, true, "ok");
        let head = {
            let g = SERIAL.lock().unwrap();
            g.as_ref().unwrap().pools.get("core").unwrap()[0].clone()
        };
        assert_eq!(head.ip, ip0);
    }
}
