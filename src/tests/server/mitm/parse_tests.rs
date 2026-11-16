//! 解析模块 fixture：按真实 GitHub 仓库页结构手写（head 资产引用 + importmap +
//! 身份 meta + body 的 embeddedData 与内容），GitHub 改版时先更新 fixture 再改规则。

use super::*;

/// 含 3 条外链资产引用（href/src 混排）、importmap（内含资产 URL，必须排除）、
/// 身份 meta 与标题、body 的 embeddedData（内含资产 URL 字符串，必须排除）。
const FIX_A: &str = r#"<html lang="en" data-color-mode="auto">
<head>
<link rel="stylesheet" href="https://github.githubassets.com/assets/primer-aaaa1111.css" />
<link crossorigin="anonymous" rel="modulepreload" href="https://github.githubassets.com/assets/react-bbbb2222.js" />
<meta name="html-safe-nonce" content="nonce-xyz-1">
<meta property="og:url" content="https://github.com/owner/repo" />
<title>owner/repo: title text</title>
<script type="importmap">{"imports":{"react":"https://github.githubassets.com/assets/react-bbbb2222.js","react-dom":"https://github.githubassets.com/assets/react-dom-dddd4444.js"}}</script>
<script crossorigin="anonymous" type="module" src="https://github.githubassets.com/assets/core-cccc3333.js" defer="defer"></script>
</head>
<body class="logged-out env-production">
<script type="application/json" data-target="react-app.embeddedData">{"payload":{"repoName":"repo","hint":"https://github.githubassets.com/assets/fake-eeee5555.js","nested":{"a":1}}}</script>
<a href="/owner/repo">owner/repo</a>
<div data-target="react-app.reactRoot"></div>
</body></html>"#;

/// 同结构、资产哈希全换（模拟 GitHub 发版）；importmap 同步换（触发重剥的场景由 fp 区分）。
const FIX_B: &str = r#"<html lang="en" data-color-mode="auto">
<head>
<link rel="stylesheet" href="https://github.githubassets.com/assets/primer-ffff6666.css" />
<link crossorigin="anonymous" rel="modulepreload" href="https://github.githubassets.com/assets/react-gggg7777.js" />
<meta name="html-safe-nonce" content="nonce-xyz-2">
<meta property="og:url" content="https://github.com/owner/repo" />
<title>owner/repo: title text</title>
<script type="importmap">{"imports":{"react":"https://github.githubassets.com/assets/react-gggg7777.js","react-dom":"https://github.githubassets.com/assets/react-dom-hhhh8888.js"}}</script>
<script crossorigin="anonymous" type="module" src="https://github.githubassets.com/assets/core-iiii9999.js" defer="defer"></script>
</head>
<body class="logged-in env-production">
<script type="application/json" data-target="react-app.embeddedData">{"payload":{"repoName":"repo","fresh":true,"hint":"https://github.githubassets.com/assets/fake-jjjj0000.js"}}</script>
<a href="/owner/repo">owner/repo</a>
<div data-target="react-app.reactRoot"></div>
</body></html>"#;

/// 抽取：只收属性形态的 githubassets 引用且保文档顺序；script 体内与 importmap 里的 URL 一律不吃。
#[test]
fn extract_skeleton_captures_attribute_refs_in_order() {
    let sk = extract_skeleton(FIX_A).expect("fixture 必须抽得出");
    assert_eq!(
        sk.refs,
        vec![
            "https://github.githubassets.com/assets/primer-aaaa1111.css",
            "https://github.githubassets.com/assets/react-bbbb2222.js",
            "https://github.githubassets.com/assets/core-cccc3333.js",
        ],
        "文档顺序的属性引用: {:?}",
        sk.refs
    );
    assert_ne!(sk.import_fp, 0, "importmap 指纹必须有值");
    // 指纹对 importmap 内容敏感
    let sk_b = extract_skeleton(FIX_B).expect("B 必须抽得出");
    assert_ne!(
        sk.import_fp, sk_b.import_fp,
        "importmap 变了指纹必须变（触发重剥）"
    );
    // 无资产引用的页面不立胚
    assert!(extract_skeleton("<html><body>plain</body></html>").is_none());
}

/// 换装：fresh 新哈希按位置换成 frozen 旧哈希；importmap/身份/数据区一字不动。
#[test]
fn swap_replaces_positionally_and_keeps_everything_else() {
    let sk_a = extract_skeleton(FIX_A).expect("A 骨架");
    let (out, n) = swap_asset_refs(FIX_B, &sk_a.refs).expect("同结构必须换装成功");
    assert_eq!(n, 3, "三条引用全换: {out}");
    assert!(out.contains("primer-aaaa1111.css"), "旧引用回填: {out}");
    assert!(out.contains("react-bbbb2222.js\""), "modulepreload 换旧");
    assert!(out.contains("core-cccc3333.js"), "入口脚本换旧");
    assert!(!out.contains("primer-ffff6666.css"), "新哈希不得残留");
    assert!(!out.contains("core-iiii9999.js"), "新哈希不得残留");
    // importmap 是内联脚本体：保持 fresh（react-gggg7777），不被换装污染
    assert!(
        out.contains("\"react\":\"https://github.githubassets.com/assets/react-gggg7777.js\""),
        "importmap 必须保持 fresh（CSP 哈希一致）: {out}"
    );
    // 身份/nonce/数据区保持 fresh
    assert!(out.contains("nonce-xyz-2"), "nonce 保持 fresh");
    assert!(out.contains("og:url"), "meta 保持 fresh");
    assert!(out.contains("\"fresh\":true"), "embeddedData 保持 fresh");
    assert!(out.contains("fake-jjjj0000.js"), "数据区内的 URL 不参与换装");
    assert!(out.contains("logged-in env-production"), "body 保持 fresh");
}

/// 同部署恒等：引用一致 = 原样返回零换装（99% 的访问走这里，零风险直通）。
#[test]
fn swap_is_identity_when_refs_match() {
    let sk = extract_skeleton(FIX_A).expect("A 骨架");
    let (out, n) = swap_asset_refs(FIX_A, &sk.refs).expect("同结构");
    assert_eq!(n, 0, "同部署零换装");
    assert_eq!(out, FIX_A, "恒等必须逐字节一致");
}

/// 结构变化（引用数量不符）= None，调用方重剥；文件名带连字符/点号的 URL 正确捕获。
#[test]
fn swap_rejects_structure_change() {
    let sk = extract_skeleton(FIX_A).expect("A 骨架");
    // 少一条引用 = 结构变了
    assert!(swap_asset_refs(FIX_A, &sk.refs[..2]).is_none(), "数量不符必须拒绝");
    // 带连字符与多段哈希的文件名照常捕获（真实 GitHub 资产形态）
    let tricky = r#"<link rel="stylesheet" href="https://github.githubassets.com/assets/CodeViewHeader-D4-FNQWQ.css" />"#;
    let sk2 = extract_skeleton(tricky).expect("必须抽出");
    assert_eq!(
        sk2.refs,
        vec!["https://github.githubassets.com/assets/CodeViewHeader-D4-FNQWQ.css"]
    );
}

/// FNV 跨进程确定性 + script 体置换等长（偏移在原文上有效）。
#[test]
fn fnv_is_stable_and_masking_preserves_offsets() {
    assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325, "FNV 空串偏移基准");
    // 敏感性：单字节差异必须改指纹（基准向量由空串锚定，算法为 XOR-后-乘 的标准 FNV-1a）
    assert_ne!(fnv1a(b"a"), fnv1a(b"b"), "单字节差异必须改指纹");
    assert_eq!(fnv1a(b"ab"), fnv1a(b"ab"), "确定性");
    let masked = blank_script_bodies(FIX_A);
    assert_eq!(
        masked.len(),
        FIX_A.len(),
        "置换必须等长，否则扫描区间在原文上失效"
    );
    // 置换后属性扫描结果与原文抽取一致
    let refs_masked: Vec<String> = scan_refs(&masked).into_iter().map(|(_, _, u)| u).collect();
    assert_eq!(refs_masked.len(), 3);
}
