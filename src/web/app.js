/* Viaduct 工作台前端: 状态轮询 + 连通性探针 + 日志增量 + 规则/池/设置管理。
   所有开关一律由状态对象 S 驱动, 不解析按钮文字(双击/慢响应下会串状态)。 */
const $ = id => document.getElementById(id);
let logSeq = 0;
let S = { running: false, mitm: false, port: 7810 };

const titles = {
  overview: ['概览', '代理状态与 GitHub 连通性一览'],
  pools:    ['IP 池', '三组域名分池管理 · TLS 真证书测速'],
  logs:     ['运行日志', '实时运行日志 · 增量拉取'],
  settings: ['设置', '应用行为偏好 · 分流接管 · MITM'],
};

async function copyText(t) {
  if (!t) return;
  // 桌面壳内: window.ipc 由 wry 注入, Rust 侧直接写系统剪贴板 —— WebView2
  // 的 clipboard API/execCommand 会被权限假成功, 所以壳内一律 IPC 优先;
  // 浏览器直接打开时(无 window.ipc)才走网页 API。
  if (window.ipc) {
    try { window.ipc.postMessage('copy:' + t); toast('已复制'); }
    catch (e) { toast('复制失败'); }
    return;
  }
  let ok = false;
  try { await navigator.clipboard.writeText(t); ok = true; } catch (e) {}
  if (!ok) {
    try {
      const ta = document.createElement('textarea');
      ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.focus(); ta.select();
      ok = document.execCommand('copy'); ta.remove();
    } catch (e) {}
  }
  toast(ok ? '已复制' : '复制失败, 请手动选中复制');
}

/* hash 路由 */
function route() {
  const view = (location.hash || '#overview').slice(1);
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const el = $('view-' + view);
  if (el) el.classList.add('active');
  document.querySelectorAll('.item').forEach(a => a.classList.toggle('active', a.dataset.view === view));
  const t = titles[view] || titles.overview;
  $('pageTitle').textContent = t[0];
  $('pageSub').textContent = t[1];
}
window.onhashchange = route;

/* ---------- 状态轮询 ---------- */
function badge(id, on, onText, offText) {
  const b = $(id);
  b.textContent = on ? onText : offText;
  b.classList.toggle('on', on);
}
async function refreshStatus() {
  let s;
  try { s = await (await fetch('/api/status')).json(); } catch (e) { return; }
  S = { running: s.running, mitm: s.mitm, port: s.port };

  $('dot').classList.toggle('on', s.running);
  $('footState').textContent = s.running ? '运行中' : '已停止';
  $('footPort').textContent = '127.0.0.1:' + s.port;
  if (s.version) $('footVer').textContent = 'v' + s.version;
  $('addr').textContent = '127.0.0.1:' + s.port;
  $('sRun').textContent = s.running ? '运行中' : '已停止';
  $('sRun').style.color = s.running ? 'var(--green)' : '';
  $('sPortMeta').textContent = '127.0.0.1:' + s.port;

  badge('bMitm', s.mitm, 'MITM 开', 'MITM 关');
  $('sDomains').textContent = '分流域名 ' + s.domainCount + ' 个';

  $('mitmBtn').className = 'btn ' + (s.mitm ? 'danger' : 'primary');
  $('mitmBtn').textContent = s.mitm ? '关闭' : '开启';

  /* IP 池卡片: 顺序即优先级, 表头即正在所用(2026-10-12 用户裁定: 不显示颜色/动画) */
  const poolOrder = ['core', 'api', 'edge'];
  const poolLabel = {core: 'core · 主站', api: 'api · API', edge: 'edge · 授权/静态/头像'};
  let sp;
  try { sp = await (await fetch('/api/pools')).json(); } catch (e) { return; }
  const total = poolOrder.reduce((a, n) => a + ((sp[n] || []).length), 0);
  $('sPoolCount').textContent = total;
  $('sPoolCount').style.color = total ? 'var(--green)' : '';
  $('navPools').textContent = total;
  $('poolCards').innerHTML = poolOrder.map(name => {
    const items = sp[name] || [];
    const shown = items.slice(0, 9);
    const chips = shown.length
      ? '<div class="chips">' + shown.map(p =>
          '<span class="chip"><span>' + p.ip + '</span><span class="ms">' +
          (p.sni || '自动') + '</span></span>'
        ).join('') + (items.length > 9 ? '<div class="hint" style="margin:4px 0 0">…其余 ' + (items.length - 9) + ' 条按序候补</div>' : '') + '</div>'
      : '<div class="pool-empty">表空: 手动往 plans.json 加候选(改完重启生效)</div>';
    return '<div class="panel pool-card">' +
      '<div class="pool-head"><span class="pool-name">' + (poolLabel[name] || name) + '</span>' +
      '<span class="pool-count">' + items.length + ' 候选</span></div>' +
      chips + '</div>';
  }).join('');
}

/* ---------- 日志增量 ---------- */
async function refreshLogs() {
  let d;
  try { d = await (await fetch('/api/logs?after=' + logSeq)).json(); } catch (e) { return; }
  if (d.logs.length) {
    const lines = d.logs.map(x => x[1]);
    const box = $('logsBox');
    const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 4;
    box.textContent += lines.join('\n') + '\n';
    while (box.textContent.split('\n').length > 400) box.textContent = box.textContent.split('\n').slice(1).join('\n');
    if ($('autoScroll').checked && atBottom) box.scrollTop = box.scrollHeight;
    $('logsMini').textContent = lines.slice(-6).join('\n');
  }
  logSeq = d.latest;
}


/* ---------- 开关 ---------- */
async function postJSON(url, body) {
  return (await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body || {})})).json();
}

async function toggleMitm(on) {
  const r = await postJSON('/api/mitm', {on});
  if (!r.ok) alert('操作失败: ' + (r.error || ''));
  else toast(on ? 'MITM 已开启, 重启浏览器后生效' : 'MITM 已关闭');
  refreshStatus();
}
$('mitmBtn').onclick = () => toggleMitm(!S.mitm);

// poolRefresh 已移除: 串发模式按 plans.json 演化, 无换血刷新

/* ---------- 设置页 ---------- */
async function refreshSettings() {
  let s;
  try { s = await (await fetch('/api/settings')).json(); } catch (e) { return; }
  $('swAutostart').checked = s.autostart;
  $('swTray').checked = s.closeToTray;
  $('swGh').checked = s.githubPAC !== false; // 旧版无此键时维持缺省(开)
}
async function setSetting(path, on) {
  const r = await postJSON(path, {on});
  if (!r.ok) { alert('设置失败: ' + (r.error || '')); }
  refreshSettings();
}
$('swAutostart').onchange = e => setSetting('/api/settings/autostart', e.target.checked);
$('swTray').onchange = e => setSetting('/api/settings/closeToTray', e.target.checked);
$('swGh').onchange = e => setSetting('/api/settings/githubPAC', e.target.checked);

/* ---------- 镜像链校准 ---------- */
// 半自动: 点击 -> 后端按内置模板对每条镜像链串行实测 TTFB -> 按成绩重排
// 各资源链序并写盘 -> 返回人读报告。全程约 30~90s, 期间按钮禁用。
$('calBtn').onclick = async () => {
  const btn = $('calBtn'), box = $('calResult');
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = '校准中…';
  box.style.display = 'block';
  box.textContent = '正在逐个实测各镜像速度(每资源串行, 约 30~90 秒)…';
  try {
    const r = await fetch('/api/calibrate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
    const text = await r.text();
    box.textContent = text.trim() || '校准完成(无结果)';
    toast('镜像链校准完成, 新顺序已保存');
    refreshLogs();
  } catch (e) {
    box.textContent = '校准失败: ' + e;
  }
  btn.disabled = false;
  btn.textContent = old;
};

/* ---------- 启动 ---------- */
route(); refreshStatus(); refreshLogs(); refreshSettings();
// 页面在后台(挂托盘/切走)时完全停轮询 —— 后台零请求
setInterval(() => { if (!document.hidden) refreshStatus(); }, 2000);
setInterval(() => { if (!document.hidden) refreshLogs(); }, 2000);
