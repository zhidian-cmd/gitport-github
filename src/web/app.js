/* GitPort GitHub 工作台前端: 状态轮询 + 连通性探针 + 日志增量 + 规则/池/设置管理。
   所有开关一律由状态对象 S 驱动, 不解析按钮文字(双击/慢响应下会串状态)。 */
const $ = id => document.getElementById(id);

/* toast 提示（2026-10-18 补：函数定义此前丢失，所有 toast 调用抛
   ReferenceError——copyText 的 try/catch 把它静默吞掉，校准/MITM 路径上
   则暴露为"TypeError: toast is not a function"） */
let toastTimer = null;
function toast(msg) {
  const el = $('toast');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2200);
}
let logSeq = 0;
let S = { running: false, mitm: false, port: 7810 };

const titles = {
  overview: ['概览', '代理状态与 GitHub 连通性一览'],
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

  /* 串发候选总数：概览只留一个数；明细页已删（显示不全且无操作价值） */
  const total = s.poolTotal || 0;
  $('sPoolCount').textContent = total;
  $('sPoolCount').style.color = total ? 'var(--green)' : '';
}

/* ---------- 日志增量 ---------- */
/* 日志行着色：按关键字分级（纯前端，零额外请求） */
function logTone(l) {
  // 顺序即优先级：降级类（冷却/垫底/拦截）先判黄 —— 这些行常同时含“超时/失败”，
  // 若红先判，黄色永远走不到（2026-10-18 实测：用户只看到红绿）。
  if (/冷却|垫底|降权|拦截|假页|退化|注入/.test(l)) return 'warn';
  if (/失败|错误|全灭|超时|拒绝|状态 [45]\d\d/.test(l)) return 'err';
  if (/via |握手|复用连接|新连接|已解密|成功|已保存/.test(l)) return 'ok';
  return '';
}

async function refreshLogs() {
  let d;
  try { d = await (await fetch('/api/logs?after=' + logSeq)).json(); } catch (e) { return; }
  if (d.logs.length) {
    const lines = d.logs.map(x => x[1]);
    const box = $('logsBox');
    const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 4;
    const frag = document.createDocumentFragment();
    for (const l of lines) {
      const row = document.createElement('div');
      row.className = 'lg ' + logTone(l);
      row.textContent = l;
      frag.appendChild(row);
    }
    box.appendChild(frag);
    while (box.childElementCount > 400) box.removeChild(box.firstChild);
    if ($('autoScroll').checked && atBottom) box.scrollTop = box.scrollHeight;
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
async function runCal(mode, btn, label) {
  const box = $('calResult');
  btn.disabled = true;
  box.style.display = 'block';
  try {
    const r = await fetch('/api/calibrate?mode=' + mode, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
    const text = await r.text();
    box.textContent = text;
    toast(label + '校准已在后台开始');
    refreshLogs();
    // 后台任务完成前轮询状态；完成后把排序结果（各镜像实测值）回显出来
    const timer = setInterval(async () => {
      try {
        const st = await (await fetch('/api/calibrate')).json();
        if (st.running) { box.textContent = label + '校准中…（进度见「运行日志」页）'; return; }
        clearInterval(timer);
        box.textContent = st.report || label + '校准完成（无可校准的链）';
        toast(label + '校准完成');
        refreshLogs();
      } catch (e) { /* 网络抖动继续轮询 */ }
    }, 1500);
  } catch (e) {
    box.textContent = '校准启动失败: ' + e;
  }
  btn.disabled = false; // 校准已后台化，按钮立即恢复（防重入在服务端）
}
$('calBigBtn').onclick = () => runCal('throughput', $('calBigBtn'), '大文件链');
$('calImgBtn').onclick = () => runCal('ttfb', $('calImgBtn'), '图片链');

/* ---------- 启动 ---------- */
route(); refreshStatus(); refreshLogs(); refreshSettings();
// 页面在后台(挂托盘/切走)时完全停轮询 —— 后台零请求
setInterval(() => { if (!document.hidden) refreshStatus(); }, 2000);
setInterval(() => { if (!document.hidden) refreshLogs(); }, 2000);
