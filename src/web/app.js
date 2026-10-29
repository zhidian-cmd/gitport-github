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
  if ((location.hash || '#overview') === '#mirrors') refreshSettings();
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
  return (await fetch(url, {method:'POST', headers:{'Content-Type':'application/json','X-GitPort-Request':'1'}, body: JSON.stringify(body || {})})).json();
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
function applySettings(s) {
  $('swAutostart').checked = s.autostart;
  $('swTray').checked = s.closeToTray;
  $('swGh').checked = s.githubPAC !== false; // 旧版无此键时维持缺省(开)
}
function applyMirrors(s) {
  MIRRORS = (s.workerMirrors || []).map(w => ({url: w.url, on: !!w.on}));
  renderMirrors();
}
/* 一次 /api/settings 喂两边：开关回显 + 镜像列表（启动与切页都不再拉两次） */
async function refreshSettings() {
  let s;
  try { s = await (await fetch('/api/settings')).json(); } catch (e) { return; }
  applySettings(s);
  applyMirrors(s);
}
/* 开关乐观翻转：失败只回滚本开关，不再整页重拉 */
async function setSetting(path, on, el) {
  const r = await postJSON(path, {on});
  if (!r.ok) { el.checked = !on; alert('设置失败: ' + (r.error || '')); }
}
$('swAutostart').onchange = e => setSetting('/api/settings/autostart', e.target.checked, e.target);
$('swTray').onchange = e => setSetting('/api/settings/closeToTray', e.target.checked, e.target);
$('swGh').onchange = e => setSetting('/api/settings/githubPAC', e.target.checked, e.target);

/* ---------- 自定义镜像注册表 ----------
   settings.json 永久记录全部网址（点垃圾桶才彻底消失）；
   启动/关闭只增删 plans.json 镜像链成员，注册表不受影响。 */
let MIRRORS = [];
const TRASH_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v6M14 11v6"/></svg>';
// HTML 属性转义：五个预定义字符实体一个都不能少——少一个就是一条注入面
// （曾把 & < > " 原样返回，镜像 URL 里的 "><script> 直接逃逸 value="" 属性执行）。
const escAttr = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function renderMirrors() {
  $('mirrorRows').innerHTML = MIRRORS.length
    ? MIRRORS.map((m, i) => mirrorRow(m, i)).join('')
    : '<div class="pool-empty">还没有自定义镜像——点下方「＋ 添加镜像」，填入地址后点「启动」</div>';
}

function mirrorRow(m, i) {
  const toggle = m.on ? '关闭' : '启动';
  const cls = m.on ? 'btn sm' : 'btn sm primary';
  return '<div class="mirror-row">' +
    '<input type="text" class="text-input" value="' + escAttr(m.url) + '" data-idx="' + i + '" placeholder="https://your-worker.example.com" spellcheck="false" autocomplete="off">' +
    '<button class="' + cls + '" data-act="toggle" data-idx="' + i + '">' + toggle + '</button>' +
    '<button class="icon-btn" data-act="del" data-idx="' + i + '" title="彻底删除（注册表与镜像链一并清除）">' + TRASH_SVG + '</button>' +
    '</div>';
}

async function commitMirrors(merge = true) {
  // 合并模式(启停/编辑):先拉最新清单,服务端新增条目并入本地,防旧页面
  // 覆盖新收编条目。删除路径传 merge=false:本地已 splice,合并会把刚删的
  // 条目从服务端补回来,删除就失效了。
  if (merge) {
    try {
      const s = await (await fetch('/api/settings')).json();
      for (const l of (s.workerMirrors || [])) {
        if (!MIRRORS.some(m => m.url === l.url)) MIRRORS.push({url: l.url, on: !!l.on});
      }
    } catch (e) { /* 拉取失败按本地状态提交 */ }
  }
  const mirrors = MIRRORS.filter(m => m.url).map(m => ({url: m.url, on: !!m.on}));
  let r;
  try { r = await postJSON('/api/settings/workerMirrors', {mirrors}); }
  catch (e) { alert('保存失败: ' + e); return; }
  if (!r.ok) { alert('保存失败: ' + (r.error || '')); }
  MIRRORS = (r.workerMirrors || []).map(w => ({url: w.url, on: !!w.on}));
  renderMirrors();
}

$('mirrorAdd').onclick = () => {
  MIRRORS.push({url: '', on: false});
  renderMirrors();
  const inputs = $('mirrorRows').querySelectorAll('input[data-idx]');
  if (inputs.length) inputs[inputs.length - 1].focus();
};

$('mirrorRows').addEventListener('click', async e => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const idx = +btn.dataset.idx;
  const row = MIRRORS[idx];
  if (!row) return;
  if (btn.dataset.act === 'toggle') {
    const input = $('mirrorRows').querySelector('input[data-idx="' + idx + '"]');
    const url = (input ? input.value : row.url).trim();
    if (!url) { toast('请先填入镜像地址'); return; }
    row.url = url;
    row.on = !row.on;
    await commitMirrors();
  } else if (btn.dataset.act === 'del') {
    MIRRORS.splice(idx, 1);
    await commitMirrors(false);
    toast('已彻底删除');
  }
});

$('mirrorRows').addEventListener('input', e => {
  if (e.target.matches('input[data-idx]')) {
    const idx = +e.target.dataset.idx;
    if (MIRRORS[idx]) MIRRORS[idx].url = e.target.value;
  }
});

/* ---------- 图片链校准 ---------- */
// 半自动: 点击 -> 后端按内置模板对图片(小文件)链逐镜像串行实测 TTFB -> 按成绩重排
// 链序并写盘 -> 返回人读报告。全程约 30~90s, 期间按钮禁用。
// 大文件链不校准: 其速度学习由代理的实时流量调度(ECT)自动完成, 无需手动。
async function runCal(btn) {
  const box = $('calResult');
  btn.disabled = true;
  box.style.display = 'block';
  try {
    const r = await fetch('/api/calibrate', {method: 'POST', headers: {'Content-Type': 'application/json','X-GitPort-Request':'1'}, body: '{}'});
    const text = await r.text();
    box.textContent = text;
    toast('图片链校准已在后台开始');
    refreshLogs();
    // 后台任务完成前轮询状态；完成后把排序结果（各镜像实测值）回显出来
    const timer = setInterval(async () => {
      try {
        const st = await (await fetch('/api/calibrate')).json();
        if (st.running) { box.textContent = '图片链校准中…（进度见「运行日志」页）'; return; }
        clearInterval(timer);
        box.textContent = st.report || '图片链校准完成（无可校准的链）';
        toast('图片链校准完成');
        refreshLogs();
      } catch (e) { /* 网络抖动继续轮询 */ }
    }, 1500);
  } catch (e) {
    box.textContent = '校准启动失败: ' + e;
  }
  btn.disabled = false; // 校准已后台化，按钮立即恢复（防重入在服务端）
}
$('calImgBtn').onclick = () => runCal($('calImgBtn'));

/* ---------- 启动 ---------- */
route(); refreshStatus(); refreshLogs(); refreshSettings();
// 页面在后台(挂托盘/切走)时完全停轮询 —— 后台零请求
setInterval(() => { if (!document.hidden) refreshStatus(); }, 2000);
setInterval(() => { if (!document.hidden) refreshLogs(); }, 2000);
