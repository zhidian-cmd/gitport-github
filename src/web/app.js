/* GitPort GitHub 工作台前端: 状态轮询 + 连通性探针 + 日志增量 + 规则/池/设置管理；开关一律由状态对象 S 驱动，不解析按钮文字（双击/慢响应下会串状态）。 */
const $ = id => document.getElementById(id);

/* toast（2026-10-18 补：此前函数定义丢失，toast 调用抛 ReferenceError 被 copyText 的 try/catch 静默吞掉） */
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
  // 壳内 window.ipc 由 wry 注入、Rust 直写剪贴板（WebView2 的 clipboard API/execCommand 会权限假成功）；浏览器无 ipc 才走网页 API。
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
  // 顺序即优先级：降级类（冷却/垫底/拦截）先判黄——红先判则黄永远走不到（2026-10-18 实测只看到红绿）。
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

// poolRefresh 已移除: 串发模式按 routes.json 演化, 无换血刷新

/* ---------- 设置页 ---------- */
function applySettings(s) {
  $('swAutostart').checked = s.autostart;
  $('swTray').checked = s.closeToTray;
  $('swGh').checked = s.githubPAC !== false; // 旧版无此键时维持缺省(开)
}
function applyMirrors(s) {
  MIRRORS = (s.workerMirrors || []).map(w => ({url: w.url, on: !!w.on, trusted: !!w.trusted}));
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
   启动/关闭只增删 routes.json 镜像链成员，注册表不受影响。 */
let MIRRORS = [];
const TRASH_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v6M14 11v6"/></svg>';
// HTML 属性转义五个字符实体缺一不可——曾把 & < > " 原样返回，镜像 URL 里的 "><script> 逃逸 value="" 执行（注入面）。
const escAttr = s => String(s).replace(/[&<>"']/g, c => ({'&':'\u0026amp;','<':'\u0026lt;','>':'\u0026gt;','"':'\u0026quot;',"'":'\u0026#39;'}[c]));

function renderMirrors() {
  $('mirrorRows').innerHTML = MIRRORS.length
    ? MIRRORS.map((m, i) => mirrorRow(m, i)).join('')
    : '<div class="pool-empty">还没有自定义镜像——点下方「＋ 添加镜像」，填入地址后点「启动」</div>';
}

function mirrorRow(m, i) {
  const toggle = m.on ? '关闭' : '启动';
  const cls = m.on ? 'btn sm' : 'btn sm primary';
  const trust = '<label class="trust-label" title="信任此镜像：带签名(github 302 落点)的下载地址也放行给它。签名等效 1 小时提货凭证，仅对你完全信任的自建/无日志镜像开启。">' +
    '<input type="checkbox" data-act="trust" data-idx="' + i + '"' + (m.trusted ? ' checked' : '') + '>信任</label>';
  return '<div class="mirror-row">' +
    '<input type="text" class="text-input" value="' + escAttr(m.url) + '" data-idx="' + i + '" placeholder="https://your-worker.example.com" spellcheck="false" autocomplete="off">' +
    trust +
    '<button class="' + cls + '" data-act="toggle" data-idx="' + i + '">' + toggle + '</button>' +
    '<button class="icon-btn" data-act="del" data-idx="' + i + '" title="彻底删除（注册表与镜像链一并清除）">' + TRASH_SVG + '</button>' +
    '</div>';
}

async function commitMirrors(opts = {}) {
  // 合并模式(启停/编辑/删除)：先拉最新清单把服务端新增条目并入本地（防旧页面覆盖新收编条目、双窗口下别家新增也保得住）；drop=本次被删 URL，合并时跳过防刚删的被补回。
  const { merge = true, drop = null } = opts;
  if (merge) {
    try {
      const s = await (await fetch('/api/settings')).json();
      for (const l of (s.workerMirrors || [])) {
        if (drop && l.url === drop) continue;
        if (!MIRRORS.some(m => m.url === l.url)) MIRRORS.push({url: l.url, on: !!l.on});
      }
    } catch (e) { /* 拉取失败按本地状态提交 */ }
  }
  const mirrors = MIRRORS.filter(m => m.url).map(m => ({url: m.url, on: !!m.on, trusted: !!m.trusted}));
  let r;
  try { r = await postJSON('/api/settings/workerMirrors', {mirrors}); }
  catch (e) { alert('保存失败: ' + e); return; }
  if (!r.ok) { alert('保存失败: ' + (r.error || '')); }
  MIRRORS = (r.workerMirrors || []).map(w => ({url: w.url, on: !!w.on, trusted: !!w.trusted}));
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
    const url = row.url;
    MIRRORS.splice(idx, 1);
    await commitMirrors({ merge: true, drop: url });
    toast('已彻底删除');
  }
});

/* 信任是 checkbox: click 监听只认 button[data-act], 收不到它——单独挂 change。 */
$('mirrorRows').addEventListener('change', async e => {
  if (!e.target.matches('input[data-act="trust"]')) return;
  const row = MIRRORS[+e.target.dataset.idx];
  if (!row) return;
  row.trusted = e.target.checked;
  await commitMirrors();
});

$('mirrorRows').addEventListener('input', e => {
  // 只认文本框: trust checkbox 同样带 data-idx, 但没有 url 语义
  if (e.target.matches('input[type="text"][data-idx]')) {
    const idx = +e.target.dataset.idx;
    if (MIRRORS[idx]) MIRRORS[idx].url = e.target.value;
  }
});

/* ---------- 路由二部图 ----------
   左列 = IP 节点（伪装身份），右列 = 分流域名（有边的），连线 = 服务关系。
   绿框 = 游标起点，红边 = (ip,host) 边缘拒绝冷却中，节点右上角 = 池内活连接数。 */
let topoSeq = 0;

function renderTopology(d) {
  const box = $('topoBox');
  if (!box) return;
  const NODE_W = 250, NODE_H = 40, NODE_GAP = 10;
  const HOST_W = 210, HOST_H = 26, HOST_GAP = 8;
  const LEFT_X = 8, RIGHT_X = 470, W = 690;
  const nodes = d.nodes || [];
  const hosts = (d.hosts || []).filter(h => !h.direct);
  const hostByKey = {};
  hosts.forEach(h => hostByKey[h.key] = h);
  // 只画有节点服务的 host（无边行不在池路径上）
  const used = new Set();
  nodes.forEach(n => (n.hosts || []).forEach(k => used.add(k)));
  const hostRows = hosts.filter(h => used.has(h.key));
  const leftH = nodes.length * (NODE_H + NODE_GAP);
  const rightH = Math.max(1, hostRows.length) * (HOST_H + HOST_GAP);
  const H = Math.max(leftH, rightH) + 10;

  const nodeY = i => 6 + i * (NODE_H + NODE_GAP);
  const hostY = i => 6 + i * (HOST_H + HOST_GAP);
  const center = y => y + 16;

  let edgesSvg = '';
  // 节点多 host 的连线从节点右侧散开到各 host 左侧；同节点多条边纵向微散
  nodes.forEach((n, i) => {
    const y = nodeY(i);
    (n.hosts || []).forEach(k => {
      const hi = hostRows.findIndex(h => h.key === k);
      if (hi < 0) return;
      const hy = center(hostY(hi));
      const ny = center(y) + ((n.hosts.length > 1 ? (n.hosts.indexOf(k) - (n.hosts.length - 1) / 2) * 6 : 0));
      const bad = (n.bad || 0) > 0 && (n.bad || 0) >= (n.count || 1);
      const partial = (n.bad || 0) > 0 && !bad;
      const live = (n.conns || 0) > 0;
      const stroke = bad ? '#e5534b' : (partial ? '#d29922' : (live ? '#57ab5a' : '#51607a'));
      const dash = bad || partial ? 'stroke-dasharray="5 3"' : '';
      edgesSvg += `<line x1="${LEFT_X + NODE_W}" y1="${ny}" x2="${RIGHT_X}" y2="${hy}" stroke="${stroke}" stroke-width="${live ? 1.6 : 1}" ${dash} opacity="${live ? 0.9 : 0.45}"><title>${escAttr(n.ip)} → ${escAttr(k)}${bad ? '（全节点冷却中）' : partial ? '（部分 IP 冷却中）' : ''}</title></line>`;
    });
  });

  const nodesSvg = nodes.map((n, i) => {
    const y = nodeY(i);
    const bad = (n.bad || 0) > 0 && (n.bad || 0) >= (n.count || 1);
    const partial = (n.bad || 0) > 0 && !bad;
    const live = (n.conns || 0) > 0;
    const border = n.cursor ? '#57ab5a' : bad ? '#e5534b' : live ? '#6cb6ff' : '#3a4450';
    const fill = bad ? 'rgba(229,83,75,.08)' : n.cursor ? 'rgba(87,171,90,.10)' : 'rgba(110,118,129,.08)';
    const tip = `${n.ip}（展开 ${n.count} IP）\nSNI: ${n.sni || '（无）'}\n锚点: ${n.verify || '按目标 host'}\n活连接: ${n.conns || 0}\n服务: ${(n.hosts || []).join(', ')}`;
    return `<g>
      <rect x="${LEFT_X}" y="${y}" width="${NODE_W}" height="${NODE_H}" rx="7" fill="${fill}" stroke="${border}" stroke-width="${n.cursor ? 1.8 : 1}"><title>${escAttr(tip)}</title></rect>
      <text x="${LEFT_X + 10}" y="${y + 17}" font-size="12" fill="${bad ? '#e5534b' : '#d0d7de'}" font-family="Consolas,monospace">${escAttr(n.ip)}${n.count > 1 ? ` ×${n.count}` : ''}</text>
      <text x="${LEFT_X + 10}" y="${y + 32}" font-size="10" fill="#768390">SNI ${escAttr(n.sni || '-')} · 锚点 ${escAttr(n.verify || 'host')}${n.bad ? ` · 坏 ${n.bad}/${n.count}` : ''}</text>
      ${n.conns ? `<text x="${LEFT_X + NODE_W - 8}" y="${y + 17}" font-size="11" fill="#57ab5a" text-anchor="end" font-weight="bold">${n.conns}</text>` : ''}
      ${n.cursor ? `<text x="${LEFT_X + NODE_W - 8}" y="${y + 32}" font-size="9" fill="#57ab5a" text-anchor="end">起点</text>` : ''}
    </g>`;
  }).join('');

  const hostsSvg = hostRows.map((h, i) => {
    const y = hostY(i);
    const marks = [h.content ? '内容' : '', h.fallback === 'mirror' ? '镜像兜底' : ''].filter(Boolean).join(' · ');
    return `<g>
      <rect x="${RIGHT_X}" y="${y}" width="${HOST_W}" height="${HOST_H}" rx="6" fill="rgba(110,118,129,.10)" stroke="#3a4450"><title>${escAttr(h.key)}${marks ? '\n' + marks : ''}</title></rect>
      <text x="${RIGHT_X + 10}" y="${y + 17}" font-size="11" fill="#c9d1d9" font-family="Consolas,monospace">${escAttr(h.key)}</text>
      ${marks ? `<text x="${RIGHT_X + HOST_W - 8}" y="${y + 17}" font-size="9" fill="#768390" text-anchor="end">${escAttr(marks)}</text>` : ''}
    </g>`;
  }).join('');

  const seq = ++topoSeq;
  if (seq !== topoSeq) return; // 防陈旧渲染覆盖
  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;display:block" font-family="system-ui,sans-serif">
    ${edgesSvg}${nodesSvg}${hostsSvg}</svg>`;
}

async function refreshTopology() {
  let d;
  try { d = await (await fetch('/api/topology')).json(); } catch (e) { return; }
  renderTopology(d);
}

/* ---------- 图片链校准 ---------- */
// 半自动校准：点击 → 后端按内置模板对图片(小文件)链逐镜像串行实测 TTFB → 按成绩重排链序写盘 → 返回人读报告（约 30~90s，期间按钮禁用）。
// 大文件链不校准：速度学习由代理的实时流量调度(ECT)自动完成，无需手动。
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
route(); refreshStatus(); refreshLogs(); refreshSettings(); refreshTopology();
// 页面在后台(挂托盘/切走)时完全停轮询 —— 后台零请求
setInterval(() => { if (!document.hidden) refreshStatus(); }, 2000);
setInterval(() => { if (!document.hidden) refreshLogs(); }, 2000);
setInterval(() => { if (!document.hidden) refreshTopology(); }, 10000);
