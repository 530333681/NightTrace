/* ============================================================
   NightTrace - front-end logic (vanilla JS, no framework)
   Two views: Process Explorer + Persistence.
   All data shown here comes from the uploaded evidence package.
   Nothing is generated, mocked or pre-filled.
   ============================================================ */
'use strict';

const PAGE_SIZE = 60;

const state = {
  session: null,          // { session, meta, systemInfo, counts, ... }
  processes: [],
  persistence: [],
  view: 'upload',
  proc: { q: '', onlyFlagged: false, onlyNoPath: false, user: '', sortKey: 'flags', sortDir: 'desc', page: 1 },
  pers: { q: '', kind: '', onlyFlagged: false, sortKey: 'flags', sortDir: 'desc', page: 1 },
};

/* ============================================================
   Small helpers
   ============================================================ */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function isBlank(v) {
  return v === null || v === undefined || String(v).trim() === '' || String(v).trim().toLowerCase() === 'null';
}

function fmtBytes(n) {
  if (!n && n !== 0) return '-';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

function fmtTime(value) {
  if (isBlank(value)) return null;
  const d = new Date(value);
  if (isNaN(d.getTime())) return String(value);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function toast(message, type = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = message;
  $('#toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 5200);
}

/* ============================================================
   Heuristics
   Deliberately conservative, rule-based and fully explainable.
   A match is a TRIAGE HINT ("worth a closer look"), never a
   verdict that something is malicious.
   ============================================================ */
const SEV_WEIGHT = { high: 3, warn: 2, info: 1 };

const SYSTEM_DIR_RE = /^[a-z]:\\(windows|program files|program files \(x86\))\\/i;
const USER_WRITABLE_RE = /(\\appdata\\|\\(temp|tmp)\\|\\downloads\\|\\desktop\\|\\documents\\|\\public\\|\\recycle\.bin|\\perflogs\\|\\windows\\temp\\|\\programdata\\|\\users\\public\\)/i;
const SCRIPT_EXT_RE = /\.(ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|scr|pif|jar|lnk)$/i;
const NET_RE = /(https?:\/\/|ftp:\/\/|\\\\[a-z0-9._-]{2,}\\)/i;
const ENCODE_RE = /(-enc(odedcommand)?\s|frombase64string|-nop\b|-w\s+hidden|-windowstyle\s+hidden|iex\s*\(|invoke-expression)/i;
const LOLBIN_RE = /\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|wmic|installutil|msbuild|at\.exe|schtasks)\b/i;
const SYSTEM_BINARIES = new Set([
  'svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe', 'wininit.exe', 'winlogon.exe',
  'smss.exe', 'explorer.exe', 'taskhostw.exe', 'dllhost.exe', 'runtimebroker.exe',
  'spoolsv.exe', 'lsaiso.exe', 'fontdrvhost.exe', 'sihost.exe', 'ctfmon.exe', 'conhost.exe',
]);

/** Locate a path inside a command line (best effort, quoted first). */
function extractPath(command) {
  if (isBlank(command)) return null;
  const text = String(command).trim();
  let m = text.match(/^"([^"]+)"/);
  if (m) return m[1];
  m = text.match(/^'([^']+)'/);
  if (m) return m[1];
  m = text.match(/^([a-zA-Z]:\\[^\s]*)/);
  if (m) return m[1];
  m = text.match(/^([^\s]+\.(?:exe|com|bat|cmd|ps1|vbs|js|dll))/i);
  return m ? m[1] : null;
}

function hint(id, severity, title, detail) {
  return { id, severity, title, detail };
}

function hintTime(value) { return isBlank(value) ? null : fmtTime(value) || String(value); }

/* ---------------- Process rules ---------------- */
function assessProcess(proc, ctx) {
  const hints = [];
  const path = isBlank(proc.ExecutablePath) ? null : proc.ExecutablePath;
  const cmd = isBlank(proc.CommandLine) ? '' : String(proc.CommandLine);
  const name = (proc.Name || '').toLowerCase();

  if (!path) {
    hints.push(hint('no_path', 'info', '镜像路径缺失',
      '无法从 Win32_Process 读取 ExecutablePath。常见原因：进程已退出、采集端权限不足，或该进程由内核驱动创建。非管理员采集时这类记录会明显增多，建议对照命令行与其他数据源确认。'));
  } else {
    if (!SYSTEM_DIR_RE.test(path)) {
      hints.push(hint('non_system_dir', 'info', '不在常规系统目录',
        '镜像文件不在 C:\\Windows 或 C:\\Program Files 下。绝大多数第三方应用、开发工具都装在其他位置，仅作为对照资产的提示。'));
    }
    if (USER_WRITABLE_RE.test(path)) {
      hints.push(hint('user_writable', 'high', '用户可写目录执行',
        '镜像位于临时目录、用户目录或 ProgramData 等普通用户可写位置，此类位置常被用于落地可执行文件，建议核对该文件的来源与签名。'));
    }
    if (SCRIPT_EXT_RE.test(path)) {
      hints.push(hint('script_image', 'warn', '非标准可执行扩展名',
        '镜像路径的扩展名为脚本或容易被滥用的类型，说明实际是由解释器（如 wscript / mshta / rundll32）加载该文件。'));
    }
    const depth = path.replace(/^[a-z]:\\/i, '').split('\\').filter(Boolean).length;
    if (depth === 1) {
      hints.push(hint('drive_root', 'info', '直接位于盘符根目录',
        '可执行文件直接放在盘符根目录，属于比较少见的部署方式，可记录后与资产基线比对。'));
    }
    if (SYSTEM_BINARIES.has(name) && !/\\windows\\(system32|syswow64|winsxs)\\/i.test(path)) {
      hints.push(hint('masquerade', 'high', '系统同名进程路径异常',
        `进程名为 ${proc.Name}（常见的 Windows 核心进程），但镜像路径不在 Windows\\System32 或 SysWOW64 下，建议优先确认其真实来源与数字签名。`));
    }
  }

  if (ENCODE_RE.test(cmd)) {
    hints.push(hint('encoded_cmd', 'warn', '命令行含编码 / 隐藏窗口参数',
      '命令行出现 -EncodedCommand、FromBase64String 或隐藏窗口等参数。管理脚本和不少安装程序也会这样用，但值得展开完整命令行核对。'));
  }
  if (NET_RE.test(cmd)) {
    hints.push(hint('net_cmd', 'info', '命令行包含网络地址',
      '命令行中出现 URL 或 UNC 路径，可核对下载来源是否可信。'));
  }
  if (!isBlank(proc.ParentProcessId) && Number(proc.ParentProcessId) > 4 && ctx && !ctx.pids.has(Number(proc.ParentProcessId))) {
    hints.push(hint('orphan', 'info', '父进程已不存在',
      '父 PID 在当前进程列表中找不到，通常表示父进程已退出，也可能是父进程被清理。'));
  }
  hints.sort((a, b) => SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity]);
  return hints;
}

/* ---------------- Persistence rules ---------------- */
function assessPersistence(item) {
  const hints = [];
  const target = String(item.Target || '');
  const path = extractPath(target) || (/(\\|^[a-z]:)/i.test(target) ? target.split(/\s+/)[0] : null);
  const runAs = String(item.RunAs || '').toLowerCase();

  if (isBlank(item.Target)) {
    if (item.kind === 'run_key') {
      hints.push(hint('no_target', 'warn', '注册表项值为空',
        'Run/RunOnce 条目的名称为空或值为空，属于结构异常的条目，建议直接打开原始 JSON 核对。'));
    } else if (item.kind === 'scheduled_task') {
      hints.push(hint('no_target', 'info', '未采集到可执行动作',
        '该任务没有可解析的 Execute（常见于纯 COM 处理程序动作，或采集权限不足），可在原始记录里查看 Actions 字段。'));
    } else {
      hints.push(hint('no_target', 'info', '未采集到可执行路径',
        'Win32_Service 未返回 PathName，可能是权限不足，也可能是内核驱动类服务本身没有用户态镜像。'));
    }
  } else {
    if (USER_WRITABLE_RE.test(target)) {
      hints.push(hint('user_writable', 'high', '指向用户可写目录',
        '执行命令指向临时目录、用户目录或 ProgramData 等普通用户可写位置，是持久化条目中值得优先核实的形态。'));
    }
    if (ENCODE_RE.test(target)) {
      hints.push(hint('encoded_cmd', 'high', '编码 / 隐藏窗口参数',
        '执行命令包含编码命令或隐藏窗口等参数，建议展开查看完整命令与对应文件。'));
    }
    if (NET_RE.test(target)) {
      hints.push(hint('remote', 'high', '包含远程地址',
        '执行命令中出现 HTTP(S)、FTP 或 UNC 路径，意味着运行时会从远端取回内容，需确认该来源是否受信。'));
    }
    if (LOLBIN_RE.test(target)) {
      hints.push(hint('lolbin', 'warn', '使用解释器 / 系统工具执行',
        '通过 powershell、mshta、rundll32、wscript 等系统自带工具拉起载荷，是常见的绕过手法，同时也是软件安装包的常见做法，需结合上下文判断。'));
    }
    if (path && !SYSTEM_DIR_RE.test(path)) {
      hints.push(hint('non_system_dir', 'info', '执行文件不在常规系统目录',
        '目标路径不在 C:\\Windows 或 C:\\Program Files 下，第三方软件也常如此，作为对照资产的提示。'));
    }
  }

  if (item.kind === 'run_key') {
    if (isBlank(item.LastWriteTime)) {
      hints.push(hint('no_lastwrite', 'info', '注册表键写入时间未采集',
        'v1 采集端未实现注册表键最后写入时间（需要 RegQueryInfoKey P/Invoke），因此无法判断条目创建时间。'));
    }
    if (!isBlank(runAs) && /user hive|hkey_users/i.test(runAs) && /s-1-5-21/i.test(runAs)) {
      hints.push(hint('unmapped_sid', 'info', '账户未能映射为用户名',
        '该 SID 未能在采集主机上映射到本地账户名，可能属于已删除或未加载的配置文件。'));
    }
  }

  if (item.kind === 'scheduled_task') {
    const trig = String(item.Triggers || '').toLowerCase();
    if (/logon|startup|boot/.test(trig)) {
      hints.push(hint('logon_trigger', 'info', '登录 / 开机触发',
        '触发器包含登录或开机事件，这类任务随系统启动而执行，属于需要建立基线的对象。'));
    }
    if (/every\s+pt?\d*m|every\s+\d+\s*minute/.test(trig) || /pt1m|pt5m/.test(trig)) {
      hints.push(hint('frequent_trigger', 'info', '高频重复触发',
        '任务以分钟级频率重复执行，常用于保活或轮询，正常业务也可能这样配置。'));
    }
    if (!isBlank(item.LastTaskResult) && item.LastTaskResult !== 0 && item.LastTaskResult !== '0') {
      hints.push(hint('task_result', 'info', '最近执行返回非 0',
        `LastTaskResult = ${item.LastTaskResult}，可能表示任务执行失败或路径不存在，值得确认任务目标是否仍然有效。`));
    }
    if (isBlank(item.Author)) {
      hints.push(hint('no_author', 'info', '任务未记录作者',
        '任务定义中 Author 为空，无法据此判断创建来源。'));
    }
    if (isBlank(item.RunAs) && !isBlank(item.RunAsRaw)) {
      hints.push(hint('unresolved_principal', 'info', '运行身份未能解析为账户',
        `采集到 UserId=${item.RunAsRaw}` + (item.GroupId ? ` / GroupId=${item.GroupId}` : '') +
        '，无法映射到具体账户名（这类任务的运行主体是组而不是单个用户），请结合任务路径、作者与触发条件判断。'));
    }
  }

  if (item.kind === 'service') {
    if (/[a-z]:\\[^"]*\s[^"]*\.exe/i.test(target) && !/^"/.test(target.trim())) {
      hints.push(hint('unquoted_path', 'warn', '服务路径未加引号',
        '服务可执行路径含空格但未使用引号，属于经典的未加引号服务路径（Unquoted Service Path）配置问题，同目录下若存在可被低权限用户写入的文件则可能被劫持。'));
    }
    if (isBlank(item.Target)) {
      hints.push(hint('no_binary_path', 'warn', '服务未记录可执行路径',
        'Win32_Service 未返回 PathName，可能是采集权限不足，也可能是内核驱动类服务本身没有用户态镜像。'));
    }
    if (/auto/i.test(String(item.StartMode || ''))) {
      hints.push(hint('auto_start', 'info', '开机自动启动',
        '服务启动类型为自动，属于随系统启动的常驻对象，可纳入资产基线比对。'));
    }
  }

  hints.sort((a, b) => SEV_WEIGHT[b.severity] - SEV_WEIGHT[a.severity]);
  return hints;
}

function flagLevel(hints) {
  if (!hints || !hints.length) return 'none';
  return hints[0].severity;
}

function flagSortValue(hints) {
  if (!hints || !hints.length) return 0;
  return hints.reduce((acc, h) => acc + SEV_WEIGHT[h.severity], 0);
}

function flagCell(hints) {
  if (!hints || !hints.length) return '<div class="flags"><span class="pill none">—</span></div>';
  const level = flagLevel(hints);
  const cls = level === 'high' ? 'bad' : level === 'warn' ? 'warn' : 'info';
  const label = level === 'high' ? '重点' : level === 'warn' ? '线索' : '提示';
  const extra = hints.length > 1 ? `<span class="pill ${cls}">+${hints.length - 1}</span>` : '';
  return `<div class="flags"><span class="pill ${cls}">${label}</span>${extra}</div>`;
}

/* ============================================================
   View switching
   ============================================================ */
function switchView(name) {
  state.view = name;
  $$('.view').forEach((v) => v.classList.toggle('is-active', v.id === 'view-' + name));
  $$('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.view === name)));
  if (name !== 'upload') $('#btnNewPackage').hidden = false;
}

function enableTabs(enabled) {
  $$('.tab').forEach((t) => {
    if (t.dataset.view === 'upload') return;
    t.disabled = !enabled;
  });
}

/* ============================================================
   Upload
   ============================================================ */
function initUpload() {
  const dz = $('#dropzone');
  const input = $('#fileInput');

  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); dz.classList.add('dragging');
  }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => {
    e.preventDefault(); dz.classList.remove('dragging');
  }));
  dz.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) uploadFile(file);
  });
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) uploadFile(input.files[0]);
    input.value = '';
  });

  $('#btnNewPackage').addEventListener('click', () => {
    switchView('upload');
    enableTabs(true);
  });
}

function showUploadError(message, hints) {
  const box = $('#uploadError');
  box.innerHTML = `<strong>导入失败：</strong>${esc(message)}` +
    (hints && hints.length ? `<br><br>参考：<br>${hints.map((h) => '· ' + esc(h)).join('<br>')}` : '');
  box.hidden = false;
}

function uploadFile(file) {
  $('#uploadError').hidden = true;
  $('#uploadNote').hidden = true;

  if (!/\.zip$/i.test(file.name)) {
    showUploadError('只接受 .zip 证据包，当前选择的是 ' + file.name);
    return;
  }

  const form = new FormData();
  form.append('package', file);

  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/upload', true);

  $('#uploadProgress').hidden = false;
  $('#upBarFill').style.width = '0%';
  $('#upText').textContent = `正在上传 ${file.name}（${fmtBytes(file.size)}）…`;

  xhr.upload.onprogress = (e) => {
    if (e.lengthComputable) {
      const pct = Math.round((e.loaded / e.total) * 100);
      $('#upBarFill').style.width = pct + '%';
      $('#upText').textContent = pct < 100 ? `正在上传… ${pct}%` : '上传完成，正在解析采集包…';
    }
  };

  xhr.onload = () => {
    $('#uploadProgress').hidden = true;
    let payload = null;
    try { payload = JSON.parse(xhr.responseText); } catch (e) {
      showUploadError('服务端返回了无法解析的响应（HTTP ' + xhr.status + '）。');
      return;
    }
    if (xhr.status >= 400 || payload.error) {
      const extra = [];
      if (payload.hint) extra.push(payload.hint);
      if (Array.isArray(payload.skipped) && payload.skipped.length) {
        extra.push('被跳过的条目：' + payload.skipped.slice(0, 5).join('；'));
      }
      showUploadError(payload.error || '导入失败', extra);
      toast(payload.error || '导入失败', 'err');
      return;
    }
    onSessionLoaded(payload, file);
  };

  xhr.onerror = () => {
    $('#uploadProgress').hidden = true;
    showUploadError('无法连接到本地服务，请确认 python app.py 仍在运行。');
  };

  xhr.send(form);
}

function onSessionLoaded(payload, file) {
  state.session = payload;
  state.processes = (payload.processes || []).map((p) => ({ ...p }));
  state.persistence = []
    .concat(payload.persistence.run_keys || [])
    .concat(payload.persistence.scheduled_tasks || [])
    .concat(payload.persistence.services || []);

  // attach assessment once, up-front
  const pids = new Set(state.processes.map((p) => Number(p.ProcessId)));
  const ctx = { pids };
  state.processes.forEach((p) => { p.hints = assessProcess(p, ctx); });
  state.persistence.forEach((p) => { p.hints = assessPersistence(p); });

  state.proc.page = 1;
  state.pers.page = 1;

  const badge = $('#sessionBadge');
  badge.textContent = `${payload.session.zip_name} · ${fmtBytes(payload.session.zip_bytes)}`;
  badge.classList.add('live');
  badge.title = '会话 ' + payload.session.id + '\n导入时间 ' + payload.session.created_at;

  enableTabs(true);
  renderWarnings(payload.session.warnings || []);
  populateUserFilter();
  renderProcesses();
  renderPersistence();
  renderStats();

  switchView('processes');
  const total = state.processes.length + state.persistence.length;
  toast(`已导入 ${file.name}：解析 ${total} 条记录`, 'ok');
}

function renderWarnings(warnings) {
  const target = ['processes', 'persistence'];
  target.forEach((view) => {
    const host = $('#view-' + view);
    const old = host.querySelector('.alert.warn.data-warn');
    if (old) old.remove();
    if (!warnings.length) return;
    const box = document.createElement('div');
    box.className = 'alert warn data-warn';
    box.style.margin = '0 0 16px';
    box.innerHTML = '<strong>采集包提示（' + warnings.length + '）：</strong><br>' +
      warnings.slice(0, 8).map((w) => '· ' + esc(w)).join('<br>') +
      (warnings.length > 8 ? `<br>… 其余 ${warnings.length - 8} 条已省略` : '');
    host.insertBefore(box, host.firstChild);
  });
}

/* ============================================================
   Stats
   ============================================================ */
function statCard(label, value, sub, accent) {
  return `<div class="stat ${accent || ''}">
    <div class="stat-label">${esc(label)}</div>
    <div class="stat-value">${esc(value)}</div>
    ${sub ? `<div class="stat-sub">${esc(sub)}</div>` : ''}
  </div>`;
}

function renderStats() {
  const procs = state.processes;
  const pHigh = procs.filter((p) => flagLevel(p.hints) === 'high').length;
  const pWarn = procs.filter((p) => flagLevel(p.hints) === 'warn').length;
  const noPath = procs.filter((p) => isBlank(p.ExecutablePath)).length;
  const users = new Set(procs.map((p) => p.UserName).filter((u) => !isBlank(u))).size;
  const counts = (state.session && state.session.counts) || {};

  $('#statbar-processes').innerHTML = [
    statCard('进程总数', procs.length, '来自 processes.json'),
    statCard('重点线索', pHigh, '需要优先核实', pHigh ? 'accent-red' : ''),
    statCard('一般线索', pWarn, '建议建立基线', 'accent-amber'),
    statCard('镜像路径缺失', noPath, '受权限或进程状态限制'),
    statCard('涉及账户', users, '去重后的运行账户', 'accent-cyan'),
  ].join('');

  const pers = state.persistence;
  const kHigh = pers.filter((p) => flagLevel(p.hints) === 'high').length;
  $('#statbar-persistence').innerHTML = [
    statCard('持久化条目', pers.length, 'Run/RunOnce + 计划任务 + 服务'),
    statCard('Run / RunOnce', counts.runKeys || 0, '注册表自启动项', 'accent-cyan'),
    statCard('计划任务', counts.scheduledTasks || 0, 'Get-ScheduledTask'),
    statCard('Windows 服务', counts.services || 0, 'Win32_Service'),
    statCard('重点线索', kHigh, '需要优先核实', kHigh ? 'accent-red' : ''),
  ].join('');
}

/* ============================================================
   Process Explorer
   ============================================================ */
function procFiltered() {
  const f = state.proc;
  const q = f.q.trim().toLowerCase();
  let rows = state.processes;
  if (f.onlyFlagged) rows = rows.filter((p) => p.hints && p.hints.length);
  if (f.onlyNoPath) rows = rows.filter((p) => isBlank(p.ExecutablePath));
  if (f.user) rows = rows.filter((p) => (p.UserName || '') === f.user);
  if (q) {
    rows = rows.filter((p) => [
      p.Name, p.ProcessId, p.ParentProcessId, p.ParentName,
      p.ExecutablePath, p.CommandLine, p.UserName,
    ].some((v) => v !== null && v !== undefined && String(v).toLowerCase().includes(q)));
  }
  return sortRows(rows, f.sortKey, f.sortDir, (p) => {
    if (f.sortKey === 'flags') return flagSortValue(p.hints);
    return p[f.sortKey];
  });
}

function sortRows(rows, key, dir, getter) {
  const mul = dir === 'asc' ? 1 : -1;
  return rows.slice().sort((a, b) => {
    let va = getter(a);
    let vb = getter(b);
    const na = va === null || va === undefined || va === '';
    const nb = vb === null || vb === undefined || vb === '';
    if (na && nb) return 0;
    if (na) return 1;         // blanks always last
    if (nb) return -1;
    if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * mul;
    va = String(va).toLowerCase();
    vb = String(vb).toLowerCase();
    return va < vb ? -mul : va > vb ? mul : 0;
  });
}

function renderProcesses() {
  const body = $('#procBody');
  const rows = procFiltered();
  const f = state.proc;
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  if (f.page > pages) f.page = pages;
  const slice = rows.slice((f.page - 1) * PAGE_SIZE, f.page * PAGE_SIZE);

  $('#procCount').textContent = `${rows.length} / ${state.processes.length} 条`;

  if (!state.processes.length) {
    body.innerHTML = '<tr><td colspan="8"><div class="empty-state"><strong>采集包中没有进程数据</strong>'
      + '请确认上传的 ZIP 由 collector.ps1 生成，且 Processes 模块的状态为 OK。</div></td></tr>';
  } else if (!rows.length) {
    body.innerHTML = '<tr><td colspan="8"><div class="empty-state"><strong>没有匹配的记录</strong>调整搜索关键词或筛选条件后重试。</div></td></tr>';
  } else {
    body.innerHTML = slice.map((p) => {
      const level = flagLevel(p.hints);
      const rowCls = p.hints && p.hints.length ? 'is-flagged' : '';
      const pathCls = isBlank(p.ExecutablePath) ? 'path flag' : (level === 'high' ? 'path flag' : 'path');
      const pathText = isBlank(p.ExecutablePath)
        ? '<span class="empty-cell">（无法获取）</span>' : esc(p.ExecutablePath);
      return `<tr class="${rowCls}" data-id="${esc(p.id)}">
        <td>${flagCell(p.hints)}</td>
        <td class="strong">${esc(p.Name) || '<span class="empty-cell">—</span>'}</td>
        <td class="num">${p.ProcessId ?? '<span class="empty-cell">—</span>'}</td>
        <td class="num">${p.ParentProcessId ?? '<span class="empty-cell">—</span>'}</td>
        <td class="dim">${esc(p.ParentName) || '<span class="empty-cell">—</span>'}</td>
        <td class="dim">${esc(fmtTime(p.CreationDate)) || '<span class="empty-cell">—</span>'}</td>
        <td class="dim">${esc(p.UserName) || '<span class="empty-cell">—</span>'}</td>
        <td class="${pathCls}">${pathText}</td>
      </tr>`;
    }).join('');
  }

  renderPager('#procPager', f.page, pages, (page) => { f.page = page; renderProcesses(); });

  body.querySelectorAll('tr[data-id]').forEach((tr) => {
    tr.addEventListener('click', () => {
      body.querySelectorAll('tr').forEach((x) => x.classList.remove('is-open'));
      tr.classList.add('is-open');
      openProcessDetail(tr.dataset.id);
    });
  });
}

function renderPager(sel, page, pages, onGo) {
  const host = $(sel);
  if (pages <= 1) {
    host.innerHTML = `<span class="page-info">共 ${pages} 页</span>`;
    return;
  }
  host.innerHTML = '';
  const mk = (label, target, disabled) => {
    const b = document.createElement('button');
    b.textContent = label;
    b.disabled = disabled;
    b.addEventListener('click', () => onGo(target));
    return b;
  };
  host.appendChild(mk('« 首页', 1, page === 1));
  host.appendChild(mk('‹ 上一页', page - 1, page === 1));
  const info = document.createElement('span');
  info.className = 'page-info';
  info.textContent = `${page} / ${pages}`;
  host.appendChild(info);
  host.appendChild(mk('下一页 ›', page + 1, page === pages));
  host.appendChild(mk('末页 »', pages, page === pages));
}

/* ============================================================
   Persistence
   ============================================================ */
function persFiltered() {
  const f = state.pers;
  const q = f.q.trim().toLowerCase();
  let rows = state.persistence;
  if (f.kind) rows = rows.filter((r) => r.kind === f.kind);
  if (f.onlyFlagged) rows = rows.filter((r) => r.hints && r.hints.length);
  if (q) {
    rows = rows.filter((r) => [
      r.Type, r.Name, r.Location, r.Target, r.RunAs, r.State, r.Author, r.Triggers,
    ].some((v) => v !== null && v !== undefined && String(v).toLowerCase().includes(q)));
  }
  return sortRows(rows, f.sortKey, f.sortDir, (r) => {
    if (f.sortKey === 'flags') return flagSortValue(r.hints);
    return r[f.sortKey];
  });
}

function renderPersistence() {
  const body = $('#persBody');
  const rows = persFiltered();
  const f = state.pers;
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  if (f.page > pages) f.page = pages;
  const slice = rows.slice((f.page - 1) * PAGE_SIZE, f.page * PAGE_SIZE);

  $('#persCount').textContent = `${rows.length} / ${state.persistence.length} 条`;

  if (!state.persistence.length) {
    body.innerHTML = '<tr><td colspan="7"><div class="empty-state"><strong>采集包中没有持久化数据</strong>'
      + '请确认上传的 ZIP 包含 persistence_*.json，且采集模块状态为 OK。</div></td></tr>';
  } else if (!rows.length) {
    body.innerHTML = '<tr><td colspan="7"><div class="empty-state"><strong>没有匹配的记录</strong>调整搜索关键词或类型筛选后重试。</div></td></tr>';
  } else {
    body.innerHTML = slice.map((r) => {
      const rowCls = r.hints && r.hints.length ? 'is-flagged' : '';
      const target = isBlank(r.Target) ? '<span class="empty-cell">（未采集到）</span>' : esc(r.Target);
      return `<tr class="${rowCls}" data-id="${esc(r.id)}">
        <td>${flagCell(r.hints)}</td>
        <td><span class="tag ${esc(r.kind)}">${esc(r.Type)}</span></td>
        <td class="strong">${esc(r.Name) || '<span class="empty-cell">—</span>'}</td>
        <td class="path">${esc(r.Location) || '<span class="empty-cell">—</span>'}</td>
        <td class="cmd">${target}</td>
        <td class="dim">${esc(r.RunAs) || '<span class="empty-cell">—</span>'}</td>
        <td class="dim">${esc(r.State) || '<span class="empty-cell">—</span>'}</td>
      </tr>`;
    }).join('');
  }

  renderPager('#persPager', f.page, pages, (page) => { f.page = page; renderPersistence(); });

  body.querySelectorAll('tr[data-id]').forEach((tr) => {
    tr.addEventListener('click', () => {
      body.querySelectorAll('tr').forEach((x) => x.classList.remove('is-open'));
      tr.classList.add('is-open');
      openPersDetail(tr.dataset.id);
    });
  });
}

/* ============================================================
   Detail drawer
   ============================================================ */
function kv(label, value, mono = true) {
  const blank = isBlank(value);
  return `<dt>${esc(label)}</dt><dd class="${blank ? 'empty' : ''}">${blank ? '未采集到' : esc(value)}</dd>`;
}

function findingsBlock(hints) {
  if (!hints || !hints.length) {
    return '<p class="muted small">未匹配到任何启发式线索。这不代表该对象无风险，只说明它符合本工具的常规判断条件。</p>';
  }
  return hints.map((h) => {
    const cls = h.severity === 'high' ? 'sev-high' : h.severity === 'info' ? 'sev-info' : '';
    const tag = h.severity === 'high' ? '重点线索' : h.severity === 'warn' ? '线索' : '提示';
    return `<div class="finding ${cls}">
      <span class="f-tag">${tag}</span>
      <div class="f-text">${esc(h.title)}<small>${esc(h.detail)}</small></div>
    </div>`;
  }).join('');
}

function rawButton(session, file) {
  if (!file) return '';
  return `<div class="drawer-actions">
      <button class="btn ghost small" data-raw="${esc(file)}">查看原始采集文件 · ${esc(file)}</button>
    </div>`;
}

function openDrawer(kicker, title, html) {
  $('#drawerKicker').textContent = kicker;
  $('#drawerTitle').textContent = title;
  $('#drawerBody').innerHTML = html;
  $('#drawer').hidden = false;
  $('#drawerBackdrop').hidden = false;
  $('#drawerBody').querySelectorAll('[data-raw]').forEach((b) => {
    b.addEventListener('click', () => openRaw(b.dataset.raw));
  });
  $('#drawerBody').scrollTop = 0;
}

function closeDrawer() {
  $('#drawer').hidden = true;
  $('#drawerBackdrop').hidden = true;
  $$('.grid tbody tr').forEach((tr) => tr.classList.remove('is-open'));
}

function openProcessDetail(id) {
  const p = state.processes.find((x) => x.id === id);
  if (!p) return;
  const session = state.session.session;
  const html = `
    <dl class="kv">
      ${kv('进程名', p.Name)}
      ${kv('PID', p.ProcessId)}
      ${kv('父进程 PID', p.ParentProcessId)}
      ${kv('父进程名', p.ParentName)}
      ${kv('启动时间', fmtTime(p.CreationDate))}
      ${kv('运行账户', p.UserName)}
      ${kv('会话 ID', p.SessionId)}
      ${kv('镜像路径', p.ExecutablePath)}
      ${kv('命令行', p.CommandLine)}
    </dl>
    <div class="section-title">调查线索 · ${(p.hints || []).length} 条</div>
    ${findingsBlock(p.hints)}
    <div class="section-title">原始记录（processes.json 单条）</div>
    <pre class="code-block">${esc(JSON.stringify(p.raw, null, 2))}</pre>
    ${rawButton(session, session.sources.processes)}
  `;
  openDrawer('Process · ' + (p.Name || 'unknown'), (p.Name || '进程') + '  PID ' + (p.ProcessId ?? '—'), html);
}

function openPersDetail(id) {
  const r = state.persistence.find((x) => x.id === id);
  if (!r) return;
  const session = state.session.session;
  const extra = [];
  if (r.kind === 'run_key') {
    extra.push(kv('注册表配置单元', (r.raw || {}).Hive));
    extra.push(kv('键路径', (r.raw || {}).KeyPath));
    extra.push(kv('作用域', r.Scope));
    extra.push(kv('值类型', r.ValueType));
    extra.push(kv('键写入时间', null));
  } else if (r.kind === 'scheduled_task') {
    extra.push(kv('任务完整路径', r.Location));
    extra.push(kv('状态', r.State));
    extra.push(kv('作者', r.Author));
    extra.push(kv('运行身份原始值', r.RunAsRaw));
    extra.push(kv('运行主体 GroupId', r.GroupId));
    extra.push(kv('运行级别', r.RunLevel));
    extra.push(kv('触发器', r.Triggers));
    extra.push(kv('上次运行', fmtTime(r.LastRunTime)));
    extra.push(kv('下次运行', fmtTime(r.NextRunTime)));
    extra.push(kv('上次返回码', r.LastTaskResult));
  } else {
    extra.push(kv('显示名称', r.DisplayName));
    extra.push(kv('状态', r.State));
    extra.push(kv('启动类型', r.StartMode));
    extra.push(kv('服务类型', r.ServiceType));
    extra.push(kv('关联进程 PID', r.ProcessId));
    if (r.LocationDerived) {
      extra.push(kv('源位置说明', 'Win32_Service 不返回注册表路径，此处按服务名推导（Windows 服务的配置固定存放于该键下）。'));
    }
  }

  const html = `
    <dl class="kv">
      ${kv('类型', r.Type)}
      ${kv('名称', r.Name)}
      ${kv('源位置', r.Location)}
      ${kv('执行路径 / 命令', r.Target)}
      ${kv('运行账户', r.RunAs)}
      ${extra.join('')}
      ${kv('采集时间', fmtTime(r.CollectedAt))}
    </dl>
    <div class="section-title">调查线索 · ${(r.hints || []).length} 条</div>
    ${findingsBlock(r.hints)}
    <div class="section-title">原始记录（采集 JSON 单条）</div>
    <pre class="code-block">${esc(JSON.stringify(r.raw, null, 2))}</pre>
    ${rawButton(session, session.sources[r.kind] || null)}
  `;
  openDrawer('Persistence · ' + r.Type, r.Name || '条目', html);
}

/* ============================================================
   Raw artifact viewer
   ============================================================ */
function openRaw(file) {
  const files = (state.session.session.raw_files) || [];
  if (!files.length) { toast('该采集包没有可查看的原始文件', 'err'); return; }
  const picker = $('#rawPicker');
  picker.innerHTML = files.map((f) => `<option value="${esc(f)}">${esc(f)}</option>`).join('');
  picker.value = files.includes(file) ? file : files[0];
  $('#rawModal').hidden = false;
  loadRaw(picker.value);
}

function loadRaw(file) {
  $('#rawTitle').textContent = file;
  $('#rawContent').textContent = '加载中…';
  fetch(`/api/session/${state.session.session.id}/raw?file=${encodeURIComponent(file)}`)
    .then((r) => r.json().then((j) => ({ ok: r.ok, body: j })))
    .then(({ ok, body }) => {
      if (!ok) { $('#rawContent').textContent = '读取失败：' + (body.error || '未知错误'); return; }
      $('#rawContent').textContent = body.content +
        (body.truncated ? '\n\n… 文件较大，以上内容已截断。' : '');
    })
    .catch(() => { $('#rawContent').textContent = '读取失败：无法访问本地服务。'; });
}

/* ============================================================
   Wiring
   ============================================================ */
function initControls() {
  // tabs
  $$('.tab').forEach((tab) => tab.addEventListener('click', () => {
    if (tab.disabled) return;
    switchView(tab.dataset.view);
  }));

  // processes toolbar
  let procTimer = null;
  $('#procSearch').addEventListener('input', (e) => {
    clearTimeout(procTimer);
    procTimer = setTimeout(() => {
      state.proc.q = e.target.value; state.proc.page = 1; renderProcesses();
    }, 160);
  });
  $('#procOnlyFlagged').addEventListener('change', (e) => {
    state.proc.onlyFlagged = e.target.checked; state.proc.page = 1; renderProcesses();
  });
  $('#procOnlyNoPath').addEventListener('change', (e) => {
    state.proc.onlyNoPath = e.target.checked; state.proc.page = 1; renderProcesses();
  });
  $('#procUserFilter').addEventListener('change', (e) => {
    state.proc.user = e.target.value; state.proc.page = 1; renderProcesses();
  });
  $('#procReset').addEventListener('click', () => {
    state.proc = { q: '', onlyFlagged: false, onlyNoPath: false, user: '', sortKey: 'flags', sortDir: 'desc', page: 1 };
    $('#procSearch').value = '';
    $('#procOnlyFlagged').checked = false;
    $('#procOnlyNoPath').checked = false;
    $('#procUserFilter').value = '';
    $$('#procTable thead th').forEach((th) => th.classList.remove('sort-asc', 'sort-desc'));
    renderProcesses();
  });

  // persistence toolbar
  let persTimer = null;
  $('#persSearch').addEventListener('input', (e) => {
    clearTimeout(persTimer);
    persTimer = setTimeout(() => {
      state.pers.q = e.target.value; state.pers.page = 1; renderPersistence();
    }, 160);
  });
  $('#persOnlyFlagged').addEventListener('change', (e) => {
    state.pers.onlyFlagged = e.target.checked; state.pers.page = 1; renderPersistence();
  });
  $('#persChips').addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    $$('#persChips .chip').forEach((c) => c.classList.toggle('is-on', c === chip));
    state.pers.kind = chip.dataset.kind; state.pers.page = 1; renderPersistence();
  });
  $('#persReset').addEventListener('click', () => {
    state.pers = { q: '', kind: '', onlyFlagged: false, sortKey: 'flags', sortDir: 'desc', page: 1 };
    $('#persSearch').value = '';
    $('#persOnlyFlagged').checked = false;
    $$('#persChips .chip').forEach((c) => c.classList.toggle('is-on', c.dataset.kind === ''));
    $$('#persTable thead th').forEach((th) => th.classList.remove('sort-asc', 'sort-desc'));
    renderPersistence();
  });

  // sortable headers
  $$('#procTable thead th.sortable').forEach((th) => th.addEventListener('click', () => {
    toggleSort(th, state.proc, () => renderProcesses());
  }));
  $$('#persTable thead th.sortable').forEach((th) => th.addEventListener('click', () => {
    toggleSort(th, state.pers, () => renderPersistence());
  }));

  // drawer + modal
  $('#drawerClose').addEventListener('click', closeDrawer);
  $('#drawerBackdrop').addEventListener('click', closeDrawer);
  $('#rawClose').addEventListener('click', () => { $('#rawModal').hidden = true; });
  $('#rawModal').addEventListener('click', (e) => { if (e.target.id === 'rawModal') $('#rawModal').hidden = true; });
  $('#rawPicker').addEventListener('change', (e) => loadRaw(e.target.value));
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!$('#rawModal').hidden) { $('#rawModal').hidden = true; return; }
    if (!$('#drawer').hidden) closeDrawer();
  });
}

function toggleSort(th, target, rerender) {
  const key = th.dataset.sort;
  if (target.sortKey === key) {
    target.sortDir = target.sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    target.sortKey = key;
    target.sortDir = key === 'flags' ? 'desc' : 'asc';
  }
  const table = th.closest('table');
  table.querySelectorAll('thead th').forEach((x) => x.classList.remove('sort-asc', 'sort-desc'));
  th.classList.add(target.sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
  target.page = 1;
  rerender();
}

function populateUserFilter() {
  const users = Array.from(new Set(state.processes.map((p) => p.UserName).filter((u) => !isBlank(u)))).sort();
  $('#procUserFilter').innerHTML = '<option value="">全部账户</option>' +
    users.map((u) => `<option value="${esc(u)}">${esc(u)}</option>`).join('');
}

document.addEventListener('DOMContentLoaded', () => {
  initControls();
  initUpload();
});
