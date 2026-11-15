'use strict';
// All URLs are relative so the page works under any nginx prefix.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
let status = null;
let skew = 0; // server time minus browser time

function msg(text, err) {
  const m = $('msg');
  m.textContent = text;
  m.className = err ? 'err' : '';
  m.hidden = !text;
}

async function api(path, body) {
  const opt = body === undefined ? {} : { method: 'POST', headers: { 'X-Qmgr': '1', 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const r = await fetch('api/' + path, { ...opt, credentials: 'same-origin' });
  if (r.status === 401) {
    location.reload();
    throw new Error('login required');
  }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
  return j;
}
async function act(label, path, body) {
  msg(label + ' ...');
  try {
    const j = await api(path, body);
    msg(label + ': ok');
    if (j.mode) render(j);
    return j;
  } catch (e) {
    msg(label + ': ' + e.message, true);
    refresh();
  }
}

const fmtTime = (ms) => new Date(ms).toLocaleTimeString();
function render(s) {
  status = s;
  skew = s.now - Date.now();
  $('mode').textContent = s.busy ? 'switching...' : s.mode;
  document.querySelectorAll('[data-mode]').forEach((b) => b.classList.toggle('active', b.dataset.mode === s.mode));
  $('autorestore').value = String(s.autoRestoreMin);
  $('warnings').innerHTML = s.warnings.map((w) => `<div class="warn">${esc(w)}</div>`).join('');
  const l = s.listeners;
  const rows = [
    ['TCP 443', (l.tcp443 || ['-']).join(', ') || 'nobody'],
    ['UDP 443', (l.udp443 || ['-']).join(', ') || 'nobody'],
    ['TCP ' + s.controlPort, (l.tcpControl || ['-']).join(', ') || 'nobody'],
    ['UDP ' + s.controlPort, (l.udpControl || ['-']).join(', ') || 'nobody'],
    ['trojan', s.trojan.map((t) => `pid ${t.pid}, started ${t.started}`).join('; ') || 'not running'],
    ['iperf3 (ours)', s.iperf3.map((i) => `pid ${i.pid}${i.alive ? '' : ' (dead)'}`).join(', ') || 'none'],
    ['control (ours)', s.control ? `pid ${s.control.pid}${s.control.alive ? '' : ' (dead)'}` : 'none'],
    ['TX payload', s.payload.error ? esc(s.payload.error) : s.payload.value === 0 ? 'default (0)' : s.payload.value],
    ['capture', s.capture.running ? `running until ${fmtTime(s.capture.stopAt)}` : 'stopped'],
  ];
  $('stat').innerHTML = rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('');
  if (s.payload.value !== null && document.activeElement !== $('payload') && document.activeElement !== $('payload-custom')) {
    const v = String(s.payload.value);
    $('payload').value = [...$('payload').options].some((o) => o.value === v) ? v : 'custom';
    $('payload-custom').hidden = $('payload').value !== 'custom';
    if (!$('payload-custom').hidden) $('payload-custom').value = v;
  }
  $('actions').textContent = s.actions.map((a) => `${a.t.slice(11, 19)} ${a.action}: ${a.detail} [${a.result}]`).join('\n');
  hints(s);
  tickCountdown();
}

function hints(s) {
  const el = $('hints');
  if (s.mode !== 'iperf3') {
    el.innerHTML = s.mode === 'control' ? `<p class="note">Control instance on port ${s.controlPort}: point a client at it and compare QUIC with 443.</p>` : '';
    return;
  }
  const host = location.hostname;
  const sizes = [1200, 1250, 1350, 1400, 1452];
  el.innerHTML =
    '<label>-l <select id="hint-l">' + sizes.map((n) => `<option>${n}</option>`).join('') + '</select></label><div id="hint-cmds"></div>';
  const upd = () => {
    const n = $('hint-l').value;
    const b = `iperf3 -c ${host} -p 443 -u -b 2M -l ${n} -t 10`;
    $('hint-cmds').innerHTML = `<code>${esc(b)}</code><code>${esc(b + ' -R')}</code><code>${esc(`iperf3 -c ${host} -p 443 -t 5`)}</code>`;
  };
  $('hint-l').onchange = upd;
  upd();
}

function tickCountdown() {
  const el = $('countdown');
  if (!status || !status.deadline) return (el.textContent = '');
  const left = Math.max(0, Math.round((status.deadline - (Date.now() + skew)) / 1000));
  el.textContent = `restore in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
}
setInterval(tickCountdown, 1000);

async function refresh() {
  try {
    render(await api('status'));
  } catch (e) {
    msg('status: ' + e.message, true);
  }
}

document.querySelectorAll('[data-mode]').forEach((b) =>
  b.addEventListener('click', () => act('mode ' + b.dataset.mode, 'mode', { mode: b.dataset.mode, autoRestoreMin: Number($('autorestore').value) })),
);
$('autorestore').addEventListener('change', () => act('auto-restore', 'autorestore', { minutes: Number($('autorestore').value) }));
$('payload').addEventListener('change', () => ($('payload-custom').hidden = $('payload').value !== 'custom'));
$('payload-apply').addEventListener('click', () => {
  const v = $('payload').value === 'custom' ? $('payload-custom').value : $('payload').value;
  if (confirm(`Set server TX payload size to ${v} and restart trojan?`)) act('payload size', 'payload', { size: Number(v) });
});

// ---- capture
async function refreshCapture() {
  try {
    const c = await api('capture');
    const cp = c.capture;
    $('cap-state').textContent = cp.running ? `running: ${cp.filter}, stops ${fmtTime(cp.stopAt)}` : 'stopped';
    $('cap-sum').innerHTML =
      '<tr><th>IP</th><th>proto</th><th>dir</th><th>pkts</th><th>bytes</th>' + c.buckets.map((b) => `<th>${esc(b)}</th>`).join('') + '<th>last</th></tr>' +
      c.summary.map((r) => `<tr><td>${esc(r.ip)}</td><td>${esc(r.proto.toUpperCase())}</td><td>${r.dir}</td><td>${r.packets}</td><td>${r.bytes}</td>${r.buckets.map((n) => `<td>${n}</td>`).join('')}<td>${esc(r.last.slice(11, 19))}</td></tr>`).join('');
    $('cap-files').innerHTML = c.files.map((f) => `<a class="btn" href="api/capture/file/${encodeURIComponent(f.name)}">${esc(f.name)} (${Math.round(f.size / 1024)} KB)</a> `).join('');
  } catch (e) {
    /* status() shows auth problems */
  }
}
$('cap-start').addEventListener('click', async () => {
  await act('capture start', 'capture/start', { ports: $('cap-ports').value, clientIp: $('cap-ip').value.trim(), proto: $('cap-proto').value, maxMinutes: Number($('cap-max').value) });
  connectLive();
});
$('cap-stop').addEventListener('click', () => act('capture stop', 'capture/stop', {}).then(refreshCapture));
$('cap-reset').addEventListener('click', () => act('reset summary', 'capture/reset', {}).then(refreshCapture));
$('live-clear').addEventListener('click', () => ($('live').textContent = ''));
$('live-clearlog').addEventListener('click', () => confirm('Truncate live.log?') && act('clear live.log', 'capture/clearlog', {}));

function follow(es, pre, pauseBtn) {
  const st = { paused: false };
  pauseBtn.onclick = () => {
    st.paused = !st.paused;
    pauseBtn.textContent = st.paused ? 'Resume scroll' : 'Pause scroll';
  };
  es.onmessage = (ev) => {
    pre.textContent += JSON.parse(ev.data) + '\n';
    if (pre.textContent.length > 300000) pre.textContent = pre.textContent.slice(-200000);
    if (!st.paused) pre.scrollTop = pre.scrollHeight;
  };
}
let liveES = null;
function connectLive() {
  if (liveES) liveES.close();
  liveES = new EventSource('api/capture/stream');
  follow(liveES, $('live'), $('live-pause'));
}
connectLive();

// ---- logs
let logES = null;
const logQuery = () => '?filter=' + encodeURIComponent($('log-filter').value);
async function loadLog() {
  const n = $('log-name').value;
  $('log-dl').href = `api/log/${n}/download`;
  if (logES) logES.close();
  try {
    const j = await api(`log/${n}${logQuery()}&lines=200`);
    $('log').textContent = j.exists ? j.lines.join('\n') + '\n' : `(no log: ${j.path || 'path unknown'})`;
    $('log').scrollTop = $('log').scrollHeight;
    if (j.exists) {
      logES = new EventSource(`api/log/${n}/stream${logQuery()}`);
      follow(logES, $('log'), $('log-pause'));
    }
  } catch (e) {
    msg('log: ' + e.message, true);
  }
}
$('log-follow').addEventListener('click', loadLog);
$('log-name').addEventListener('change', loadLog);
$('log-filter').addEventListener('change', loadLog);
$('log-clear').addEventListener('click', () => {
  const n = $('log-name').value;
  if (confirm(`Truncate the ${n} log file? This cannot be undone.`)) act('clear ' + n + ' log', `log/${n}/clear`, { confirm: true }).then(loadLog);
});

refresh();
refreshCapture();
loadLog();
setInterval(refresh, 3000);
setInterval(refreshCapture, 3000);
