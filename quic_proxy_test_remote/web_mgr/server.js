'use strict';
// qmgr: remote web console for diagnosing UDP/QUIC reachability on the test server.
// Node 22, standard library only. Run `node server.js` (QMGR_CONFIG=/etc/qmgr/config.json).
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const cp = require('node:child_process');

const TROJAN_PORT = 443;
const MODES = ['trojan', 'iperf3', 'control'];
const AUTORESTORE = [0, 5, 10, 15];
const CAPTURE_MAX = [5, 15, 30, 60, 120];
const CAPTURE_PROTOS = ['udp', 'tcp+udp'];
const LIVE_MAX_BYTES = 20 * 1024 * 1024;
const COOKIE_NAME = 'qmgr';

// ---------------------------------------------------------------- config

const DEFAULTS = {
  listenHost: '127.0.0.1',
  listenPort: 3480,
  basePath: '/qmgr/',
  publicUrl: 'https://vpn1.yuchs.com:3443',
  tokenFile: '/etc/qmgr/token',
  stateFile: '/var/lib/qmgr/state.json',
  trojanDir: '/root/trojan-plus-temp',
  trojanBinary: 'trojan',
  trojanConfig: 'config.json',
  runScript: 'run_trojan-plus.sh',
  trojanLog: '',
  iface: 'eth0',
  captureDir: '/var/lib/qmgr/cap',
  controlPort: 8443,
  iperf3Binary: '/usr/bin/iperf3',
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
const bad = (m) => new HttpError(400, m);

function normalizeConfig(raw = {}) {
  const c = { ...DEFAULTS, ...raw };
  let b = String(c.basePath || '/');
  if (!/^[A-Za-z0-9/_.-]+$/.test(b)) throw new Error('invalid basePath');
  if (!b.startsWith('/')) b = '/' + b;
  if (!b.endsWith('/')) b += '/';
  c.basePath = b;
  for (const k of ['listenPort', 'controlPort']) {
    // listenPort 0 = ephemeral (tests)
    if (!Number.isInteger(c[k]) || c[k] < (k === 'listenPort' ? 0 : 1) || c[k] > 65535) throw new Error(`invalid ${k}`);
  }
  if (!/^[A-Za-z0-9_.:-]{1,15}$/.test(c.iface)) throw new Error('invalid iface');
  return c;
}

function loadConfig(file) {
  let raw = {};
  try {
    raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') throw new Error(`cannot read config ${file}: ${e.code || 'invalid JSON'}`);
  }
  return normalizeConfig(raw);
}

// ---------------------------------------------------------------- validation

function parsePort(v) {
  const n = typeof v === 'string' && /^\d{1,5}$/.test(v.trim()) ? Number(v.trim()) : v;
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw bad('invalid port');
  return n;
}

function parseIp(v) {
  if (typeof v !== 'string' || v.length > 45 || v.includes('%') || net.isIP(v) === 0) throw bad('invalid IP address');
  return v;
}

function parsePorts(v, dflt) {
  if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) return dflt;
  const parts = Array.isArray(v) ? v : String(v).split(',');
  const out = [...new Set(parts.map((p) => parsePort(typeof p === 'string' ? p.trim() : p)))];
  if (out.length > 8) throw bad('too many ports');
  return out;
}

function parsePayload(v) {
  const n = typeof v === 'string' && /^\d{1,5}$/.test(v) ? Number(v) : v;
  if (!Number.isInteger(n) || !(n === 0 || (n >= 1200 && n <= 1452))) throw bad('payload size must be 0 or 1200-1452');
  return n;
}

function parseEnum(v, allowed, what) {
  const n = typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : v;
  if (!allowed.includes(n)) throw bad(`invalid ${what}`);
  return n;
}

// proto: 'udp' (default) or 'tcp+udp'. Only validated parts are interpolated.
function buildFilter(ports, ip, proto = 'udp') {
  if (!CAPTURE_PROTOS.includes(proto)) throw bad('invalid protocol');
  let f = (proto === 'udp' ? 'udp and ' : '(udp or tcp) and ') + '(' + ports.map((p) => `port ${p}`).join(' or ') + ')';
  if (ip) f += ` and host ${ip}`;
  return f;
}

// ---------------------------------------------------------------- parsing helpers

function parseSs(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 5 || (f[0] !== 'tcp' && f[0] !== 'udp')) continue;
    const m = /:(\d+)$/.exec(f[4]);
    if (!m) continue;
    const procs = [];
    const re = /\("([^"]*)",pid=(\d+)/g;
    let x;
    while ((x = re.exec(line))) procs.push({ name: x[1], pid: Number(x[2]) });
    out.push({ proto: f[0], port: Number(m[1]), procs });
  }
  return out;
}

const owners = (l, proto, port) => {
  const seen = new Map();
  for (const e of l) if (e.proto === proto && e.port === port) for (const p of e.procs) seen.set(p.pid, p);
  return [...seen.values()];
};
// true if the socket exists and every owning process satisfies pred
const ownedBy = (l, proto, port, pred) => {
  const es = l.filter((e) => e.proto === proto && e.port === port);
  const ps = owners(l, proto, port);
  return es.length > 0 && ps.length > 0 && ps.every(pred);
};

const BUCKETS = ['<=1200', '1201-1250', '1251-1350', '1351-1452', '>1452'];
const bucketOf = (n) => (n <= 1200 ? 0 : n <= 1250 ? 1 : n <= 1350 ? 2 : n <= 1452 ? 3 : 4);

function splitAddr(a) {
  const i = a.lastIndexOf('.');
  const port = Number(a.slice(i + 1));
  return i < 0 || !Number.isInteger(port) ? null : { ip: a.slice(0, i), port };
}

// tcpdump -nn -tttt line -> {ts, proto, src, dst, len} or null.
// -nn is required: with -n tcpdump still prints service names (".https"), which are not numeric ports.
function parseDumpLine(line) {
  const m = /^(\S+ \S+) IP6? (\S+) > (\S+?): (UDP|Flags \[).*?\blength (\d+)/.exec(line);
  if (!m) return null;
  const src = splitAddr(m[2]);
  const dst = splitAddr(m[3]);
  return src && dst ? { ts: m[1], proto: m[4] === 'UDP' ? 'udp' : 'tcp', src, dst, len: Number(m[5]) } : null;
}

function secretsOf(obj, out = []) {
  if (Array.isArray(obj)) obj.forEach((v) => secretsOf(v, out));
  else if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'string' && v.length >= 4 && /pass|key|secret|token|auth/i.test(k)) out.push(v);
      else if (Array.isArray(v) && /pass/i.test(k)) v.forEach((s) => typeof s === 'string' && s.length >= 4 && out.push(s));
      else secretsOf(v, out);
    }
  }
  return out;
}

// ---------------------------------------------------------------- real runner / clock

function realRunner() {
  return {
    // Resolves on process exit (not on pipe close: the run script may daemonize and keep pipes open).
    run(cmd, args, { cwd, timeout = 30000 } = {}) {
      return new Promise((resolve) => {
        let out = '';
        let err = '';
        let done = false;
        let timer;
        const fin = (code) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          setTimeout(() => {
            c.stdout?.destroy();
            c.stderr?.destroy();
            resolve({ code, stdout: out, stderr: err });
          }, 100);
        };
        const c = cp.spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
        c.stdout.on('data', (d) => out.length < 1e6 && (out += d));
        c.stderr.on('data', (d) => err.length < 1e6 && (err += d));
        c.on('error', (e) => {
          err += e.message;
          fin(-1);
        });
        c.on('exit', (code) => fin(code ?? -1));
        timer = setTimeout(() => {
          err += ' [timeout]';
          c.kill('SIGKILL');
        }, timeout);
      });
    },
    // Long-lived child. opts: cwd, pipe (capture stdout), errFile (stderr appended to file).
    spawn(cmd, args, opts = {}) {
      let errFd = 'ignore';
      if (opts.errFile) errFd = fs.openSync(opts.errFile, 'a', 0o600);
      try {
        const c = cp.spawn(cmd, args, { cwd: opts.cwd, detached: !!opts.detached, stdio: ['ignore', opts.pipe ? 'pipe' : 'ignore', errFd] });
        c.on('error', () => {});
        if (opts.detached) c.unref();
        if (!c.pid) throw new Error(`cannot start ${cmd}`);
        return c;
      } finally {
        if (typeof errFd === 'number') fs.closeSync(errFd);
      }
    },
    kill(pid, sig) {
      try {
        process.kill(pid, sig);
      } catch {
        /* already gone */
      }
    },
    // argv array, or null if the process does not exist (or is a zombie)
    cmdline(pid) {
      try {
        const s = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8');
        return s ? s.replace(/\0$/, '').split('\0') : null;
      } catch {
        return null;
      }
    },
  };
}

const realClock = { now: () => Date.now(), sleep: (ms) => new Promise((r) => setTimeout(r, ms)) };

// ---------------------------------------------------------------- app factory

function createApp({ config, runner, clock = realClock, logger = console }) {
  const cfg = normalizeConfig(config);
  const base = cfg.basePath;
  const stateDir = path.dirname(cfg.stateFile);
  const actionsFile = path.join(stateDir, 'actions.log');
  const controlCfg = path.join(stateDir, 'control-config.json');
  const controlLog = path.join(stateDir, 'control.log');
  const liveLog = path.join(cfg.captureDir, 'live.log');
  const publicDir = path.join(__dirname, 'public');
  const trojanBin = path.isAbsolute(cfg.trojanBinary) ? cfg.trojanBinary : path.join(cfg.trojanDir, cfg.trojanBinary);
  const trojanName = path.basename(cfg.trojanBinary).slice(0, 15);
  const trojanCfgPath = path.resolve(cfg.trojanDir, cfg.trojanConfig);
  const scriptCmd = path.isAbsolute(cfg.runScript) ? cfg.runScript : './' + cfg.runScript;
  const isTrojan = (p) => p.name === trojanName;

  let state = { mode: 'unknown', deadline: null, autoRestoreMin: 0, tracked: { iperf3: [], control: null, tcpdump: [] } };
  const actions = [];
  let busy = null;
  let chain = Promise.resolve();
  let lcache = null;
  const lstart = new Map();

  // ---- state, action log, mutex

  const writeAtomic = (file, data, mode = 0o600) => {
    const tmp = `${file}.tmp${process.pid}`;
    fs.writeFileSync(tmp, data, { mode });
    fs.renameSync(tmp, file);
  };
  const saveState = () => writeAtomic(cfg.stateFile, JSON.stringify(state, null, 2));

  function act(action, detail, result = 'ok') {
    const e = { t: new Date(clock.now()).toISOString(), action, detail, result };
    actions.push(e);
    if (actions.length > 50) actions.shift();
    try {
      fs.appendFileSync(actionsFile, JSON.stringify(e) + '\n', { mode: 0o600 });
    } catch {
      /* best effort */
    }
  }

  const locked = (label, fn) => {
    const run = chain.then(async () => {
      busy = label;
      try {
        return await fn();
      } finally {
        busy = null;
      }
    });
    chain = run.catch(() => {});
    return run;
  };

  // ---- auth

  function ensureToken() {
    if (fs.existsSync(cfg.tokenFile)) return;
    fs.mkdirSync(path.dirname(cfg.tokenFile), { recursive: true, mode: 0o700 });
    const token = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(cfg.tokenFile, token, { mode: 0o600, flag: 'wx' });
    // printed exactly once, when the token is created
    logger.log(`qmgr: token created in ${cfg.tokenFile}. Login URL: ${cfg.publicUrl}${base}?token=${token}`);
  }
  const readToken = () => {
    try {
      const t = fs.readFileSync(cfg.tokenFile, 'utf8').trim();
      return t || null;
    } catch {
      return null;
    }
  };
  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
  const tokenOk = (cand, token) => !!token && typeof cand === 'string' && crypto.timingSafeEqual(sha(cand), sha(token));
  const cookieFor = (token) => crypto.createHmac('sha256', token).update('qmgr-cookie-v1').digest('hex');
  function isAuthed(req) {
    const token = readToken();
    if (!token) return false;
    const m = /(?:^|;\s*)qmgr=([0-9a-f]+)/.exec(req.headers.cookie || '');
    if (!m) return false;
    const want = cookieFor(token);
    return m[1].length === want.length && crypto.timingSafeEqual(Buffer.from(m[1]), Buffer.from(want));
  }
  function clientIp(req) {
    const remote = (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
    if (remote === '127.0.0.1' || remote === '::1') {
      const last = String(req.headers['x-forwarded-for'] || '').split(',').pop().trim();
      if (net.isIP(last)) return last;
    }
    return remote;
  }
  const fails = new Map();
  const failsOf = (ip) => {
    const a = (fails.get(ip) || []).filter((t) => clock.now() - t < 60000);
    if (a.length) fails.set(ip, a);
    else fails.delete(ip);
    return a;
  };

  // ---- process / listener helpers

  const invalidate = () => {
    lcache = null;
  };
  async function readListeners() {
    const r = await runner.run('ss', ['-lntup']);
    if (r.code !== 0) throw new Error('ss failed: ' + (r.stderr || '').slice(0, 200));
    const v = parseSs(r.stdout);
    lcache = { t: clock.now(), v };
    return v;
  }
  async function cachedListeners() {
    return lcache && clock.now() - lcache.t < 1500 ? lcache.v : readListeners();
  }
  async function waitFor(pred, ms = 10000, step = 500) {
    const end = clock.now() + ms;
    for (;;) {
      const l = await readListeners();
      if (pred(l)) return l;
      if (clock.now() >= end) return null;
      await clock.sleep(step);
    }
  }
  const script = async (verb) => {
    invalidate();
    return runner.run(scriptCmd, [verb, String(TROJAN_PORT)], { cwd: cfg.trojanDir, timeout: 60000 });
  };
  const trojanUp = (l) => ownedBy(l, 'tcp', TROJAN_PORT, isTrojan) && ownedBy(l, 'udp', TROJAN_PORT, isTrojan);
  const sameArgv = (a, b) => !!a && JSON.stringify(a) === JSON.stringify(b);
  const isLive = (rec) => !!rec && sameArgv(runner.cmdline(rec.pid), rec.argv);

  function readJsonFile(file) {
    let raw;
    try {
      raw = fs.readFileSync(file, 'utf8');
    } catch {
      throw new Error(`cannot read ${file}`);
    }
    try {
      return { raw, obj: JSON.parse(raw) };
    } catch {
      throw new Error(`${path.basename(file)} is not valid JSON`); // no parser message: it can quote secrets
    }
  }
  function redact(text, obj) {
    let t = String(text || '');
    for (const s of secretsOf(obj || {})) t = t.split(s).join('***');
    return t.slice(0, 300);
  }

  // Kill a tracked pid only if /proc/<pid>/cmdline still equals exactly what we spawned.
  async function killTracked(rec, label) {
    invalidate();
    const cl = runner.cmdline(rec.pid);
    if (!cl) return 'gone';
    if (!sameArgv(cl, rec.argv)) {
      act('kill-skip', `${label} pid ${rec.pid}: cmdline mismatch, not killing`, 'skipped');
      return 'mismatch';
    }
    runner.kill(rec.pid, 'SIGTERM');
    for (let i = 0; i < 30; i++) {
      await clock.sleep(100);
      if (!runner.cmdline(rec.pid)) return 'stopped';
    }
    if (sameArgv(runner.cmdline(rec.pid), rec.argv)) runner.kill(rec.pid, 'SIGKILL');
    await clock.sleep(200);
    return 'killed';
  }
  async function stopIperf() {
    for (const r of state.tracked.iperf3) await killTracked(r, 'iperf3');
    state.tracked.iperf3 = [];
    saveState();
  }
  async function stopControl() {
    if (state.tracked.control) await killTracked(state.tracked.control, 'control');
    state.tracked.control = null;
    saveState();
  }

  // ---- modes

  function detectMode(l) {
    if (state.tracked.iperf3.some((r) => owners(l, 'tcp', TROJAN_PORT).some((p) => p.pid === r.pid))) return 'iperf3';
    if (ownedBy(l, 'tcp', TROJAN_PORT, isTrojan)) {
      const c = state.tracked.control;
      return c && owners(l, 'tcp', cfg.controlPort).some((p) => p.pid === c.pid) ? 'control' : 'trojan';
    }
    return 'unknown';
  }

  async function ensureTrojan() {
    let l = await readListeners();
    if (trojanUp(l)) return;
    const all = [...owners(l, 'tcp', TROJAN_PORT), ...owners(l, 'udp', TROJAN_PORT)];
    const foreign = all.filter((p) => !isTrojan(p));
    if (foreign.length) throw new Error('443 is held by ' + foreign.map((p) => `${p.name}(${p.pid})`).join(', '));
    if (!all.length) {
      const r = await script('start');
      if (r.code !== 0) throw new Error('run script start failed: ' + (r.stderr || r.stdout || '').slice(0, 200));
    }
    l = await waitFor(trojanUp);
    if (!l) throw new Error('trojan does not own TCP+UDP 443 after 10 s');
  }

  async function toTrojan() {
    await stopIperf();
    await stopControl();
    await ensureTrojan();
  }

  async function toIperf() {
    await stopControl();
    let l = await readListeners();
    if (state.tracked.iperf3.some((r) => isLive(r) && owners(l, 'tcp', TROJAN_PORT).some((p) => p.pid === r.pid))) return;
    await stopIperf();
    await script('stop');
    l = await waitFor((x) => !owners(x, 'tcp', TROJAN_PORT).length && !owners(x, 'udp', TROJAN_PORT).length);
    if (!l) throw new Error('443 not freed after stop');
    const args = ['-s', '-p', String(TROJAN_PORT)];
    const child = runner.spawn(cfg.iperf3Binary, args, { detached: true, errFile: path.join(stateDir, 'iperf3.err') });
    const rec = { pid: child.pid, argv: [cfg.iperf3Binary, ...args], startedAt: clock.now() };
    state.tracked.iperf3.push(rec);
    saveState();
    invalidate();
    if (!(await waitFor((x) => owners(x, 'tcp', TROJAN_PORT).some((p) => p.pid === rec.pid), 5000, 250))) {
      throw new Error('iperf3 does not listen on TCP 443');
    }
  }

  async function toControl() {
    await stopIperf();
    await ensureTrojan();
    const c = state.tracked.control;
    if (isLive(c) && owners(await readListeners(), 'tcp', cfg.controlPort).some((p) => p.pid === c.pid)) return;
    await stopControl();
    const { obj } = readJsonFile(trojanCfgPath);
    obj.local_port = cfg.controlPort;
    writeAtomic(controlCfg, JSON.stringify(obj, null, 4) + '\n', 0o600);
    const args = ['-c', controlCfg, '-l', controlLog];
    const child = runner.spawn(trojanBin, args, { cwd: cfg.trojanDir, detached: true, errFile: path.join(stateDir, 'control.err') });
    const rec = { pid: child.pid, argv: [trojanBin, ...args], startedAt: clock.now() };
    state.tracked.control = rec;
    saveState();
    invalidate();
    if (!(await waitFor((x) => owners(x, 'tcp', cfg.controlPort).some((p) => p.pid === rec.pid)))) {
      throw new Error(`control instance does not listen on TCP ${cfg.controlPort}`);
    }
  }

  async function doSetMode(mode, reason) {
    const from = state.mode;
    try {
      await { trojan: toTrojan, iperf3: toIperf, control: toControl }[mode]();
      state.mode = mode;
      state.deadline = mode === 'trojan' || !state.autoRestoreMin ? null : clock.now() + state.autoRestoreMin * 60000;
      saveState();
      act('mode', `${from} to ${mode} (${reason})`);
    } catch (e) {
      act('mode', `${from} to ${mode} (${reason})`, 'FAILED: ' + e.message);
      if (mode !== 'trojan') {
        try {
          await toTrojan(); // do not leave the server without trojan
          act('mode', 'restore trojan after failed switch');
        } catch (e2) {
          act('mode', 'restore trojan after failed switch', 'FAILED: ' + e2.message);
        }
      } else {
        state.deadline = null; // no retry loop
      }
      try {
        state.mode = detectMode(await readListeners());
      } catch {
        state.mode = 'unknown';
      }
      if (state.mode === 'trojan') state.deadline = null;
      saveState();
      throw e;
    }
  }
  const setMode = (mode, reason = 'manual') => locked('mode:' + mode, () => doSetMode(mode, reason));

  const setAutoRestore = (minutes) =>
    locked('autorestore', async () => {
      state.autoRestoreMin = minutes;
      if (state.mode !== 'trojan' && state.mode !== 'unknown') state.deadline = minutes ? clock.now() + minutes * 60000 : null;
      saveState();
      act('autorestore', minutes ? `${minutes} min` : 'off');
    });

  // ---- server payload size

  const readPayloadSetting = () => {
    try {
      const { obj } = readJsonFile(trojanCfgPath);
      return { value: obj.quic?.tx_udp_payload_size ?? 0 };
    } catch (e) {
      return { value: null, error: e.message };
    }
  };

  function applyPayload(size) {
    return locked('payload', async () => {
      if (state.mode !== 'trojan') throw new HttpError(409, 'payload size can only be changed in trojan mode');
      const { raw, obj } = readJsonFile(trojanCfgPath);
      const prev = obj.quic?.tx_udp_payload_size ?? 0;
      if (!obj.quic || typeof obj.quic !== 'object') obj.quic = {};
      obj.quic.tx_udp_payload_size = size;
      const ts = new Date(clock.now()).toISOString().replace(/[-:.]/g, '');
      const bak = `${trojanCfgPath}.qmgr-${ts}.bak`;
      const mode = fs.statSync(trojanCfgPath).mode & 0o777;
      fs.writeFileSync(bak, raw, { mode: 0o600 });
      const prefix = path.basename(trojanCfgPath) + '.qmgr-';
      const baks = fs.readdirSync(path.dirname(trojanCfgPath)).filter((f) => f.startsWith(prefix) && f.endsWith('.bak')).sort();
      for (const f of baks.slice(0, -10)) fs.unlinkSync(path.join(path.dirname(trojanCfgPath), f));
      const restore = () => writeAtomic(trojanCfgPath, raw, mode);
      writeAtomic(trojanCfgPath, JSON.stringify(obj, null, 4) + '\n', mode);
      const t = await runner.run(trojanBin, ['-t', '-c', trojanCfgPath], { cwd: cfg.trojanDir });
      if (t.code !== 0) {
        restore();
        const msg = `config test failed, restored: ${redact(t.stderr || t.stdout, obj)}`;
        act('payload', `${prev} to ${size}`, 'FAILED: ' + msg);
        throw new Error(msg);
      }
      await script('restart');
      if (!(await waitFor(trojanUp))) {
        restore();
        await script('restart');
        const ok = await waitFor(trojanUp);
        const msg = `trojan did not come up with size ${size}; config restored, trojan ${ok ? 'running again' : 'STILL DOWN'}`;
        act('payload', `${prev} to ${size}`, 'FAILED: ' + msg);
        throw new Error(msg);
      }
      act('payload', `quic.tx_udp_payload_size ${prev} to ${size}, backup ${path.basename(bak)}`);
    });
  }

  // ---- packet capture

  const cap = { running: false, starting: false, stopping: false, startedAt: null, stopAt: null, ports: [], clientIp: '', proto: 'udp', filter: '', maxMinutes: 0 };
  const summary = new Map();
  let ring = [];
  const subs = new Set();
  let liveFd = null;
  let liveSize = 0;
  let lineBuf = '';

  function appendLive(data) {
    if (liveFd === null) {
      liveFd = fs.openSync(liveLog, 'a', 0o600);
      liveSize = fs.fstatSync(liveFd).size;
    }
    if (liveSize + data.length > LIVE_MAX_BYTES) {
      fs.closeSync(liveFd);
      fs.renameSync(liveLog, liveLog + '.1'); // keep 1 old
      liveFd = fs.openSync(liveLog, 'a', 0o600);
      liveSize = 0;
    }
    fs.writeSync(liveFd, data);
    liveSize += Buffer.byteLength(data);
  }
  function account(line) {
    const d = parseDumpLine(line);
    if (!d) return;
    const ports = new Set(cap.ports);
    let dir;
    let ip;
    if (ports.has(d.dst.port)) [dir, ip] = ['in', d.src.ip];
    else if (ports.has(d.src.port)) [dir, ip] = ['out', d.dst.ip];
    else return;
    const key = `${ip}|${dir}|${d.proto}`;
    let s = summary.get(key);
    if (!s) {
      if (summary.size >= 1000) return;
      s = { ip, dir, proto: d.proto, packets: 0, bytes: 0, buckets: [0, 0, 0, 0, 0], last: '' };
      summary.set(key, s);
    }
    s.packets++;
    s.bytes += d.len;
    s.buckets[bucketOf(d.len)]++;
    s.last = d.ts;
  }
  function onDumpData(chunk) {
    lineBuf += chunk;
    const lines = lineBuf.split('\n');
    lineBuf = lines.pop();
    if (lineBuf.length > 65536) lineBuf = '';
    if (!lines.length) return;
    try {
      appendLive(lines.join('\n') + '\n');
    } catch (e) {
      logger.error('live.log write failed: ' + e.message);
    }
    for (const line of lines) {
      ring.push(line);
      account(line);
      for (const res of subs) res.write(`data: ${JSON.stringify(line)}\n\n`);
    }
    if (ring.length > 300) ring = ring.slice(-300);
  }

  async function startCapture(o = {}) {
    if (cap.running || cap.starting) throw new HttpError(409, 'capture already running');
    cap.starting = true;
    try {
      const ports = parsePorts(o.ports, [TROJAN_PORT, cfg.controlPort]);
      const clientIp = o.clientIp ? parseIp(o.clientIp) : '';
      const maxMinutes = parseEnum(o.maxMinutes ?? 30, CAPTURE_MAX, 'duration');
      const proto = parseEnum(o.proto ?? 'udp', CAPTURE_PROTOS, 'protocol');
      const filter = buildFilter(ports, clientIp, proto);
      fs.mkdirSync(cfg.captureDir, { recursive: true, mode: 0o700 });
      const errFile = path.join(cfg.captureDir, 'tcpdump.err');
      fs.writeFileSync(errFile, '', { mode: 0o600 });
      const pcap = path.join(cfg.captureDir, 'qmgr.pcap');
      // -Z root: the distro default drops to user "tcpdump", which cannot rotate files in our 0700 dir
      const argsA = ['-i', cfg.iface, '-nn', '-s', '128', '-U', '-C', '10', '-W', '5', '-Z', 'root', '-w', pcap, filter];
      const argsB = ['-i', cfg.iface, '-nn', '-l', '-tttt', '-s', '128', filter];
      const a = runner.spawn('tcpdump', argsA, { errFile });
      let b;
      try {
        b = runner.spawn('tcpdump', argsB, { pipe: true, errFile });
      } catch (e) {
        runner.kill(a.pid, 'SIGTERM');
        throw e;
      }
      const recs = [
        { pid: a.pid, argv: ['tcpdump', ...argsA], startedAt: clock.now() },
        { pid: b.pid, argv: ['tcpdump', ...argsB], startedAt: clock.now() },
      ];
      state.tracked.tcpdump = recs;
      saveState();
      lineBuf = '';
      b.stdout.on('data', (d) => onDumpData(String(d)));
      b.on('exit', () => {
        if (cap.running && !cap.stopping) stopCapture('tcpdump exited unexpectedly').catch(() => {});
      });
      await clock.sleep(500);
      if (!recs.every(isLive)) {
        let why = '';
        try {
          why = fs.readFileSync(errFile, 'utf8').slice(0, 300);
        } catch {
          /* none */
        }
        for (const r of recs) await killTracked(r, 'tcpdump');
        state.tracked.tcpdump = [];
        saveState();
        throw new Error('tcpdump failed to start: ' + why);
      }
      Object.assign(cap, { running: true, startedAt: clock.now(), stopAt: clock.now() + maxMinutes * 60000, ports, clientIp, proto, filter, maxMinutes });
      act('capture', `start filter "${filter}" for ${maxMinutes} min`);
    } finally {
      cap.starting = false;
    }
  }

  async function stopCapture(reason = 'manual') {
    if (!cap.running) return;
    cap.stopping = true;
    try {
      for (const r of state.tracked.tcpdump) await killTracked(r, 'tcpdump');
      state.tracked.tcpdump = [];
      saveState();
      cap.running = false;
      act('capture', `stop (${reason})`);
    } finally {
      cap.stopping = false;
    }
  }

  function clearLive() {
    for (const f of [liveLog, liveLog + '.1']) {
      try {
        fs.truncateSync(f, 0);
      } catch {
        /* missing */
      }
    }
    liveSize = 0;
    ring = [];
  }

  const CAP_FILE = /^(qmgr\.pcap\d{0,3}|live\.log|live\.log\.1)$/;
  function captureFiles() {
    try {
      return fs
        .readdirSync(cfg.captureDir)
        .filter((f) => CAP_FILE.test(f))
        .sort()
        .map((f) => {
          const s = fs.statSync(path.join(cfg.captureDir, f));
          return { name: f, size: s.size, mtime: s.mtimeMs };
        });
    } catch {
      return [];
    }
  }
  const capView = () => ({
    running: cap.running,
    startedAt: cap.startedAt,
    stopAt: cap.running ? cap.stopAt : null,
    ports: cap.ports,
    clientIp: cap.clientIp,
    proto: cap.proto,
    filter: cap.filter,
    maxMinutes: cap.maxMinutes,
  });

  // ---- logs

  async function detectTrojanLog() {
    if (cfg.trojanLog) return path.resolve(cfg.trojanDir, cfg.trojanLog);
    const r = await runner.run('ps', ['-eo', 'pid=,args=']);
    for (const line of r.stdout.split('\n')) {
      const a = line.trim().split(/\s+/);
      if (path.basename(a[1] || '') !== path.basename(cfg.trojanBinary) || a.includes(controlCfg)) continue;
      const i = a.indexOf('-l');
      if (i > 0 && a[i + 1]) return path.resolve(cfg.trojanDir, a[i + 1]);
    }
    return null;
  }
  async function logPath(name) {
    return name === 'control' ? (fs.existsSync(controlLog) ? controlLog : null) : detectTrojanLog();
  }
  function tailLines(file, n, filter) {
    const st = fs.statSync(file);
    const len = Math.min(st.size, 1024 * 1024);
    const buf = Buffer.alloc(len);
    const fd = fs.openSync(file, 'r');
    try {
      fs.readSync(fd, buf, 0, len, st.size - len);
    } finally {
      fs.closeSync(fd);
    }
    let lines = buf.toString('utf8').split('\n');
    if (st.size > len) lines.shift();
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    if (filter) {
      const f = filter.toLowerCase();
      lines = lines.filter((x) => x.toLowerCase().includes(f));
    }
    return lines.slice(-n);
  }

  // ---- status

  async function status() {
    const warnings = [];
    let l = null;
    try {
      l = await cachedListeners();
    } catch (e) {
      warnings.push(e.message);
    }
    const fmt = (proto, port) => (l ? owners(l, proto, port).map((p) => `${p.name}(${p.pid})`) : null);
    const tOwners = l ? owners(l, 'tcp', TROJAN_PORT).concat(owners(l, 'udp', TROJAN_PORT)).filter(isTrojan) : [];
    const tPids = [...new Set(tOwners.map((p) => p.pid))];
    const trojan = [];
    for (const pid of tPids) {
      if (!lstart.has(pid)) lstart.set(pid, (await runner.run('ps', ['-o', 'lstart=', '-p', String(pid)])).stdout.trim());
      trojan.push({ pid, started: lstart.get(pid) });
    }
    const detected = l ? detectMode(l) : null;
    if (l) {
      const nobody = !owners(l, 'tcp', TROJAN_PORT).length && !owners(l, 'udp', TROJAN_PORT).length;
      if (nobody) warnings.push('TCP/UDP 443 is owned by nothing');
      else if (state.mode === 'trojan' && !trojanUp(l)) warnings.push('trojan mode, but trojan does not own both TCP and UDP 443');
      if (detected !== state.mode && !busy) warnings.push(`recorded mode ${state.mode} differs from detected mode ${detected}`);
    }
    return {
      now: clock.now(),
      mode: state.mode,
      detectedMode: detected,
      busy,
      deadline: state.deadline,
      autoRestoreMin: state.autoRestoreMin,
      controlPort: cfg.controlPort,
      listeners: { tcp443: fmt('tcp', TROJAN_PORT), udp443: fmt('udp', TROJAN_PORT), tcpControl: fmt('tcp', cfg.controlPort), udpControl: fmt('udp', cfg.controlPort) },
      trojan,
      iperf3: state.tracked.iperf3.map((r) => ({ pid: r.pid, startedAt: r.startedAt, alive: isLive(r) })),
      control: state.tracked.control ? { pid: state.tracked.control.pid, startedAt: state.tracked.control.startedAt, alive: isLive(state.tracked.control) } : null,
      capture: capView(),
      payload: readPayloadSetting(),
      warnings,
      actions: actions.slice().reverse(),
    };
  }

  // ---- init / reconcile / tick

  async function reconcile() {
    if (!isLive(state.tracked.control)) state.tracked.control = null;
    state.tracked.iperf3 = state.tracked.iperf3.filter(isLive);
    for (const r of state.tracked.tcpdump) await killTracked(r, 'tcpdump'); // pipes died with the old process
    state.tracked.tcpdump = [];
    let mode;
    try {
      mode = detectMode(await readListeners());
    } catch (e) {
      act('reconcile', e.message, 'ERROR');
      mode = 'unknown';
    }
    if (mode !== state.mode) act('reconcile', `recorded mode ${state.mode}, detected ${mode}`);
    if (mode === 'unknown') act('reconcile', 'WARNING: 443 is owned by nothing', 'warning');
    state.mode = mode;
    const past = state.deadline && state.deadline <= clock.now();
    if (mode === 'trojan') state.deadline = null;
    saveState();
    if (past && mode !== 'trojan') {
      act('auto-restore', 'deadline passed while qmgr was not running');
      await setMode('trojan', 'auto-restore').catch(() => {});
    }
  }

  async function init() {
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(cfg.captureDir, { recursive: true, mode: 0o700 });
    ensureToken();
    try {
      const s = JSON.parse(fs.readFileSync(cfg.stateFile, 'utf8'));
      state = { ...state, ...s, tracked: { ...state.tracked, ...(s.tracked || {}) } };
    } catch {
      /* first start or unreadable: reconcile rebuilds */
    }
    try {
      for (const line of fs.readFileSync(actionsFile, 'utf8').trim().split('\n').slice(-50)) actions.push(JSON.parse(line));
    } catch {
      /* none yet */
    }
    await reconcile();
  }

  let ticking = false;
  async function tick() {
    if (ticking) return;
    ticking = true;
    try {
      if (state.deadline && clock.now() >= state.deadline && state.mode !== 'trojan') {
        act('auto-restore', 'deadline reached');
        await setMode('trojan', 'auto-restore').catch(() => {});
      }
      if (cap.running && clock.now() >= cap.stopAt) await stopCapture('max duration reached');
    } finally {
      ticking = false;
    }
  }

  // ---- HTTP

  const SEC_HEADERS = {
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
  };
  const send = (res, status, type, body, extra = {}) => {
    res.writeHead(status, { ...SEC_HEADERS, 'Content-Type': type, ...extra });
    res.end(body);
  };
  const json = (res, status, obj) => send(res, status, 'application/json; charset=utf-8', JSON.stringify(obj));
  const redirect = (res, loc, extra = {}) => {
    res.writeHead(302, { ...SEC_HEADERS, Location: loc, ...extra });
    res.end();
  };

  function readBody(req, limit = 16384) {
    return new Promise((resolve, reject) => {
      let n = 0;
      const chunks = [];
      req.on('data', (c) => {
        n += c.length;
        if (n > limit) {
          reject(new HttpError(413, 'body too large'));
          req.destroy();
        } else chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }
  async function readJson(req) {
    const s = await readBody(req);
    if (!s.trim()) return {};
    try {
      const o = JSON.parse(s);
      if (!o || typeof o !== 'object' || Array.isArray(o)) throw 0;
      return o;
    } catch {
      throw bad('invalid JSON body');
    }
  }

  const loginPage = (msg = '') =>
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>qmgr login</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:24rem;padding:0 1rem}input,button{width:100%;font-size:1.1rem;padding:.7rem;margin:.4rem 0;box-sizing:border-box}.e{color:#b00}</style></head>
<body><h1>qmgr</h1><p class="e">${msg}</p><form method="post" action="login"><input type="password" name="token" placeholder="token" autocomplete="current-password" autofocus><button type="submit">Log in</button></form></body></html>`;

  function tryLogin(req, res, cand) {
    const ip = clientIp(req);
    const html = 'text/html; charset=utf-8';
    if (failsOf(ip).length >= 10) {
      if (!fails.get(ip).blockedLogged) {
        fails.get(ip).blockedLogged = true;
        act('login', `ip ${ip} rate limited`, 'blocked');
      }
      return send(res, 429, html, loginPage('Too many attempts, wait a minute.'), { 'Retry-After': '60' });
    }
    const token = readToken();
    if (tokenOk(cand, token)) {
      act('login', `ip ${ip}`);
      return redirect(res, base, {
        'Set-Cookie': `${COOKIE_NAME}=${cookieFor(token)}; HttpOnly; Secure; SameSite=Strict; Path=${base}; Max-Age=2592000`,
      });
    }
    const a = failsOf(ip);
    a.push(clock.now());
    fails.set(ip, a);
    if (fails.size > 10000) fails.delete(fails.keys().next().value);
    return send(res, 401, html, loginPage('Invalid token.'));
  }

  function sseStart(req, res) {
    res.writeHead(200, { ...SEC_HEADERS, 'Content-Type': 'text/event-stream', 'X-Accel-Buffering': 'no', Connection: 'keep-alive' });
    res.write(': ok\n\n');
    const hb = setInterval(() => res.write(': hb\n\n'), 15000);
    hb.unref();
    return hb;
  }

  function streamFile(req, res, file, filter) {
    const hb = sseStart(req, res);
    let pos = fs.statSync(file).size;
    let carry = '';
    const f = (filter || '').toLowerCase();
    const poll = setInterval(() => {
      try {
        const size = fs.statSync(file).size;
        if (size < pos) pos = 0; // truncated
        if (size === pos) return;
        const len = Math.min(size - pos, 262144);
        const buf = Buffer.alloc(len);
        const fd = fs.openSync(file, 'r');
        try {
          fs.readSync(fd, buf, 0, len, pos);
        } finally {
          fs.closeSync(fd);
        }
        pos += len;
        const lines = (carry + buf.toString('utf8')).split('\n');
        carry = lines.pop();
        for (const ln of lines) if (!f || ln.toLowerCase().includes(f)) res.write(`data: ${JSON.stringify(ln)}\n\n`);
      } catch {
        /* file may briefly vanish */
      }
    }, 1000);
    poll.unref();
    req.on('close', () => {
      clearInterval(hb);
      clearInterval(poll);
    });
  }

  function download(res, file, name) {
    const st = fs.statSync(file);
    res.writeHead(200, { ...SEC_HEADERS, 'Content-Type': 'application/octet-stream', 'Content-Length': st.size, 'Content-Disposition': `attachment; filename="${name}"` });
    fs.createReadStream(file).pipe(res);
  }

  const STATIC = { '': 'index.html', 'index.html': 'index.html', 'app.js': 'app.js', 'style.css': 'style.css' };
  const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

  async function route(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    if (p === base.slice(0, -1)) return redirect(res, base);
    if (!p.startsWith(base)) return send(res, 404, 'text/plain', 'not found');
    const rel = p.slice(base.length);
    const method = req.method;
    if (method !== 'GET' && method !== 'POST') return send(res, 405, 'text/plain', 'method not allowed', { Allow: 'GET, POST' });

    if (rel === 'login' && method === 'POST') {
      const form = new URLSearchParams(await readBody(req, 4096));
      return tryLogin(req, res, form.get('token') || '');
    }
    if (rel === '' && method === 'GET' && url.searchParams.has('token')) return tryLogin(req, res, url.searchParams.get('token'));
    const authed = isAuthed(req);
    if (rel === 'style.css' && method === 'GET') return send(res, 200, TYPES['.css'], fs.readFileSync(path.join(publicDir, 'style.css')));
    if (!authed) {
      if (rel === '' && method === 'GET') return send(res, 200, 'text/html; charset=utf-8', loginPage());
      return json(res, 401, { error: 'unauthorized' });
    }
    if (method === 'GET' && rel in STATIC) {
      const f = STATIC[rel];
      return send(res, 200, TYPES[path.extname(f)], fs.readFileSync(path.join(publicDir, f)));
    }
    if (method === 'POST' && req.headers['x-qmgr'] !== '1') return json(res, 403, { error: 'missing X-Qmgr header' });

    const key = `${method} ${rel}`;
    let m;
    switch (key) {
      case 'GET api/status':
        return json(res, 200, await status());
      case 'POST api/mode': {
        const b = await readJson(req);
        const mode = parseEnum(b.mode, MODES, 'mode');
        if (b.autoRestoreMin !== undefined) await setAutoRestore(parseEnum(b.autoRestoreMin, AUTORESTORE, 'auto-restore minutes'));
        await setMode(mode);
        return json(res, 200, await status());
      }
      case 'POST api/autorestore': {
        const b = await readJson(req);
        await setAutoRestore(parseEnum(b.minutes, AUTORESTORE, 'auto-restore minutes'));
        return json(res, 200, await status());
      }
      case 'POST api/payload': {
        const b = await readJson(req);
        await applyPayload(parsePayload(b.size));
        return json(res, 200, await status());
      }
      case 'GET api/capture':
        return json(res, 200, { capture: capView(), summary: [...summary.values()].sort((a, b) => (a.last < b.last ? 1 : -1)), buckets: BUCKETS, files: captureFiles() });
      case 'POST api/capture/start':
        await startCapture(await readJson(req));
        return json(res, 200, { capture: capView() });
      case 'POST api/capture/stop':
        await stopCapture('manual');
        return json(res, 200, { capture: capView() });
      case 'POST api/capture/reset':
        summary.clear();
        return json(res, 200, { ok: true });
      case 'POST api/capture/clearlog':
        clearLive();
        act('capture', 'live.log cleared');
        return json(res, 200, { ok: true });
      case 'GET api/capture/stream': {
        const hb = sseStart(req, res);
        for (const line of ring) res.write(`data: ${JSON.stringify(line)}\n\n`);
        subs.add(res);
        req.on('close', () => {
          clearInterval(hb);
          subs.delete(res);
        });
        return;
      }
    }
    if ((m = /^api\/capture\/file\/([A-Za-z0-9._]+)$/.exec(rel)) && method === 'GET') {
      if (!CAP_FILE.test(m[1]) || !fs.existsSync(path.join(cfg.captureDir, m[1]))) throw new HttpError(404, 'no such file');
      return download(res, path.join(cfg.captureDir, m[1]), m[1]);
    }
    if ((m = /^api\/log\/(trojan|control)(?:\/(stream|download|clear))?$/.exec(rel))) {
      const [, name, sub] = m;
      if ((sub === 'clear') !== (method === 'POST')) throw new HttpError(405, 'wrong method');
      const file = await logPath(name);
      if (!file || !fs.existsSync(file)) {
        if (!sub) return json(res, 200, { name, path: file, exists: false, lines: [] });
        throw new HttpError(404, 'log not found');
      }
      const filter = (url.searchParams.get('filter') || '').slice(0, 100);
      if (sub === 'clear') {
        const b = await readJson(req);
        if (b.confirm !== true) throw bad('confirm required');
        fs.truncateSync(file, 0);
        act('log', `cleared ${name} log`);
        return json(res, 200, { ok: true });
      }
      if (sub === 'download') return download(res, file, `${name}.log`);
      if (sub === 'stream') return streamFile(req, res, file, filter);
      const n = Math.min(Math.max(parseInt(url.searchParams.get('lines') || '200', 10) || 200, 1), 2000);
      return json(res, 200, { name, path: file, exists: true, size: fs.statSync(file).size, lines: tailLines(file, n, filter) });
    }
    return json(res, 404, { error: 'not found' });
  }

  async function handler(req, res) {
    try {
      await route(req, res);
    } catch (e) {
      if (res.headersSent) return res.end();
      if (e instanceof HttpError) return json(res, e.status, { error: e.message });
      logger.error('qmgr: ' + (e && e.stack));
      json(res, 500, { error: e.message });
    }
  }

  let server = null;
  let timer = null;
  function listen() {
    server = http.createServer(handler);
    server.listen(cfg.listenPort, cfg.listenHost, () => logger.log(`qmgr listening on ${cfg.listenHost}:${cfg.listenPort}${base}`));
    timer = setInterval(() => tick().catch((e) => logger.error(e)), 1000);
    return server;
  }
  // Stops capture; deliberately leaves modes and tracked iperf3/control processes alone.
  async function shutdown() {
    clearInterval(timer);
    await stopCapture('qmgr shutdown').catch(() => {});
    server?.close();
    for (const r of subs) r.end();
  }

  return { handler, init, listen, tick, shutdown, setMode, setAutoRestore, applyPayload, startCapture, stopCapture, status, getState: () => state, config: cfg };
}

// ---------------------------------------------------------------- main

async function main() {
  const cfg = loadConfig(process.env.QMGR_CONFIG || '/etc/qmgr/config.json');
  let runner;
  if (process.env.QMGR_FAKE === '1') {
    runner = new (require('./fake_runner').FakeRunner)(cfg);
    runner.addTrojan443();
    console.log('qmgr: FAKE runner (demo mode), no real commands are run');
  } else runner = realRunner();
  const app = createApp({ config: cfg, runner });
  await app.init();
  app.listen();
  const stop = () => app.shutdown().finally(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
  process.on('SIGHUP', () => {}); // token file is re-read on every request
}

if (require.main === module) {
  main().catch((e) => {
    console.error('qmgr: fatal: ' + e.message);
    process.exit(1);
  });
}

module.exports = { createApp, realRunner, loadConfig, normalizeConfig, parsePort, parseIp, parsePorts, parsePayload, buildFilter, parseSs, parseDumpLine, HttpError };
