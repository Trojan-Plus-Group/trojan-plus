'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { makeEnv, login, post, get } = require('./helper.js');

async function setup() {
    const env = makeEnv();
    env.runner.addTrojan443();
    await env.app.init();
    env.auth = await login(env);
    return env;
}

test('capture start runs two tcpdump with identical validated filter', async () => {
    const env = await setup();
    const r = await post(env, env.auth, 'api/capture/start', { ports: '443, 8443', clientIp: '1.2.3.4', maxMinutes: 15 });
    assert.equal(r.status, 200);
    const dumps = env.runner.calls.filter((c) => c.startsWith('tcpdump'));
    const f = 'udp and (port 443 or port 8443) and host 1.2.3.4';
    assert.deepEqual(dumps, [
        `tcpdump -i eth0 -nn -s 128 -U -C 10 -W 5 -Z root -w ${path.join(env.config.captureDir, 'qmgr.pcap')} ${f}`,
        `tcpdump -i eth0 -nn -l -tttt -s 128 ${f}`,
    ]);
    const s = await env.app.status();
    assert.equal(s.capture.running, true);
    assert.equal(s.capture.stopAt, env.clock.now() + 15 * 60000);
    assert.equal(env.app.getState().tracked.tcpdump.length, 2);
    assert.equal((await post(env, env.auth, 'api/capture/start', {})).status, 409, 'no double start');
});

test('capture defaults: ports 443 + controlPort, 30 min', async () => {
    const env = await setup();
    await env.app.startCapture({});
    assert.ok(env.runner.calls.includes('tcpdump -i eth0 -nn -l -tttt -s 128 udp and (port 443 or port 8443)'));
    assert.equal((await env.app.status()).capture.maxMinutes, 30);
    assert.equal((await env.app.status()).capture.proto, 'udp');
});

test('regression: protocol selector tcp+udp widens the filter on both tcpdumps; bad protocol rejected', async () => {
    const env = await setup();
    assert.equal((await post(env, env.auth, 'api/capture/start', { proto: 'icmp' })).status, 400);
    assert.equal((await post(env, env.auth, 'api/capture/start', { proto: 'udp; id' })).status, 400);
    assert.equal(env.runner.calls.filter((c) => c.startsWith('tcpdump')).length, 0);
    await post(env, env.auth, 'api/capture/start', { proto: 'tcp+udp', ports: '443', clientIp: '2001:db8::1' });
    const dumps = env.runner.calls.filter((c) => c.startsWith('tcpdump'));
    assert.equal(dumps.length, 2);
    for (const d of dumps) assert.ok(d.endsWith(' (udp or tcp) and (port 443) and host 2001:db8::1'), d);
});

test('regression: TCP and UDP rows are separate, TCP lengths never enter UDP buckets (real host lines, -nn)', async () => {
    const env = await setup();
    await env.app.startCapture({ proto: 'tcp+udp' });
    const [dump] = env.runner.pidOf('tcpdump', '-tttt');
    env.runner.emitDump(
        dump,
        [
            '2026-11-15 08:44:33.931745 IP 92.63.204.149.58167 > 172.236.226.35.443: Flags [S], seq 1, win 64240, options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0',
            '2026-11-15 08:44:33.940000 IP 92.63.204.149.58167 > 172.236.226.35.443: Flags [P.], seq 2:2000, ack 1, win 502, length 1998',
            '2026-11-15 08:44:34.000001 IP 1.2.3.4.51000 > 172.236.226.35.443: UDP, length 1250',
            '2026-11-15 08:44:34.100001 IP 172.236.226.35.443 > 1.2.3.4.51000: UDP, length 1200',
            '2026-11-15 08:44:35.000001 IP6 2001:db8::1.51000 > 2001:db8::2.443: UDP, length 1350',
        ].join('\n') + '\n',
    );
    const rows = (await get(env, env.auth, 'api/capture')).json().summary;
    assert.equal(rows.length, 4);
    const row = (ip, dir, proto) => rows.find((r) => r.ip === ip && r.dir === dir && r.proto === proto);
    const tcp = row('92.63.204.149', 'in', 'tcp');
    assert.deepEqual([tcp.packets, tcp.bytes], [2, 1998]);
    assert.ok(!row('92.63.204.149', 'in', 'udp'));
    assert.deepEqual(row('1.2.3.4', 'in', 'udp').buckets, [0, 1, 0, 0, 0]);
    assert.deepEqual(row('1.2.3.4', 'out', 'udp').buckets, [1, 0, 0, 0, 0]);
    assert.deepEqual(row('2001:db8::1', 'in', 'udp').buckets, [0, 0, 1, 0, 0]);
});

test('capture stop kills only tracked tcpdump, auto-stops at max duration', async () => {
    const env = await setup();
    const other = env.runner.add('tcpdump', ['tcpdump', '-i', 'lo'], []); // somebody else's tcpdump
    await env.app.startCapture({ maxMinutes: 5 });
    env.clock.advance(4 * 60000);
    await env.app.tick();
    assert.equal((await env.app.status()).capture.running, true);
    env.clock.advance(61000);
    await env.app.tick();
    assert.equal((await env.app.status()).capture.running, false);
    assert.equal(env.runner.kills.length, 2);
    assert.ok(!env.runner.kills.some((k) => k[0] === other));
    assert.deepEqual(env.app.getState().tracked.tcpdump, []);
    assert.ok((await env.app.status()).actions.some((a) => a.detail.includes('max duration')));
});

test('live output is appended to live.log, summarized per IP/direction/bucket, reset works', async () => {
    const env = await setup();
    await env.app.startCapture({});
    const [dump] = env.runner.pidOf('tcpdump', '-tttt');
    const ln = (src, dst, len) => `2026-11-15 10:00:00.1 IP ${src} > ${dst}: UDP, length ${len}\n`;
    env.runner.emitDump(dump, ln('1.2.3.4.5000', '9.9.9.9.443', 1200) + ln('1.2.3.4.5000', '9.9.9.9.443', 1201));
    env.runner.emitDump(dump, ln('9.9.9.9.443', '1.2.3.4.5000', 1500) + '2026-11-15 10:00:01.1 IP 1.2.3.4.5');
    env.runner.emitDump(dump, '000 > 9.9.9.9.443: UDP, length 1300\n');
    const live = fs.readFileSync(path.join(env.config.captureDir, 'live.log'), 'utf8');
    assert.equal(live.trim().split('\n').length, 4);
    const c = (await get(env, env.auth, 'api/capture')).json();
    const inn = c.summary.find((s) => s.dir === 'in' && s.ip === '1.2.3.4');
    const out = c.summary.find((s) => s.dir === 'out' && s.ip === '1.2.3.4');
    assert.deepEqual([inn.packets, inn.bytes, inn.buckets], [3, 3701, [1, 1, 1, 0, 0]]);
    assert.deepEqual([out.packets, out.buckets], [1, [0, 0, 0, 0, 1]]);
    assert.ok(c.files.some((f) => f.name === 'live.log'));
    await post(env, env.auth, 'api/capture/reset');
    assert.equal((await get(env, env.auth, 'api/capture')).json().summary.length, 0);
    await post(env, env.auth, 'api/capture/clearlog');
    assert.equal(fs.statSync(path.join(env.config.captureDir, 'live.log')).size, 0);
});

test('live.log rotates at 20 MB keeping one old file', async () => {
    const env = await setup();
    await env.app.startCapture({});
    const [dump] = env.runner.pidOf('tcpdump', '-tttt');
    const big = ('x'.repeat(1023) + '\n').repeat(1024); // 1 MB
    for (let i = 0; i < 21; i++) env.runner.emitDump(dump, big);
    const dir = env.config.captureDir;
    assert.ok(fs.existsSync(path.join(dir, 'live.log.1')));
    assert.ok(fs.statSync(path.join(dir, 'live.log')).size <= 20 * 1024 * 1024);
    assert.ok(fs.statSync(path.join(dir, 'live.log')).size > 0);
    assert.equal(fs.readdirSync(dir).filter((f) => f.startsWith('live.log')).length, 2);
});

test('capture file download: allowlisted names only', async () => {
    const env = await setup();
    fs.writeFileSync(path.join(env.config.captureDir, 'qmgr.pcap0'), 'pcapdata');
    fs.writeFileSync(path.join(env.config.captureDir, 'secret.txt'), 'no');
    const ok = await get(env, env.auth, 'api/capture/file/qmgr.pcap0');
    assert.equal(ok.status, 200);
    assert.equal(ok.headers['Content-Disposition'], 'attachment; filename="qmgr.pcap0"');
    assert.equal((await get(env, env.auth, 'api/capture/file/secret.txt')).status, 404);
    assert.equal((await get(env, env.auth, 'api/capture/file/..%2Fetc')).status, 404);
});

// ---- logs

test('log tail with filter, truncate needs confirm, download', async () => {
    const env = await setup();
    const logf = path.join(env.trojanDir, 'trojan.log');
    let r = (await get(env, env.auth, 'api/log/trojan?lines=2')).json();
    assert.deepEqual(r.lines, ['line two', 'line three 5.6.7.8']);
    r = (await get(env, env.auth, 'api/log/trojan?filter=1.2.3.4')).json();
    assert.deepEqual(r.lines, ['line one 1.2.3.4']);
    assert.equal((await post(env, env.auth, 'api/log/trojan/clear', {})).status, 400);
    assert.ok(fs.statSync(logf).size > 0);
    assert.equal((await get(env, env.auth, 'api/log/trojan/clear')).status, 405);
    const dl = await get(env, env.auth, 'api/log/trojan/download');
    assert.equal(dl.status, 200);
    const t = await post(env, env.auth, 'api/log/trojan/clear', { confirm: true });
    assert.equal(t.status, 200);
    assert.equal(fs.statSync(logf).size, 0);
    assert.ok((await env.app.status()).actions.some((a) => a.action === 'log'));
});

test('trojan log auto-detected from ps args -l when not configured; control log only when present', async () => {
    const env = makeEnv({ config: { trojanLog: '' } });
    const pid = env.runner.addTrojan443();
    env.runner.procs.get(pid).argv = ['/root/trojan-plus-temp/trojan', '-c', 'config.json', '-l', 'trojan.log'];
    await env.app.init();
    env.auth = await login(env);
    assert.equal((await get(env, env.auth, 'api/log/trojan')).json().exists, true);
    assert.equal((await get(env, env.auth, 'api/log/control')).json().exists, false);
    await env.app.setMode('control');
    fs.writeFileSync(path.join(path.dirname(env.config.stateFile), 'control.log'), 'ctl line\n');
    assert.deepEqual((await get(env, env.auth, 'api/log/control')).json().lines, ['ctl line']);
});
