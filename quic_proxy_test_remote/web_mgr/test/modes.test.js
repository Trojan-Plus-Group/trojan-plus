'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { makeEnv, login, post, get } = require('./helper.js');

const scriptCalls = (r) => r.calls.filter((c) => c.includes('run_trojan-plus.sh'));

async function withTrojan() {
    const env = makeEnv();
    env.runner.addTrojan443();
    env.preexisting = env.runner.addForeign('iperf3', 9988); // unrelated, must survive
    await env.app.init();
    return env;
}

test('startup reconcile detects trojan mode from ss, not the file', async () => {
    const env = await withTrojan();
    assert.equal(env.app.getState().mode, 'trojan');
    const s = await env.app.status();
    assert.deepEqual(s.listeners.tcp443.length, 1);
    assert.deepEqual(s.warnings, []);
});

test('443 owned by nothing: mode unknown plus warning', async () => {
    const env = makeEnv();
    await env.app.init();
    const s = await env.app.status();
    assert.equal(s.mode, 'unknown');
    assert.ok(s.warnings.some((w) => /owned by nothing/.test(w)));
});

test('trojan -> iperf3 -> trojan: exact commands, only tracked pid killed', async () => {
    const env = await withTrojan();
    const r = env.runner;
    r.calls.length = 0;
    await env.app.setMode('iperf3');
    assert.ok(scriptCalls(r)[0].endsWith('run_trojan-plus.sh stop 443'));
    assert.equal(scriptCalls(r).length, 1);
    assert.equal(r.calls.filter((c) => c.startsWith('/usr/bin/iperf3')).join(), '/usr/bin/iperf3 -s -p 443');
    assert.equal(env.app.getState().mode, 'iperf3');
    const [ipid] = r.pidOf('iperf3', '443');
    assert.equal(r.listening('tcp', 443)[0], ipid);

    r.calls.length = 0;
    await env.app.setMode('trojan');
    assert.deepEqual(r.kills.map((k) => k[0]), [ipid], 'only our iperf3 killed');
    assert.ok(scriptCalls(r)[0].endsWith('run_trojan-plus.sh start 443'));
    assert.ok(r.procs.has(env.preexisting), 'iperf3 on 9988 untouched');
    assert.equal(env.app.getState().mode, 'trojan');
    assert.deepEqual(env.app.getState().tracked.iperf3, []);
});

test('control mode: second trojan on controlPort with copied config, 443 untouched', async () => {
    const env = await withTrojan();
    const r = env.runner;
    r.calls.length = 0;
    await env.app.setMode('control');
    assert.equal(scriptCalls(r).length, 0, 'main trojan not touched');
    const spawned = r.calls.filter((c) => c.includes(' -c ') && c.includes(' -l '));
    assert.equal(spawned.length, 1);
    const stateDir = path.dirname(env.config.stateFile);
    assert.equal(spawned[0], `${path.join(env.trojanDir, 'trojan')} -c ${path.join(stateDir, 'control-config.json')} -l ${path.join(stateDir, 'control.log')}`);
    const copy = JSON.parse(fs.readFileSync(path.join(stateDir, 'control-config.json'), 'utf8'));
    const orig = JSON.parse(fs.readFileSync(env.trojanConf, 'utf8'));
    assert.equal(copy.local_port, 8443);
    assert.deepEqual({ ...copy, local_port: 443 }, orig);
    assert.equal(JSON.parse(fs.readFileSync(env.trojanConf, 'utf8')).local_port, 443, 'original config unchanged');
    assert.equal(r.listening('tcp', 8443).length, 1);
    const [cpid] = r.listening('tcp', 8443);

    // leaving control mode stops only that instance
    await env.app.setMode('trojan');
    assert.deepEqual(r.kills.map((k) => k[0]), [cpid]);
    assert.equal(scriptCalls(r).length, 0, 'trojan 443 was never restarted');
    assert.equal(r.listening('tcp', 443).length, 1);
    assert.ok(r.procs.has(env.preexisting));
});

test('control -> iperf3 stops control then swaps 443', async () => {
    const env = await withTrojan();
    await env.app.setMode('control');
    const [cpid] = env.runner.listening('tcp', 8443);
    await env.app.setMode('iperf3');
    assert.equal(env.runner.kills[0][0], cpid);
    assert.equal(env.runner.listening('tcp', 8443).length, 0);
    assert.equal(env.app.getState().mode, 'iperf3');
});

test('never kills a pid whose cmdline no longer matches (pid reuse)', async () => {
    const env = await withTrojan();
    await env.app.setMode('iperf3');
    const [ipid] = env.runner.pidOf('iperf3', '443');
    // simulate pid reuse: same pid now runs something else
    env.runner.procs.get(ipid).argv = ['/usr/sbin/sshd', '-D'];
    env.runner.procs.get(ipid).ports = [];
    await env.app.setMode('trojan');
    assert.deepEqual(env.runner.kills, [], 'no kill issued');
    assert.ok(env.runner.procs.has(ipid));
    assert.ok(env.app.getState().tracked.iperf3.length === 0);
    assert.ok((await env.app.status()).actions.some((a) => a.action === 'kill-skip'));
});

test('failed switch restores trojan and reports the failure', async () => {
    const env = await withTrojan();
    // make iperf3 unable to bind: foreign process grabs 443 right after stop
    const orig = env.runner.run.bind(env.runner);
    env.runner.run = async (cmd, args, o) => {
        const res = await orig(cmd, args, o);
        if (cmd.endsWith('run_trojan-plus.sh') && args[0] === 'stop') env.squat = env.runner.addForeign('squatter', 443);
        return res;
    };
    await assert.rejects(env.app.setMode('iperf3'), /443 not freed/);
    assert.ok(env.runner.procs.has(env.squat), 'foreign process not killed');
    const last = (await env.app.status()).actions[0];
    assert.match(last.result, /FAILED/);
});

test('trojan verify failure is reported', async () => {
    const env = makeEnv();
    await env.app.init(); // nothing running
    env.runner.startFails = true;
    await assert.rejects(env.app.setMode('trojan'), /does not own TCP\+UDP 443/);
    assert.equal(env.app.getState().mode, 'unknown');
});

test('mode switches are serialized by a mutex', async () => {
    const env = await withTrojan();
    const a = env.app.setMode('iperf3');
    const b = env.app.setMode('trojan');
    const c = env.app.setMode('control');
    await Promise.all([a, b, c]);
    assert.equal(env.app.getState().mode, 'control');
    const modes = (await env.app.status()).actions.filter((x) => x.action === 'mode').map((x) => x.detail).reverse();
    assert.deepEqual(modes, ['trojan to iperf3 (manual)', 'iperf3 to trojan (manual)', 'trojan to control (manual)']);
});

test('state persisted; tracked iperf3 survives qmgr restart and is stopped later', async () => {
    const env = await withTrojan();
    await env.app.setMode('iperf3');
    const saved = JSON.parse(fs.readFileSync(env.config.stateFile, 'utf8'));
    assert.equal(saved.mode, 'iperf3');
    assert.equal(saved.tracked.iperf3.length, 1);
    const { createApp } = require('../server.js');
    const app2 = createApp({ config: env.config, runner: env.runner, clock: env.clock, logger: { log() {}, error() {} } });
    await app2.init();
    assert.equal(app2.getState().mode, 'iperf3');
    await app2.setMode('trojan');
    assert.equal(env.runner.kills.length, 1);
    assert.equal(env.runner.listening('tcp', 443).length, 1);
});

test('HTTP API drives a mode switch', async () => {
    const env = await withTrojan();
    const auth = await login(env);
    const r = await post(env, auth, 'api/mode', { mode: 'iperf3', autoRestoreMin: 5 });
    assert.equal(r.status, 200);
    const s = r.json();
    assert.equal(s.mode, 'iperf3');
    assert.equal(s.autoRestoreMin, 5);
    assert.equal(s.deadline, env.clock.now() + 300000);
    assert.equal(s.iperf3.length, 1);
    assert.equal((await get(env, auth, 'api/status')).json().mode, 'iperf3');
});

test('every state change lands in actions.log', async () => {
    const env = await withTrojan();
    await env.app.setMode('iperf3');
    await env.app.setMode('trojan');
    const lines = fs.readFileSync(path.join(path.dirname(env.config.stateFile), 'actions.log'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.filter((l) => l.action === 'mode').length, 2);
    assert.ok(lines[0].t && lines[0].result);
});
