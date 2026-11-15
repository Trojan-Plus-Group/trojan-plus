'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { makeEnv, login, post } = require('./helper.js');
const { createApp } = require('../server.js');

async function withTrojan() {
    const env = makeEnv();
    env.runner.addTrojan443();
    await env.app.init();
    return env;
}
const quiet = { log() {}, error() {} };

test('auto-restore deadline fires with fake clock', async () => {
    const env = await withTrojan();
    await env.app.setAutoRestore(10);
    await env.app.setMode('iperf3');
    assert.equal(env.app.getState().deadline, env.clock.now() + 600000);
    env.clock.advance(599000);
    await env.app.tick();
    assert.equal(env.app.getState().mode, 'iperf3');
    env.clock.advance(2000);
    await env.app.tick();
    assert.equal(env.app.getState().mode, 'trojan');
    assert.equal(env.app.getState().deadline, null);
    assert.equal(env.runner.listening('tcp', 443).length, 1);
    assert.ok((await env.app.status()).actions.some((a) => a.action === 'auto-restore'));
});

test('auto-restore off by default: no deadline', async () => {
    const env = await withTrojan();
    await env.app.setMode('iperf3');
    assert.equal(env.app.getState().deadline, null);
    env.clock.advance(3600000);
    await env.app.tick();
    assert.equal(env.app.getState().mode, 'iperf3');
});

test('auto-restore can be changed while in a mode, and turned off', async () => {
    const env = await withTrojan();
    await env.app.setMode('control');
    assert.equal(env.app.getState().deadline, null);
    await env.app.setAutoRestore(5);
    assert.equal(env.app.getState().deadline, env.clock.now() + 300000);
    env.clock.advance(120000);
    await env.app.setAutoRestore(15);
    assert.equal(env.app.getState().deadline, env.clock.now() + 900000);
    await env.app.setAutoRestore(0);
    assert.equal(env.app.getState().deadline, null);
});

test('qmgr restart with past deadline restores trojan immediately', async () => {
    const env = await withTrojan();
    await env.app.setAutoRestore(5);
    await env.app.setMode('iperf3');
    env.clock.advance(3600000); // qmgr "down" for an hour
    const app2 = createApp({ config: env.config, runner: env.runner, clock: env.clock, logger: quiet });
    await app2.init();
    assert.equal(app2.getState().mode, 'trojan');
    assert.equal(env.runner.listening('tcp', 443).length, 1);
    assert.equal(env.runner.listening('tcp', 443).every((p) => env.runner.procs.get(p).name === 'trojan'), true);
});

test('qmgr restart with future deadline keeps mode and deadline', async () => {
    const env = await withTrojan();
    await env.app.setAutoRestore(15);
    await env.app.setMode('iperf3');
    const dl = env.app.getState().deadline;
    env.clock.advance(60000);
    const app2 = createApp({ config: env.config, runner: env.runner, clock: env.clock, logger: quiet });
    await app2.init();
    assert.equal(app2.getState().mode, 'iperf3');
    assert.equal(app2.getState().deadline, dl);
});

// ---- payload size

const readConf = (env) => JSON.parse(fs.readFileSync(env.trojanConf, 'utf8'));

test('payload edit changes only quic.tx_udp_payload_size, keeps keys and 4-space indent, backs up, restarts', async () => {
    const env = await withTrojan();
    const before = readConf(env);
    const raw = fs.readFileSync(env.trojanConf, 'utf8');
    env.runner.calls.length = 0;
    await env.app.applyPayload(1350);
    const after = readConf(env);
    assert.equal(after.quic.tx_udp_payload_size, 1350);
    assert.deepEqual({ ...after, quic: { ...after.quic, tx_udp_payload_size: 0 } }, before);
    assert.match(fs.readFileSync(env.trojanConf, 'utf8'), /\n {4}"quic": \{\n {8}"enabled"/);
    const baks = fs.readdirSync(env.trojanDir).filter((f) => /^config\.json\.qmgr-.*\.bak$/.test(f));
    assert.equal(baks.length, 1);
    assert.equal(fs.readFileSync(path.join(env.trojanDir, baks[0]), 'utf8'), raw);
    const cmds = env.runner.calls.filter((c) => !c.startsWith('ss'));
    assert.equal(cmds.length, 2);
    assert.equal(cmds[0], `${path.join(env.trojanDir, 'trojan')} -t -c ${env.trojanConf}`);
    assert.ok(cmds[1].endsWith('run_trojan-plus.sh restart 443'));
    assert.equal(env.runner.listening('udp', 443).length, 1);
    assert.equal((await env.app.status()).payload.value, 1350);
});

test('payload: -t failure restores the original config, no restart, secret not leaked', async () => {
    const env = await withTrojan();
    const raw = fs.readFileSync(env.trojanConf, 'utf8');
    env.runner.testFail = true;
    env.runner.calls.length = 0;
    await assert.rejects(env.app.applyPayload(1400), (e) => /restored/.test(e.message) && !e.message.includes('SECRETPASS'));
    assert.equal(fs.readFileSync(env.trojanConf, 'utf8'), raw);
    assert.equal(env.runner.calls.filter((c) => c.includes('run_trojan-plus.sh')).length, 0);
    assert.match((await env.app.status()).actions[0].result, /FAILED/);
});

test('payload: restart that fails to listen restores config and restarts again', async () => {
    const env = await withTrojan();
    const raw = fs.readFileSync(env.trojanConf, 'utf8');
    let n = 0;
    const orig = env.runner.run.bind(env.runner);
    env.runner.run = async (cmd, args, o) => {
        if (cmd.endsWith('run_trojan-plus.sh') && args[0] === 'restart' && n++ === 0) {
            env.runner.calls.push(`${cmd} ${args.join(' ')}`);
            for (const [pid, p] of [...env.runner.procs]) if (p.fromScript) env.runner.procs.delete(pid);
            return { code: 0, stdout: '', stderr: '' }; // died
        }
        return orig(cmd, args, o);
    };
    await assert.rejects(env.app.applyPayload(1250), /config restored, trojan running again/);
    assert.equal(fs.readFileSync(env.trojanConf, 'utf8'), raw);
    assert.equal(env.runner.listening('tcp', 443).length, 1);
});

test('payload: keeps only last 10 backups', async () => {
    const env = await withTrojan();
    for (let i = 0; i < 13; i++) {
        env.clock.advance(1000);
        await env.app.applyPayload(i % 2 ? 1200 : 1250);
    }
    const baks = fs.readdirSync(env.trojanDir).filter((f) => f.endsWith('.bak')).sort();
    assert.equal(baks.length, 10);
    assert.ok(baks[9] > baks[0]);
});

test('payload: refused outside trojan mode; 0 allowed; adds quic section if missing', async () => {
    const env = await withTrojan();
    await env.app.setMode('iperf3');
    await assert.rejects(env.app.applyPayload(1200), /only be changed in trojan mode/);
    await env.app.setMode('trojan');
    const conf = readConf(env);
    delete conf.quic;
    fs.writeFileSync(env.trojanConf, JSON.stringify(conf, null, 4));
    await env.app.applyPayload(0);
    assert.equal(readConf(env).quic.tx_udp_payload_size, 0);
});

test('status exposes only the payload key, never secrets', async () => {
    const env = await withTrojan();
    const auth = await login(env);
    const r = await post(env, auth, 'api/payload', { size: 1250 });
    assert.equal(r.status, 200);
    assert.equal(r.json().payload.value, 1250);
    assert.ok(!r.text.includes('SECRETPASS'));
    const bad = await post(env, auth, 'api/payload', { size: 1100 });
    assert.equal(bad.status, 400);
});
