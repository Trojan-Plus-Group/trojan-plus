'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { makeEnv, call, login, get, post } = require('./helper.js');

test('token file created 0600 on init, login hint logged once', async () => {
    const env = makeEnv();
    await env.app.init();
    assert.equal(fs.statSync(env.config.tokenFile).mode & 0o777, 0o600);
    assert.match(env.token(), /^[0-9a-f]{64}$/);
    assert.equal(env.logs.filter((l) => l.includes('?token=' + env.token())).length, 1);
    const env2 = makeEnv();
    fs.mkdirSync(require('node:path').dirname(env2.config.tokenFile), { recursive: true });
    fs.writeFileSync(env2.config.tokenFile, 'abc123');
    await env2.app.init();
    assert.equal(env2.logs.filter((l) => l.includes('abc123')).length, 0, 'existing token never logged');
});

test('no cookie: page shows login, API 401', async () => {
    const env = makeEnv();
    await env.app.init();
    const page = await call(env.app, 'GET', '/qmgr/');
    assert.equal(page.status, 200);
    assert.match(page.text, /<form/);
    assert.doesNotMatch(page.text, /id="mode"/);
    for (const u of ['api/status', 'api/capture', 'api/log/trojan', 'api/capture/stream']) {
        assert.equal((await call(env.app, 'GET', '/qmgr/' + u)).status, 401, u);
    }
    assert.equal((await call(env.app, 'POST', '/qmgr/api/mode', { headers: { 'X-Qmgr': '1' }, body: { mode: 'trojan' } })).status, 401);
    assert.equal((await call(env.app, 'GET', '/other')).status, 404);
});

test('token login via query sets cookie, redirects without token', async () => {
    const env = makeEnv();
    await env.app.init();
    const r = await call(env.app, 'GET', `/qmgr/?token=${env.token()}`);
    assert.equal(r.status, 302);
    assert.equal(r.headers.Location, '/qmgr/');
    const sc = r.headers['Set-Cookie'];
    const want = crypto.createHmac('sha256', env.token()).update('qmgr-cookie-v1').digest('hex');
    assert.ok(sc.startsWith(`qmgr=${want};`));
    for (const a of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/qmgr/', 'Max-Age=2592000']) assert.ok(sc.includes(a), a);
    const cookie = { Cookie: sc.split(';')[0] };
    assert.equal((await get(env, cookie, 'api/status')).status, 200);
    assert.match((await get(env, cookie, '')).text, /id="mode"/);
});

test('token login via POST form', async () => {
    const env = makeEnv();
    await env.app.init();
    const r = await call(env.app, 'POST', '/qmgr/login', { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'token=' + env.token() });
    assert.equal(r.status, 302);
    assert.ok(r.headers['Set-Cookie']);
    const bad = await call(env.app, 'POST', '/qmgr/login', { body: 'token=nope' });
    assert.equal(bad.status, 401);
    assert.equal(bad.headers['Set-Cookie'], undefined);
});

test('bad token rate limited per IP, other IP unaffected, window expires', async () => {
    const env = makeEnv();
    await env.app.init();
    for (let i = 0; i < 10; i++) assert.equal((await call(env.app, 'GET', '/qmgr/?token=bad')).status, 401);
    assert.equal((await call(env.app, 'GET', '/qmgr/?token=bad')).status, 429);
    assert.equal((await call(env.app, 'GET', `/qmgr/?token=${env.token()}`)).status, 429, 'good token also blocked while limited');
    const other = await call(env.app, 'GET', '/qmgr/?token=bad', { headers: { 'X-Forwarded-For': '9.9.9.9' } });
    assert.equal(other.status, 401, 'XFF from 127.0.0.1 is trusted: separate bucket');
    env.clock.advance(61000);
    assert.equal((await call(env.app, 'GET', `/qmgr/?token=${env.token()}`)).status, 302);
});

test('X-Forwarded-For ignored from non-loopback peers', async () => {
    const env = makeEnv();
    await env.app.init();
    for (let i = 0; i < 10; i++) await call(env.app, 'GET', '/qmgr/?token=bad', { remote: '5.5.5.5', headers: { 'X-Forwarded-For': `1.1.1.${i}` } });
    const r = await call(env.app, 'GET', '/qmgr/?token=bad', { remote: '5.5.5.5', headers: { 'X-Forwarded-For': '2.2.2.2' } });
    assert.equal(r.status, 429);
});

test('POST without X-Qmgr rejected, with header accepted', async () => {
    const env = makeEnv();
    await env.app.init();
    const auth = await login(env);
    const no = await call(env.app, 'POST', '/qmgr/api/capture/reset', { headers: auth, body: {} });
    assert.equal(no.status, 403);
    const mode = await call(env.app, 'POST', '/qmgr/api/mode', { headers: auth, body: { mode: 'iperf3' } });
    assert.equal(mode.status, 403);
    assert.equal(env.runner.calls.filter((c) => !c.startsWith('ss')).length, 0, 'nothing executed');
    assert.equal((await post(env, auth, 'api/capture/reset')).status, 200);
});

test('state-changing endpoints are POST only', async () => {
    const env = makeEnv();
    await env.app.init();
    const auth = await login(env);
    for (const u of ['api/mode', 'api/payload', 'api/capture/start', 'api/capture/stop', 'api/log/trojan/clear']) {
        const r = await get(env, auth, u);
        assert.ok([404, 405].includes(r.status), `${u} -> ${r.status}`);
    }
    assert.equal((await call(env.app, 'PUT', '/qmgr/api/mode', { headers: auth })).status, 405);
});

test('rotating the token invalidates cookies', async () => {
    const env = makeEnv();
    await env.app.init();
    const auth = await login(env);
    assert.equal((await get(env, auth, 'api/status')).status, 200);
    fs.writeFileSync(env.config.tokenFile, 'rotated-token');
    assert.equal((await get(env, auth, 'api/status')).status, 401);
});

test('cookie with wrong value rejected', async () => {
    const env = makeEnv();
    await env.app.init();
    assert.equal((await get(env, { Cookie: 'qmgr=' + '0'.repeat(64) }, 'api/status')).status, 401);
    assert.equal((await get(env, { Cookie: 'qmgr=abc' }, 'api/status')).status, 401);
});

test('custom base path is honored in cookie path and redirect', async () => {
    const env = makeEnv({ basePath: 'tools/q' });
    await env.app.init();
    const r = await call(env.app, 'GET', `/tools/q/?token=${env.token()}`);
    assert.equal(r.headers.Location, '/tools/q/');
    assert.match(r.headers['Set-Cookie'], /Path=\/tools\/q\//);
    assert.equal((await call(env.app, 'GET', '/tools/q')).status, 302);
});
