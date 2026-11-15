'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { makeEnv } = require('./helper.js');

function request(port, method, p, headers = {}, body) {
    return new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, method, path: p, headers }, (res) => {
            let t = '';
            res.on('data', (d) => (t += d));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: t }));
        });
        req.on('error', reject);
        req.end(body);
    });
}

test('real HTTP server on ephemeral port, login flow under a base path', async () => {
    const env = makeEnv({ basePath: '/qmgr/' });
    env.runner.addTrojan443();
    await env.app.init();
    const server = env.app.listen();
    await new Promise((r) => (server.listening ? r() : server.once('listening', r)));
    const { port } = server.address();
    try {
        let r = await request(port, 'GET', '/qmgr/');
        assert.equal(r.status, 200);
        assert.match(r.text, /<form/);
        assert.equal((await request(port, 'GET', '/')).status, 404);

        r = await request(port, 'GET', `/qmgr/?token=${env.token()}`);
        assert.equal(r.status, 302);
        assert.equal(r.headers.location, '/qmgr/');
        const cookie = r.headers['set-cookie'][0].split(';')[0];

        r = await request(port, 'GET', '/qmgr/', { cookie });
        assert.equal(r.status, 200);
        assert.match(r.text, /<title>qmgr<\/title>/);
        assert.match(r.text, /href="style.css"/);
        assert.match(r.text, /src="app.js"/);
        assert.doesNotMatch(r.text, /(?:href|src)="\//, 'all links relative');

        r = await request(port, 'GET', '/qmgr/app.js', { cookie });
        assert.equal(r.status, 200);
        assert.match(r.headers['content-type'], /javascript/);
        assert.doesNotMatch(r.text, /fetch\('\//, 'fetches relative');

        r = await request(port, 'GET', '/qmgr/api/status', { cookie });
        assert.equal(r.status, 200);
        assert.equal(JSON.parse(r.text).mode, 'trojan');

        r = await request(port, 'POST', '/qmgr/api/capture/reset', { cookie });
        assert.equal(r.status, 403);

        // SSE: first event arrives, then the client hangs up
        const first = await new Promise((resolve, reject) => {
            const q = http.get({ host: '127.0.0.1', port, path: '/qmgr/api/log/trojan/stream', headers: { cookie } }, (res) => {
                res.once('data', (d) => {
                    resolve({ status: res.statusCode, type: res.headers['content-type'], text: String(d) });
                    q.destroy();
                });
            });
            q.on('error', reject);
        });
        assert.equal(first.status, 200);
        assert.match(first.type, /text\/event-stream/);
    } finally {
        await env.app.shutdown();
        server.closeAllConnections();
    }
});
