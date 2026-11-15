'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createApp } = require('../server.js');
const { FakeRunner } = require('../fake_runner.js');

const TROJAN_CONF = {
    run_type: 'server',
    local_addr: '0.0.0.0',
    local_port: 443,
    password: ['SECRETPASS'],
    ssl: { cert: '/c.pem', key: '/k.pem' },
    quic: { enabled: true, tx_udp_payload_size: 0, keep: 'me' },
};

function fakeClock(start = 1_700_000_000_000) {
    const c = {
        t: start,
        now: () => c.t,
        sleep: async (ms) => {
            c.t += ms;
        },
        advance: (ms) => {
            c.t += ms;
        },
    };
    return c;
}

function makeEnv(opts = {}) {
    const dir = fs.mkdtempSync(path.join(process.env.QMGR_TEST_TMP || os.tmpdir(), 'qmgr-test-'));
    process.on('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
    const trojanDir = path.join(dir, 'trojan');
    fs.mkdirSync(trojanDir);
    fs.writeFileSync(path.join(trojanDir, 'config.json'), JSON.stringify(TROJAN_CONF, null, 4) + '\n');
    fs.writeFileSync(path.join(trojanDir, 'trojan.log'), 'line one 1.2.3.4\nline two\nline three 5.6.7.8\n');
    const config = {
        listenPort: 0,
        basePath: opts.basePath || '/qmgr/',
        tokenFile: path.join(dir, 'etc', 'token'),
        stateFile: path.join(dir, 'var', 'state.json'),
        captureDir: path.join(dir, 'var', 'cap'),
        trojanDir,
        trojanBinary: 'trojan',
        trojanLog: 'trojan.log',
        controlPort: 8443,
        ...opts.config,
    };
    const runner = new FakeRunner(config);
    const clock = fakeClock();
    const logs = [];
    const logger = { log: (m) => logs.push(m), error: (m) => logs.push(m) };
    const app = createApp({ config, runner, clock, logger });
    return { dir, config, runner, clock, app, logs, trojanDir, trojanConf: path.join(trojanDir, 'config.json'), token: () => fs.readFileSync(config.tokenFile, 'utf8').trim() };
}

// Minimal request/response doubles for calling app.handler without a socket.
function call(app, method, url, { headers = {}, body, remote = '127.0.0.1' } = {}) {
    return new Promise((resolve) => {
        const { Readable } = require('node:stream');
        const req = Readable.from(body === undefined ? [] : [Buffer.from(typeof body === 'string' ? body : JSON.stringify(body))]);
        Object.assign(req, { method, url, headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])), socket: { remoteAddress: remote } });
        const res = {
            headersSent: false,
            head: {},
            chunks: [],
            writeHead(status, h) {
                this.status = status;
                this.head = h;
                this.headersSent = true;
            },
            write(c) {
                this.chunks.push(String(c));
                return true;
            },
            end(c) {
                if (c) this.chunks.push(String(c));
                resolve({ status: this.status, headers: this.head, text: this.chunks.join(''), json: () => JSON.parse(this.chunks.join('')) });
            },
            on() {},
        };
        app.handler(req, res);
    });
}

async function login(env) {
    const r = await call(env.app, 'GET', `${env.config.basePath}?token=${env.token()}`);
    const cookie = r.headers['Set-Cookie'].split(';')[0];
    return { Cookie: cookie };
}

// authenticated helpers
const get = (env, auth, url) => call(env.app, 'GET', env.config.basePath + url, { headers: auth });
const post = (env, auth, url, body = {}) => call(env.app, 'POST', env.config.basePath + url, { headers: { ...auth, 'X-Qmgr': '1' }, body });

module.exports = { makeEnv, call, login, get, post, fakeClock, TROJAN_CONF };
