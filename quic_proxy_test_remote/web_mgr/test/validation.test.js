'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parsePort, parseIp, parsePorts, parsePayload, buildFilter, parseSs, parseDumpLine } = require('../server.js');
const { makeEnv, login, post } = require('./helper.js');

test('port validation', () => {
    for (const ok of [1, 443, '8443', 65535]) assert.ok(parsePort(ok));
    for (const no of [0, 65536, -1, 1.5, '44a', '', '1e3', null, undefined, '443; ls', ' ', {}, []]) {
        assert.throws(() => parsePort(no), /invalid port/, String(no));
    }
});

test('IP validation: IPv4/IPv6 literals only', () => {
    for (const ok of ['1.2.3.4', '2001:db8::1', '::1', '::ffff:1.2.3.4']) assert.equal(parseIp(ok), ok);
    for (const no of ['', 'example.com', '1.2.3', '1.2.3.4/24', '1.2.3.4 or port 22', 'fe80::1%eth0', '999.1.1.1', '1.2.3.4;id', '$(id)', null, 5]) {
        assert.throws(() => parseIp(no), /invalid IP/, String(no));
    }
});

test('ports list parsing', () => {
    assert.deepEqual(parsePorts('443, 8443,443', [1]), [443, 8443]);
    assert.deepEqual(parsePorts('', [443, 8443]), [443, 8443]);
    assert.deepEqual(parsePorts(undefined, [443]), [443]);
    assert.throws(() => parsePorts('443,abc', []), /invalid port/);
    assert.throws(() => parsePorts('443 or 22', []), /invalid port/);
    assert.throws(() => parsePorts('1,2,3,4,5,6,7,8,9', []), /too many/);
});

test('payload validation', () => {
    for (const ok of [0, 1200, 1250, 1452, '1400']) assert.doesNotThrow(() => parsePayload(ok));
    for (const no of [1, 1199, 1453, -5, 1e9, 1300.5, 'abc', '', null, undefined]) assert.throws(() => parsePayload(no), /payload size/, String(no));
});

test('capture filter is built from validated parts', () => {
    assert.equal(buildFilter([443, 8443], ''), 'udp and (port 443 or port 8443)');
    assert.equal(buildFilter([443], '1.2.3.4'), 'udp and (port 443) and host 1.2.3.4');
    assert.equal(buildFilter([443], '2001:db8::1', 'udp'), 'udp and (port 443) and host 2001:db8::1');
    assert.equal(buildFilter([443, 8443], '', 'tcp+udp'), '(udp or tcp) and (port 443 or port 8443)');
    assert.equal(buildFilter([443], '1.2.3.4', 'tcp+udp'), '(udp or tcp) and (port 443) and host 1.2.3.4');
    assert.throws(() => buildFilter([443], '', 'tcp'), /invalid protocol/);
});

test('ss -lntup parsing', () => {
    const out = [
        'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process',
        'tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("trojan",pid=10,fd=5))',
        'udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("trojan",pid=10,fd=6),("trojan",pid=11,fd=6))',
        'tcp LISTEN 0 4096 [::]:9988 [::]:* users:(("iperf3",pid=77,fd=3))',
        'tcp LISTEN 0 128 *:22 *:*',
    ].join('\n');
    const l = parseSs(out);
    assert.equal(l.length, 4);
    assert.deepEqual(l[1].procs.map((p) => p.pid), [10, 11]);
    assert.equal(l[2].port, 9988);
    assert.deepEqual(l[3].procs, []);
});

test('tcpdump line parsing', () => {
    const d = parseDumpLine('2026-11-15 10:00:00.123456 IP 1.2.3.4.51000 > 5.6.7.8.443: UDP, length 1250');
    assert.deepEqual(d, { ts: '2026-11-15 10:00:00.123456', proto: 'udp', src: { ip: '1.2.3.4', port: 51000 }, dst: { ip: '5.6.7.8', port: 443 }, len: 1250 });
    const d6 = parseDumpLine('2026-11-15 10:00:00.1 IP6 2001:db8::1.51000 > 2001:db8::2.443: UDP, length 30');
    assert.equal(d6.src.ip, '2001:db8::1');
    assert.equal(parseDumpLine('garbage'), null);
});

test('regression: tcpdump lines from the real host', () => {
    // -n only: service name instead of a numeric port, not parseable (the reason for -nn)
    const named = '2026-11-15 08:44:33.931745 IP 92.63.204.149.58167 > 172.236.226.35.https: Flags [S], seq 1, win 64240, length 0';
    assert.equal(parseDumpLine(named), null);
    // -nn output of the same packet
    const tcp = parseDumpLine('2026-11-15 08:44:33.931745 IP 92.63.204.149.58167 > 172.236.226.35.443: Flags [S], seq 1, win 64240, length 0');
    assert.deepEqual(tcp, { ts: '2026-11-15 08:44:33.931745', proto: 'tcp', src: { ip: '92.63.204.149', port: 58167 }, dst: { ip: '172.236.226.35', port: 443 }, len: 0 });
    const udp = parseDumpLine('2026-11-15 08:44:34.000001 IP 1.2.3.4.51000 > 172.236.226.35.443: UDP, length 1250');
    assert.deepEqual(udp, { ts: '2026-11-15 08:44:34.000001', proto: 'udp', src: { ip: '1.2.3.4', port: 51000 }, dst: { ip: '172.236.226.35', port: 443 }, len: 1250 });
    const v6 = parseDumpLine('2026-11-15 08:44:35.000001 IP6 2001:db8::1.51000 > 2001:db8::2.443: UDP, length 1350');
    assert.deepEqual(v6, { ts: '2026-11-15 08:44:35.000001', proto: 'udp', src: { ip: '2001:db8::1', port: 51000 }, dst: { ip: '2001:db8::2', port: 443 }, len: 1350 });
});

test('API rejects bad input before running anything', async () => {
    const env = makeEnv();
    await env.app.init();
    const auth = await login(env);
    const before = env.runner.calls.length;
    const cases = [
        ['api/mode', { mode: 'rm -rf' }],
        ['api/mode', { mode: 'iperf3', autoRestoreMin: 7 }],
        ['api/autorestore', { minutes: 99 }],
        ['api/payload', { size: 1100 }],
        ['api/payload', { size: '1300; id' }],
        ['api/capture/start', { ports: '443,99999' }],
        ['api/capture/start', { ports: '443', clientIp: '1.2.3.4 or port 22' }],
        ['api/capture/start', { maxMinutes: 9999 }],
    ];
    for (const [url, body] of cases) {
        const r = await post(env, auth, url, body);
        assert.equal(r.status, 400, url + JSON.stringify(body));
    }
    assert.equal(env.runner.calls.length, before);
    assert.equal(env.runner.calls.some((c) => c.startsWith('tcpdump')), false);
});
