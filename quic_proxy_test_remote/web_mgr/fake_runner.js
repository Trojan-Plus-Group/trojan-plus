'use strict';
// In-memory stand-in for the runner used by server.js: simulates ss, ps, the trojan run script,
// trojan -t, iperf3 and tcpdump. Used by the tests and by the QMGR_FAKE=1 demo mode.
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');

class FakeRunner {
  constructor(cfg) {
    this.cfg = cfg;
    this.calls = []; // every command as one string: "cmd arg arg"
    this.kills = []; // [pid, signal]
    this.procs = new Map(); // pid -> {name, argv, ports:[[proto,port]], fromScript, emitter}
    this.nextPid = 1000;
    this.testFail = false; // trojan -t fails
    this.startFails = false; // run script start leaves nothing listening
    this.ssFails = false;
    this.dumpLines = [];
  }

  add(name, argv, ports, extra = {}) {
    const pid = this.nextPid++;
    this.procs.set(pid, { name, argv, ports, ...extra });
    return pid;
  }

  // Test setup helpers.
  addTrojan443() {
    return this.add('trojan', ['trojan', '-c', 'config.json'], [['tcp', 443], ['udp', 443]], { fromScript: true });
  }
  addForeign(name, port, proto = ['tcp', 'udp']) {
    return this.add(name, [name, '-s', '-p', String(port)], proto.map((p) => [p, port]));
  }
  listening(proto, port) {
    return [...this.procs.entries()].filter(([, p]) => p.ports.some(([x, y]) => x === proto && y === port)).map(([pid]) => pid);
  }
  count(prefix) {
    return this.calls.filter((c) => c.startsWith(prefix)).length;
  }

  async run(cmd, args, opts = {}) {
    const line = [cmd, ...args].join(' ');
    const ok = (stdout = '') => ({ code: 0, stdout, stderr: '' });
    if (cmd === 'ss') {
      this.calls.push(line);
      if (this.ssFails) return { code: 1, stdout: '', stderr: 'ss broke' };
      const rows = ['Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'];
      for (const [pid, p] of this.procs)
        for (const [proto, port] of p.ports)
          rows.push(`${proto} ${proto === 'tcp' ? 'LISTEN' : 'UNCONN'} 0 4096 0.0.0.0:${port} 0.0.0.0:* users:(("${p.name}",pid=${pid},fd=3))`);
      return ok(rows.join('\n'));
    }
    if (cmd === 'ps') {
      if (args.includes('-p')) return ok('Sun Nov 15 10:00:00 2026\n');
      return ok([...this.procs].map(([pid, p]) => `${pid} ${p.argv.join(' ')}`).join('\n'));
    }
    this.calls.push(line);
    if (cmd.endsWith('run_trojan-plus.sh')) {
      const verb = args[0];
      if (verb === 'stop' || verb === 'restart')
        for (const [pid, p] of [...this.procs]) if (p.fromScript) this.procs.delete(pid);
      if ((verb === 'start' || verb === 'restart') && !this.startFails && !this.listening('tcp', 443).length) this.addTrojan443();
      return ok();
    }
    if (args[0] === '-t') {
      return this.testFail ? { code: 1, stdout: '', stderr: 'config error: bad value (password=SECRETPASS)' } : ok('Configuration OK');
    }
    return { code: 127, stdout: '', stderr: 'unexpected command ' + line };
  }

  spawn(cmd, args, opts = {}) {
    this.calls.push([cmd, ...args].join(' '));
    const name = path.basename(cmd).slice(0, 15);
    let ports = [];
    if (name === 'iperf3') {
      const p = Number(args[args.indexOf('-p') + 1]);
      ports = [['tcp', p], ['udp', p]];
    } else if (name === 'trojan') {
      const conf = JSON.parse(fs.readFileSync(args[args.indexOf('-c') + 1], 'utf8'));
      ports = [['tcp', conf.local_port], ['udp', conf.local_port]];
    }
    const child = new EventEmitter();
    if (opts.pipe) child.stdout = new EventEmitter();
    child.pid = this.add(name, [cmd, ...args], ports, { child });
    return child;
  }

  emitDump(pid, text) {
    this.procs.get(pid)?.child.stdout.emit('data', text);
  }
  pidOf(name, argPart) {
    return [...this.procs].filter(([, p]) => p.name === name && (!argPart || p.argv.includes(argPart))).map(([pid]) => pid);
  }

  kill(pid, sig) {
    this.kills.push([pid, sig]);
    const p = this.procs.get(pid);
    if (!p) return;
    this.procs.delete(pid);
    p.child?.emit('exit', 0);
  }
  cmdline(pid) {
    return this.procs.get(pid)?.argv ?? null;
  }
}

module.exports = { FakeRunner };
