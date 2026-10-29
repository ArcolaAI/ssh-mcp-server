import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import ssh2 from 'ssh2';
const { Server, utils: sshUtils } = ssh2;
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';
import { CommandLineParser } from '../build/cli/command-line-parser.js';
import { parseJumpSpec } from '../build/utils/jump-host.js';

// Two REAL ssh2 servers on loopback: a jump host that forwards direct-tcpip
// channels to one allowed target only (as the aai-web PermitOpen does), and
// a target that runs exec. The manager under test connects to the target
// through the jump with real handshakes, so host-key verification, auth and
// forwarding are all exercised on the wire, not on a fake.

function mintHostKey() {
  for (let attempt = 0; attempt < 20; attempt++) {
    const pair = sshUtils.generateKeyPairSync('ed25519');
    const parsed = sshUtils.parseKey(pair.public);
    if (parsed instanceof Error) continue;
    return { private: pair.private, b64: parsed.getPublicSSH().toString('base64') };
  }
  throw new Error('mintHostKey: 20 unparseable keys in a row');
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

const PASSWORD = 'jump-test-password';

function acceptPassword(conn, onSession) {
  conn.on('authentication', (ctx) => {
    if (ctx.method === 'password' && ctx.password === PASSWORD) ctx.accept();
    else ctx.reject(['password']);
  });
  conn.on('ready', () => onSession?.(conn));
}

describe('jump host (one-hop ProxyJump) over real ssh2 servers', () => {
  const jumpKey = mintHostKey();
  const targetKey = mintHostKey();
  const impostorKey = mintHostKey();
  let jumpServer;
  let targetServer;
  let jumpPort;
  let targetPort;
  let refusedPort;
  const state = { jumpConnections: 0, jumpCloses: 0, forwards: [] };
  let manager;
  let originalSchedule;

  before(async () => {
    targetServer = new Server({ hostKeys: [targetKey.private] }, (conn) => {
      acceptPassword(conn, (c) => {
        c.on('session', (accept) => {
          const session = accept();
          session.on('exec', (acceptExec, _reject, info) => {
            const stream = acceptExec();
            stream.write(`target ran: ${info.command}\n`);
            stream.exit(0);
            stream.end();
          });
        });
      });
      conn.on('error', () => {});
    });
    targetPort = await listen(targetServer);

    // A listener that is not the allowed target: the jump refuses to forward
    // to it, the way PermitOpen refuses a hop to another node.
    const decoy = net.createServer((s) => s.destroy());
    refusedPort = await listen(decoy);
    decoy.close();

    jumpServer = new Server({ hostKeys: [jumpKey.private] }, (conn) => {
      state.jumpConnections += 1;
      conn.on('close', () => { state.jumpCloses += 1; });
      conn.on('error', () => {});
      acceptPassword(conn, (c) => {
        c.on('tcpip', (accept, reject, info) => {
          state.forwards.push(`${info.destIP}:${info.destPort}`);
          if (info.destIP !== '127.0.0.1' || info.destPort !== targetPort) {
            reject();
            return;
          }
          const channel = accept();
          const upstream = net.connect(targetPort, '127.0.0.1');
          channel.pipe(upstream).pipe(channel);
          upstream.on('error', () => channel.destroy());
          channel.on('close', () => upstream.destroy());
        });
        c.on('session', (_accept, reject) => reject());
      });
    });
    jumpPort = await listen(jumpServer);

    manager = SSHConnectionManager.getInstance();
    originalSchedule = manager.scheduleStatusCollection;
    manager.scheduleStatusCollection = () => {};
  });

  after(() => {
    manager.disconnect();
    manager.scheduleStatusCollection = originalSchedule;
    jumpServer.close();
    targetServer.close();
  });

  afterEach(() => {
    manager.disconnect();
  });

  function knownHosts(lines) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-jump-'));
    const file = path.join(dir, 'known_hosts');
    fs.writeFileSync(file, lines.join('\n') + '\n');
    return file;
  }

  function goodKnownHosts() {
    return knownHosts([
      `[127.0.0.1]:${jumpPort} ssh-ed25519 ${jumpKey.b64}`,
      `[127.0.0.1]:${targetPort} ssh-ed25519 ${targetKey.b64}`,
    ]);
  }

  function configure(overrides) {
    manager.setConfig({
      node: {
        name: 'node',
        host: '127.0.0.1',
        port: targetPort,
        username: 'deploy',
        password: PASSWORD,
        jump: `deploy@127.0.0.1:${jumpPort}`,
        connectionTimeoutMs: 5000,
        pty: false,
        ...overrides,
      },
    });
  }

  async function waitFor(predicate, ms = 3000) {
    const deadline = Date.now() + ms;
    while (!predicate()) {
      if (Date.now() > deadline) return false;
      await new Promise((r) => setTimeout(r, 20));
    }
    return true;
  }

  it('POSITIVE CONTROL: runs a command on the target through the jump host', async () => {
    configure({ knownHostsFile: goodKnownHosts() });
    const before = state.jumpConnections;
    const output = await manager.executeCommand('hostname', undefined, 'node');
    assert.match(output, /target ran: hostname/);
    assert.strictEqual(state.jumpConnections, before + 1, 'the target was reached via the jump');
    assert.strictEqual(state.forwards.at(-1), `127.0.0.1:${targetPort}`);
  });

  it('the jump connection is closed when the target connection is', async () => {
    configure({ knownHostsFile: goodKnownHosts() });
    const closesBefore = state.jumpCloses;
    await manager.executeCommand('hostname', undefined, 'node');
    manager.disconnect();
    assert.ok(await waitFor(() => state.jumpCloses > closesBefore), 'jump connection left open after disconnect');
  });

  it('NEGATIVE CONTROL: a wrong JUMP host key is refused before any forward is asked for', async () => {
    const forwardsBefore = state.forwards.length;
    configure({
      knownHostsFile: knownHosts([
        `[127.0.0.1]:${jumpPort} ssh-ed25519 ${impostorKey.b64}`,
        `[127.0.0.1]:${targetPort} ssh-ed25519 ${targetKey.b64}`,
      ]),
    });
    await assert.rejects(manager.connect('node'), (err) => {
      assert.strictEqual(err.code, 'HOST_KEY_REJECTED');
      assert.match(err.message, /at jump host 127\.0\.0\.1:\d+/);
      return true;
    });
    assert.strictEqual(state.forwards.length, forwardsBefore);
  });

  it('a jump host with no known_hosts entry is refused (fail-closed)', async () => {
    configure({ knownHostsFile: knownHosts([`[127.0.0.1]:${targetPort} ssh-ed25519 ${targetKey.b64}`]) });
    await assert.rejects(manager.connect('node'), (err) => err.code === 'HOST_KEY_UNVERIFIABLE');
  });

  it('NEGATIVE CONTROL: a wrong TARGET host key is refused even though the jump is trusted', async () => {
    configure({
      knownHostsFile: knownHosts([
        `[127.0.0.1]:${jumpPort} ssh-ed25519 ${jumpKey.b64}`,
        `[127.0.0.1]:${targetPort} ssh-ed25519 ${impostorKey.b64}`,
      ]),
    });
    await assert.rejects(manager.connect('node'), (err) => {
      assert.strictEqual(err.code, 'HOST_KEY_REJECTED');
      assert.doesNotMatch(err.message, /jump host/);
      return true;
    });
  });

  it('a target the jump host will not forward to is refused and named', async () => {
    configure({
      port: refusedPort,
      knownHostsFile: knownHosts([
        `[127.0.0.1]:${jumpPort} ssh-ed25519 ${jumpKey.b64}`,
        `[127.0.0.1]:${refusedPort} ssh-ed25519 ${targetKey.b64}`,
      ]),
    });
    await assert.rejects(manager.connect('node'), (err) => {
      assert.match(err.message, /would not forward to 127\.0\.0\.1:\d+/);
      return true;
    });
  });
});

describe('parseJumpSpec', () => {
  it('reads user@host:port, defaults the user and port', () => {
    assert.deepStrictEqual(parseJumpSpec('ops@10.0.1.1:2222', 'deploy'), { username: 'ops', host: '10.0.1.1', port: 2222 });
    assert.deepStrictEqual(parseJumpSpec('10.0.1.1', 'deploy'), { username: 'deploy', host: '10.0.1.1', port: 22 });
    assert.deepStrictEqual(parseJumpSpec('[2001:db8::1]:22', 'deploy'), { username: 'deploy', host: '2001:db8::1', port: 22 });
  });

  it('refuses a chain, a bare IPv6 literal, an empty host and a bad port', () => {
    assert.throws(() => parseJumpSpec('a@h1,b@h2', 'deploy'), /chain/);
    assert.throws(() => parseJumpSpec('2001:db8::1', 'deploy'), /IPv6/);
    assert.throws(() => parseJumpSpec('deploy@', 'deploy'), /empty host/);
    assert.throws(() => parseJumpSpec('h:99999', 'deploy'), /invalid port/);
    assert.throws(() => parseJumpSpec('h:x', 'deploy'), /invalid port/);
  });
});

describe('CommandLineParser jump option', () => {
  it('reads jump from a JSON config file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-jump-cfg-'));
    const file = path.join(dir, 'config.json');
    fs.writeFileSync(file, JSON.stringify([{ name: 'pii', host: '10.0.1.6', port: 22, username: 'deploy', password: 'x', jump: ' deploy@157.90.229.39 ' }]));
    const saved = process.argv;
    process.argv = ['node', 'index.js', '--config-file', file];
    try {
      const parsed = CommandLineParser.parseArgs();
      assert.strictEqual(parsed.configs.pii.jump, 'deploy@157.90.229.39');
    } finally {
      process.argv = saved;
    }
  });
});
