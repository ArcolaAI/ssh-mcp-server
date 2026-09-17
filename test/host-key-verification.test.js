import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { createHmac, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import ssh2 from 'ssh2';
const { utils: sshUtils } = ssh2;
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';
import { CommandLineParser } from '../build/cli/command-line-parser.js';
import {
  parseKnownHosts,
  findHostEntries,
  verifyOfferedKey,
  serverHostKeyAlgorithmsFor,
  knownHostsLookupName,
} from '../build/utils/known-hosts.js';

// Real keys, real wire blobs: what ssh2 hands to hostVerifier during KEX is
// exactly the base64 payload of a known_hosts line, so the fixtures below are
// byte-faithful to a live handshake.
function mintKey(type = 'ed25519') {
  const pair = sshUtils.generateKeyPairSync(type, type === 'rsa' ? { bits: 2048 } : undefined);
  const parsed = sshUtils.parseKey(pair.public);
  return { type: parsed.type, blob: parsed.getPublicSSH(), b64: parsed.getPublicSSH().toString('base64') };
}

function hashedHost(name) {
  const salt = randomBytes(20);
  const mac = createHmac('sha1', salt).update(name).digest();
  return `|1|${salt.toString('base64')}|${mac.toString('base64')}`;
}

function writeKnownHosts(lines) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-known-hosts-'));
  const file = path.join(dir, 'known_hosts');
  fs.writeFileSync(file, lines.join('\n') + '\n');
  return file;
}

/**
 * Fake ssh2 client that behaves the way ssh2 does at the host-key step: if a
 * hostVerifier is configured it is called with the offered wire blob and a
 * false verdict produces the generic "Host denied" error; otherwise the
 * connection proceeds to ready.
 */
class HostKeyFakeClient extends EventEmitter {
  constructor(offeredBlob) {
    super();
    this.offeredBlob = offeredBlob;
    this.connectCalls = [];
    this.verifierCalls = 0;
  }

  connect(config) {
    this.connectCalls.push(config);
    queueMicrotask(() => {
      if (typeof config.hostVerifier === 'function') {
        this.verifierCalls += 1;
        const verdict = config.hostVerifier(this.offeredBlob);
        if (verdict !== true) {
          this.emit('error', new Error('Host denied (verification failed)'));
          return;
        }
      }
      this.emit('ready');
    });
  }

  exec(command, optionsOrCallback, maybeCallback) {
    const callback = typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;
    callback(new Error('exec not modelled in this fake'));
  }

  end() {
    this.emit('close');
  }

  destroy() {
    this.emit('close');
  }
}

describe('known_hosts parsing and matching', () => {
  const good = mintKey('ed25519');
  const rsa = mintKey('rsa');

  it('parses plain, bracketed-port, comma-separated, hashed, revoked and cert-authority lines', () => {
    const entries = parseKnownHosts([
      '# comment',
      '',
      `10.0.0.1 ssh-ed25519 ${good.b64} node-a`,
      `[10.0.0.2]:2222 ssh-rsa ${rsa.b64}`,
      `alpha.example,10.0.0.3 ssh-ed25519 ${good.b64}`,
      `${hashedHost('10.0.0.4')} ssh-ed25519 ${good.b64}`,
      `@revoked 10.0.0.5 ssh-ed25519 ${good.b64}`,
      `@cert-authority *.example ssh-rsa ${rsa.b64}`,
      'garbage line with two fields',
      `10.0.0.6 ssh-rsa ${good.b64}`, // declared type disagrees with the blob - unusable
    ].join('\n'));
    assert.strictEqual(entries.length, 6);
    assert.deepStrictEqual(entries.map((e) => e.lineNumber), [3, 4, 5, 6, 7, 8]);
    assert.strictEqual(entries[4].marker, 'revoked');
    assert.strictEqual(entries[5].marker, 'cert-authority');
  });

  it('looks up bare host on port 22 and [host]:port otherwise', () => {
    assert.strictEqual(knownHostsLookupName('10.0.0.1', 22), '10.0.0.1');
    assert.strictEqual(knownHostsLookupName('10.0.0.1', 2222), '[10.0.0.1]:2222');
    const entries = parseKnownHosts(`[10.0.0.2]:2222 ssh-rsa ${rsa.b64}\n10.0.0.2 ssh-ed25519 ${good.b64}\n`);
    assert.strictEqual(findHostEntries(entries, '10.0.0.2', 2222).length, 1);
    assert.strictEqual(findHostEntries(entries, '10.0.0.2', 2222)[0].keyType, 'ssh-rsa');
    assert.strictEqual(findHostEntries(entries, '10.0.0.2', 22)[0].keyType, 'ssh-ed25519');
  });

  it('matches hashed hostnames, wildcards and honours negation', () => {
    const entries = parseKnownHosts([
      `${hashedHost('node.internal')} ssh-ed25519 ${good.b64}`,
      `*.example,!bad.example ssh-ed25519 ${good.b64}`,
    ].join('\n'));
    assert.strictEqual(findHostEntries(entries, 'node.internal', 22).length, 1);
    assert.strictEqual(findHostEntries(entries, 'other.internal', 22).length, 0);
    assert.strictEqual(findHostEntries(entries, 'good.example', 22).length, 1);
    assert.strictEqual(findHostEntries(entries, 'bad.example', 22).length, 0);
  });

  it('verifies a matching key, refuses a wrong key of the same type, and refuses a revoked key', () => {
    const wrong = mintKey('ed25519');
    const ok = parseKnownHosts(`h ssh-ed25519 ${good.b64}\n`);
    assert.strictEqual(verifyOfferedKey(ok, good.blob).ok, true);
    const mismatch = verifyOfferedKey(ok, wrong.blob);
    assert.strictEqual(mismatch.ok, false);
    assert.strictEqual(mismatch.reason, 'mismatch');
    assert.match(mismatch.detail, /HOST KEY HAS CHANGED OR THE HOST IS BEING IMPERSONATED/);
    const revoked = parseKnownHosts(`@revoked h ssh-ed25519 ${good.b64}\nh ssh-ed25519 ${good.b64}\n`);
    const verdict = verifyOfferedKey(revoked, good.blob);
    assert.strictEqual(verdict.ok, false);
    assert.strictEqual(verdict.reason, 'revoked');
  });

  it('reports a type the file does not hold, and treats cert-authority-only as unknown', () => {
    const onlyRsa = parseKnownHosts(`h ssh-rsa ${rsa.b64}\n`);
    const verdict = verifyOfferedKey(onlyRsa, good.blob);
    assert.strictEqual(verdict.ok, false);
    assert.match(verdict.detail, /known_hosts holds only \[ssh-rsa\]/);
    const caOnly = parseKnownHosts(`@cert-authority h ssh-rsa ${rsa.b64}\n`);
    assert.strictEqual(verifyOfferedKey(caOnly, good.blob).reason, 'unknown-host');
  });

  it('restricts serverHostKey algorithms to the known types, most preferred first', () => {
    const entries = parseKnownHosts(`h ssh-rsa ${rsa.b64}\nh ssh-ed25519 ${good.b64}\n`);
    assert.deepStrictEqual(serverHostKeyAlgorithmsFor(entries), [
      'ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa',
    ]);
    assert.deepStrictEqual(serverHostKeyAlgorithmsFor(parseKnownHosts(`h ssh-rsa ${rsa.b64}\n`)), [
      'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa',
    ]);
  });
});

describe('SSHConnectionManager host-key verification (fail-closed)', () => {
  const HOST = '198.51.100.10';
  const good = mintKey('ed25519');
  const wrong = mintKey('ed25519');
  let manager;
  let originalCreateClient;
  let originalScheduleStatusCollection;
  let originalHome;

  before(() => {
    manager = SSHConnectionManager.getInstance();
    originalCreateClient = manager.createClient;
    originalScheduleStatusCollection = manager.scheduleStatusCollection;
    originalHome = process.env.HOME;
  });

  afterEach(() => {
    manager.disconnect();
    manager.createClient = originalCreateClient;
    manager.scheduleStatusCollection = originalScheduleStatusCollection;
  });

  function arm(offeredBlob, config) {
    const client = new HostKeyFakeClient(offeredBlob);
    manager.createClient = () => client;
    manager.scheduleStatusCollection = () => {};
    manager.setConfig({ node: { name: 'node', host: HOST, port: 22, username: 'deploy', password: 'x', ...config } });
    return client;
  }

  it('POSITIVE CONTROL: connects when the offered key matches known_hosts', async () => {
    const knownHostsFile = writeKnownHosts([`${HOST} ssh-ed25519 ${good.b64}`]);
    const client = arm(good.blob, { knownHostsFile });
    await manager.connect('node');
    assert.strictEqual(client.verifierCalls, 1);
    assert.strictEqual(client.connectCalls[0].algorithms.serverHostKey[0], 'ssh-ed25519');
    assert.ok(manager.getClient('node'));
  });

  it('NEGATIVE CONTROL: a wrong key for a known host is REFUSED and the connection never becomes ready', async () => {
    const knownHostsFile = writeKnownHosts([`${HOST} ssh-ed25519 ${good.b64}`]);
    const client = arm(wrong.blob, { knownHostsFile });
    await assert.rejects(manager.connect('node'), (err) => {
      assert.strictEqual(err.code, 'HOST_KEY_REJECTED');
      assert.match(err.message, /REJECTED \(mismatch\)/);
      assert.match(err.message, new RegExp(HOST.replace(/\./g, '\\.')));
      return true;
    });
    assert.strictEqual(client.verifierCalls, 1);
    assert.throws(() => manager.getClient('node'), /not connected/);
  });

  it('an unknown host is refused BEFORE the socket opens', async () => {
    const knownHostsFile = writeKnownHosts([`203.0.113.9 ssh-ed25519 ${good.b64}`]);
    const client = arm(good.blob, { knownHostsFile });
    await assert.rejects(manager.connect('node'), (err) => {
      assert.strictEqual(err.code, 'HOST_KEY_UNVERIFIABLE');
      assert.match(err.message, /has no entry in/);
      assert.match(err.message, /never adds host keys itself/);
      return true;
    });
    assert.strictEqual(client.connectCalls.length, 0);
    assert.strictEqual(client.verifierCalls, 0);
  });

  it('a missing known_hosts file is refused (fail-closed), not treated as empty', async () => {
    const knownHostsFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-nokh-')), 'absent');
    const client = arm(good.blob, { knownHostsFile });
    await assert.rejects(manager.connect('node'), (err) => {
      assert.strictEqual(err.code, 'HOST_KEY_UNVERIFIABLE');
      assert.match(err.message, /cannot read known_hosts/);
      return true;
    });
    assert.strictEqual(client.connectCalls.length, 0);
  });

  it('a @revoked key is refused even when a matching plain entry also exists', async () => {
    const knownHostsFile = writeKnownHosts([
      `@revoked ${HOST} ssh-ed25519 ${good.b64}`,
      `${HOST} ssh-ed25519 ${good.b64}`,
    ]);
    arm(good.blob, { knownHostsFile });
    await assert.rejects(manager.connect('node'), (err) => {
      assert.strictEqual(err.code, 'HOST_KEY_REJECTED');
      assert.match(err.message, /REJECTED \(revoked\)/);
      return true;
    });
  });

  it('a key of a type the file does not hold is refused, naming the known types', async () => {
    const rsa = mintKey('rsa');
    const knownHostsFile = writeKnownHosts([`${HOST} ssh-rsa ${rsa.b64}`]);
    const client = arm(good.blob, { knownHostsFile });
    await assert.rejects(manager.connect('node'), (err) => {
      assert.match(err.message, /known_hosts holds only \[ssh-rsa\]/);
      return true;
    });
    // and the negotiation was restricted so a real server could not have offered it
    assert.deepStrictEqual(client.connectCalls[0].algorithms.serverHostKey, ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa']);
  });

  it('an explicit algorithms.serverHostKey from config is left alone', async () => {
    const knownHostsFile = writeKnownHosts([`${HOST} ssh-ed25519 ${good.b64}`]);
    const client = arm(good.blob, { knownHostsFile, algorithms: { serverHostKey: ['ssh-ed25519', 'ssh-rsa'] } });
    await manager.connect('node');
    assert.deepStrictEqual(client.connectCalls[0].algorithms.serverHostKey, ['ssh-ed25519', 'ssh-rsa']);
  });

  it('hostKeyVerification "off" installs no verifier and accepts any key', async () => {
    const client = arm(wrong.blob, { hostKeyVerification: 'off' });
    await manager.connect('node');
    assert.strictEqual(client.connectCalls[0].hostVerifier, undefined);
    assert.strictEqual(client.verifierCalls, 0);
    assert.ok(manager.getClient('node'));
  });

  it('DEFAULT is verification ON: a config with no hostKeyVerification field is checked against ~/.ssh/known_hosts', async () => {
    // Point HOME at a temp dir whose known_hosts does not know the host: the
    // default path must be consulted and the connect refused there.
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-home-'));
    fs.mkdirSync(path.join(home, '.ssh'));
    fs.writeFileSync(path.join(home, '.ssh', 'known_hosts'), `203.0.113.9 ssh-ed25519 ${good.b64}\n`);
    const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    try {
      const client = arm(good.blob, {});
      await assert.rejects(manager.connect('node'), (err) => {
        assert.strictEqual(err.code, 'HOST_KEY_UNVERIFIABLE');
        assert.match(err.message, new RegExp(path.join(home, '.ssh', 'known_hosts').replace(/[\\.]/g, '\\$&')));
        return true;
      });
      assert.strictEqual(client.connectCalls.length, 0);
    } finally {
      process.env.HOME = saved.HOME;
      process.env.USERPROFILE = saved.USERPROFILE;
    }
  });
});

describe('CommandLineParser host-key options', () => {
  const base = ['--host', '10.0.0.1', '--username', 'u', '--password', 'p'];
  const originalArgv = process.argv;
  const parse = (args) => {
    process.argv = ['node', 'test', ...args];
    try {
      return CommandLineParser.parseArgs();
    } finally {
      process.argv = originalArgv;
    }
  };

  it('defaults to known_hosts when the flag is absent', () => {
    const { configs } = parse(base);
    assert.strictEqual(configs.default.hostKeyVerification, 'known_hosts');
    assert.strictEqual(configs.default.knownHostsFile, undefined);
  });

  it('accepts --host-key-verification off and --known-hosts-file', () => {
    const { configs } = parse([...base, '--host-key-verification', 'off', '--known-hosts-file', '/tmp/kh']);
    assert.strictEqual(configs.default.hostKeyVerification, 'off');
    assert.ok(configs.default.knownHostsFile.endsWith('kh'));
  });

  it('rejects any other value rather than silently disabling', () => {
    assert.throws(() => parse([...base, '--host-key-verification', 'no']), /must be "known_hosts" or "off"/);
  });

  it('reads both fields from a JSON config file and defaults to known_hosts there too', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-mcp-cfg-'));
    const file = path.join(dir, 'c.json');
    fs.writeFileSync(file, JSON.stringify({
      a: { host: '10.0.0.1', port: 22, username: 'u', password: 'p' },
      b: { host: '10.0.0.2', port: 22, username: 'u', password: 'p', hostKeyVerification: 'off' },
    }));
    const { configs } = parse(['--config-file', file]);
    assert.strictEqual(configs.a.hostKeyVerification, 'known_hosts');
    assert.strictEqual(configs.b.hostKeyVerification, 'off');
  });
});
