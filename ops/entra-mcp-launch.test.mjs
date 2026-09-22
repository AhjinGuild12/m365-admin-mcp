import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  DENYLIST,
  LaunchError,
  buildChildEnv,
  computeIntegrityManifest,
  readEnvFile,
  resolveAccountHome,
  resolveDefaultConfigDir,
  runLauncher,
  validateCredentials,
} from './entra-mcp-launch-core.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function chmod(p, mode) {
  fs.chmodSync(p, mode);
}

function writeFile(p, content, mode = 0o600) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  chmod(p, mode);
}

function futureExpiry(days = 60) {
  return new Date(Date.now() + days * 86400 * 1000).toISOString();
}

function validEnv(overrides = {}) {
  return {
    ENTRA_TENANT_ID: 'tenant-id',
    ENTRA_CLIENT_ID: 'client-id',
    ENTRA_CLIENT_SECRET: 'super-secret-value-not-for-logs',
    ENTRA_SECRET_EXPIRES: futureExpiry(60),
    ...overrides,
  };
}

function envText(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${k}=${v}`)
    .join('\n') + '\n';
}

function makeWorkspace() {
  const root = tmpDir('entra-ws-');
  writeFile(path.join(root, 'tools', 'entra-mcp-server', 'src', 'entra_mcp', 'server.py'), 'print(1)\n', 0o644);
  writeFile(path.join(root, 'tools', 'entra-mcp-server', 'pyproject.toml'), '[project]\nname="entra-mcp"\n', 0o644);
  writeFile(path.join(root, 'tools', 'entra-mcp-server', 'uv.lock'), 'version = 1\n', 0o644);
  writeFile(path.join(root, 'tools', 'entra-mcp-server', '.venv', 'pyvenv.cfg'), 'home = /usr\n', 0o644);
  const python = path.join(root, 'tools', 'entra-mcp-server', '.venv', 'bin', 'python');
  writeFile(python, '#!/bin/sh\n', 0o755);
  writeFile(path.join(root, 'tools', 'entra-mcp-launch.mjs'), fs.readFileSync(path.join(HERE, 'entra-mcp-launch.mjs')));
  writeFile(path.join(root, 'tools', 'entra-mcp-launch-core.mjs'), fs.readFileSync(path.join(HERE, 'entra-mcp-launch-core.mjs')));
  return root;
}

function makeConfig(workspace, { env = validEnv(), envMode = 0o600, parentMode = 0o700, baselineMode = 0o600, baseline } = {}) {
  const configDir = tmpDir('entra-cfg-');
  chmod(configDir, parentMode);
  const baselineDir = path.join(configDir, 'baseline');
  fs.mkdirSync(baselineDir, { mode: 0o700 });
  chmod(baselineDir, 0o700);
  if (env) {
    writeFile(path.join(configDir, 'entra-mcp.env'), envText(env), envMode);
  }
  const manifest = baseline || computeIntegrityManifest(workspace);
  writeFile(path.join(baselineDir, 'active.json'), JSON.stringify(manifest), baselineMode);
  return configDir;
}

function captureStderr(fn) {
  const chunks = [];
  const orig = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => {
    chunks.push(String(chunk));
    return orig.call(process.stderr, chunk, ...rest);
  };
  try {
    return { result: fn(), stderr: chunks.join('') };
  } catch (err) {
    return { error: err, stderr: chunks.join('') };
  } finally {
    process.stderr.write = orig;
  }
}

function stubSpawn() {
  const spawned = [];
  function spawnImpl(cmd, args, opts) {
    spawned.push({ cmd, args, opts });
    return {
      on() {},
    };
  }
  return { spawnImpl, spawned };
}

test('missing env file refuses without spawn', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { env: null });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /missing env file/);
  assert.equal(spawned.length, 0);
});

test('env file mode 644 is refused and observed mode printed', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { envMode: 0o644 });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /mode is 644/);
  assert.equal(spawned.length, 0);
});

test('parent directory mode 755 is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { parentMode: 0o755 });
  const { spawnImpl, spawned } = stubSpawn();
  const { error } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.equal(error instanceof LaunchError, true);
  assert.match(String(error.message), /parent/);
  assert.equal(spawned.length, 0);
});

test('env path symlink is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  const real = path.join(configDir, 'entra-mcp.env');
  const backup = real + '.real';
  fs.renameSync(real, backup);
  fs.symlinkSync(backup, real);
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /symlink/);
  assert.equal(spawned.length, 0);
});

test('parent symlink is refused', () => {
  const ws = makeWorkspace();
  const real = makeConfig(ws);
  const parent = tmpDir('entra-link-parent-');
  const configDir = path.join(parent, 'cfg');
  fs.symlinkSync(real, configDir);
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /symlink/);
  assert.equal(spawned.length, 0);
});

test('FIFO at env path is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  const envPath = path.join(configDir, 'entra-mcp.env');
  fs.rmSync(envPath);
  execFileSync('mkfifo', ['-m', '600', envPath]);
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => {
    try {
      readEnvFile(configDir);
    } catch (err) {
      throw err;
    }
  });
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /not a regular file|FIFO|cannot open/i);
  assert.equal(spawned.length, 0);
});

test('config-dir resolver ignores HOME', () => {
  const fixtureHome = tmpDir('fake-home-');
  fs.mkdirSync(path.join(fixtureHome, '.config', 'entra-mcp'), { recursive: true });
  writeFile(path.join(fixtureHome, '.config', 'entra-mcp', 'entra-mcp.env'), envText(validEnv()));
  const prev = process.env.HOME;
  process.env.HOME = fixtureHome;
  try {
    const resolved = resolveDefaultConfigDir();
    const account = resolveAccountHome();
    assert.equal(resolved, path.join(account, '.config', 'entra-mcp'));
    assert.notEqual(resolved, path.join(fixtureHome, '.config', 'entra-mcp'));
  } finally {
    process.env.HOME = prev;
  }
});

test('missing active baseline refuses before env open', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  fs.rmSync(path.join(configDir, 'baseline', 'active.json'));
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.match(stderr, /missing active baseline/);
  assert.equal(error instanceof LaunchError, true);
  assert.equal(spawned.length, 0);
});

test('active baseline mode 644 is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { baselineMode: 0o644 });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.match(stderr, /baseline/);
  assert.equal(error instanceof LaunchError, true);
  assert.equal(spawned.length, 0);
});

test('child environment equals allowlist and drops denylist', () => {
  const fileEnv = validEnv({
    HTTP_PROXY: 'http://evil',
    AZURE_CLIENT_SECRET: 'nope',
    SSLKEYLOGFILE: '/tmp/keys',
  });
  const parent = {
    AZURE_CLIENT_ID: 'parent-azure',
    HTTP_PROXY: 'http://parent',
    HTTPS_PROXY: 'https://parent',
    SSLKEYLOGFILE: '/tmp/parent-keys',
    SSL_CERT_FILE: '/tmp/ca.pem',
    REQUESTS_CA_BUNDLE: '/tmp/req.pem',
    LANG: 'en_US.UTF-8',
    LC_ALL: 'C',
    PATH: '/evil/bin',
    HOME: '/tmp/fake',
  };
  const child = buildChildEnv(fileEnv, parent);
  assert.deepEqual(Object.keys(child).sort(), [
    'ENTRA_CLIENT_ID',
    'ENTRA_CLIENT_SECRET',
    'ENTRA_SECRET_EXPIRES',
    'ENTRA_TENANT_ID',
    'LANG',
    'LC_ALL',
    'PATH',
  ].sort());
  for (const name of DENYLIST) {
    assert.equal(Object.hasOwn(child, name), false, name);
  }
  assert.equal(child.PATH, '/usr/bin:/bin:/usr/sbin:/sbin');
  assert.equal(child.LANG, 'en_US.UTF-8');
});

test('missing required vars refused', () => {
  for (const key of ['ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID', 'ENTRA_CLIENT_SECRET', 'ENTRA_SECRET_EXPIRES']) {
    const env = validEnv();
    delete env[key];
    const { error } = captureStderr(() => validateCredentials(env));
    assert.equal(error instanceof LaunchError, true);
    assert.match(error.message, /missing/);
  }
});

test('cert path without secret is refused', () => {
  const env = validEnv();
  delete env.ENTRA_CLIENT_SECRET;
  env.ENTRA_CLIENT_CERTIFICATE_PATH = '/tmp/cert.pem';
  const { error, stderr } = captureStderr(() => validateCredentials(env));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /certificate path does not satisfy/);
});

test('malformed and past expiry refused; 14-day warning', () => {
  const { error: bad } = captureStderr(() =>
    validateCredentials(validEnv({ ENTRA_SECRET_EXPIRES: 'not-a-date' }))
  );
  assert.match(bad.message, /malformed/);
  const { error: past } = captureStderr(() =>
    validateCredentials(validEnv({ ENTRA_SECRET_EXPIRES: '2000-01-01T00:00:00Z' }))
  );
  assert.match(past.message, /past expiry|at or past/);
  const warn = validateCredentials(validEnv({ ENTRA_SECRET_EXPIRES: futureExpiry(7) }));
  assert.equal(warn.warn, true);
});

test('source hash mismatch refuses with no spawn', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  fs.appendFileSync(path.join(ws, 'tools', 'entra-mcp-server', 'src', 'entra_mcp', 'server.py'), '# drift\n');
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.match(stderr, /integrity mismatch/);
  assert.equal(error instanceof LaunchError, true);
  assert.equal(spawned.length, 0);
});

test('happy path fixture env spawns isolated python -I -B -m entra_mcp', () => {
  const ws = makeWorkspace();
  const secret = 'super-secret-value-not-for-logs';
  const configDir = makeConfig(ws, { env: validEnv({ ENTRA_CLIENT_SECRET: secret }) });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.equal(error, undefined);
  assert.equal(spawned.length, 1);
  assert.equal(path.basename(spawned[0].cmd), 'python');
  assert.deepEqual(spawned[0].args, ['-I', '-B', '-m', 'entra_mcp']);
  assert.equal(spawned[0].opts.stdio, 'inherit');
  assert.equal(spawned[0].opts.env.ENTRA_CLIENT_SECRET, secret);
  assert.equal(stderr.includes(secret), false);
});

test('CLI source never reads argv or env', () => {
  const src = fs.readFileSync(path.join(HERE, 'entra-mcp-launch.mjs'), 'utf8');
  assert.equal(/process\.argv/.test(src), false);
  assert.equal(/process\.env/.test(src), false);
});

test('expiry within 14 days starts with stderr warning', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { env: validEnv({ ENTRA_SECRET_EXPIRES: futureExpiry(7) }) });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() =>
    runLauncher({ configDir, workspaceRoot: ws, spawnImpl, wait: false })
  );
  assert.equal(error, undefined);
  assert.equal(spawned.length, 1);
  assert.match(stderr, /within 14 days/);
});

test('directory at env path is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  const envPath = path.join(configDir, 'entra-mcp.env');
  fs.rmSync(envPath);
  fs.mkdirSync(envPath, { mode: 0o700 });
  const { error, stderr } = captureStderr(() => readEnvFile(configDir));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /not a regular file|EISDIR|cannot open/i);
});

test('foreign uid refused or skipped-with-reason', { skip: process.getuid() !== 0 ? 'not root; cannot chown fixture' : false }, () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  fs.chownSync(path.join(configDir, 'entra-mcp.env'), 1, 1);
  const { error, stderr } = captureStderr(() => readEnvFile(configDir));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /owner/);
});

test('happy path fixture env completes MCP initialize over stdio', async () => {
  const workspaceRoot = path.resolve(HERE, '..');
  const python = path.join(workspaceRoot, 'tools', 'entra-mcp-server', '.venv', 'bin', 'python');
  if (!fs.existsSync(python)) {
    throw new Error('missing venv python; U2 editable install required');
  }
  const secret = 'super-secret-value-not-for-logs';
  const configDir = makeConfig(workspaceRoot, { env: validEnv({ ENTRA_CLIENT_SECRET: secret }) });
  let child;
  const { error, stderr: launchErr } = captureStderr(() => {
    child = runLauncher({
      configDir,
      workspaceRoot,
      wait: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  });
  assert.equal(error, undefined, launchErr);
  assert.ok(child);
  const stdoutChunks = [];
  const stderrChunks = [];
  child.stdout.on('data', (d) => stdoutChunks.push(d));
  child.stderr.on('data', (d) => stderrChunks.push(d));
  const init = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'entra-u3', version: '0.1' },
    },
  };
  child.stdin.write(JSON.stringify(init) + '\n');
  const line = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('initialize timeout')), 8000);
    child.stdout.once('data', (d) => {
      clearTimeout(t);
      resolve(String(d));
    });
  });
  child.kill('SIGTERM');
  const msg = JSON.parse(line.split('\n')[0]);
  assert.equal(msg.id, 1);
  const name = msg.result?.serverInfo?.name || msg.result?.server_info?.name;
  assert.equal(name, 'entra-ro');
  const out = stdoutChunks.join('') + stderrChunks.join('') + launchErr;
  assert.equal(out.includes(secret), false);
});
