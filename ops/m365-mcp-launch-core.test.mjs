import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  BASE_DENYLIST,
  LaunchError,
  buildChildEnv,
  computeIntegrityManifest,
  prefixEnvNames,
  readEnvFile,
  resolveAccountHome,
  resolveDefaultConfigDir,
  runLauncher,
  validateCredentials,
} from './m365-mcp-launch-core.mjs';

import {
  applySharedConfirm,
  compareEntraProtected,
  defaultHygieneSurfaces,
  planSharedRelease,
  scanHygiene,
  snapshotEntraProtected,
} from './m365-mcp-gate-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

const DESC = {
  envPrefix: 'INTUNE',
  envFileName: 'intune-mcp.env',
  packageDir: 'tools/intune-mcp-server',
  kernelPackageDir: 'tools/m365-mcp-kernel',
  moduleName: 'intune_mcp',
  launchCliRel: 'tools/intune-mcp-launch.mjs',
  launchCoreRel: 'tools/m365-mcp-launch-core.mjs',
  gateRel: 'tools/intune-mcp-gate.mjs',
  gateLibRel: 'tools/m365-mcp-gate-lib.mjs',
  otherPrefixes: ['SPO_ADMIN', 'TEAMS_ADMIN', 'EXO'],
  stderrName: 'intune-mcp-launch',
};

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
    INTUNE_TENANT_ID: 'tenant-id',
    INTUNE_CLIENT_ID: 'client-id',
    INTUNE_CLIENT_SECRET: 'super-secret-value-not-for-logs',
    INTUNE_SECRET_EXPIRES: futureExpiry(60),
    INTUNE_CLIENT_CERTIFICATE_PATH: '',
    ...overrides,
  };
}

function envText(obj) {
  return (
    Object.entries(obj)
      .map(([k, v]) => `${k}=${v}`)
      .join('\n') + '\n'
  );
}

function makeWorkspace() {
  const root = tmpDir('m365-ws-');
  writeFile(
    path.join(root, 'tools', 'intune-mcp-server', 'src', 'intune_mcp', 'server.py'),
    'print(1)\n',
    0o644
  );
  writeFile(
    path.join(root, 'tools', 'intune-mcp-server', 'pyproject.toml'),
    '[project]\nname="intune-mcp"\n',
    0o644
  );
  writeFile(path.join(root, 'tools', 'intune-mcp-server', 'uv.lock'), 'version = 1\n', 0o644);
  writeFile(path.join(root, 'tools', 'intune-mcp-server', '.venv', 'pyvenv.cfg'), 'home = /usr\n', 0o644);
  const python = path.join(root, 'tools', 'intune-mcp-server', '.venv', 'bin', 'python');
  writeFile(python, '#!/bin/sh\n', 0o755);
  writeFile(
    path.join(root, 'tools', 'm365-mcp-kernel', 'src', 'm365_mcp_kernel', 'graph_client.py'),
    'x=1\n',
    0o644
  );
  writeFile(
    path.join(root, 'tools', 'm365-mcp-kernel', 'pyproject.toml'),
    '[project]\nname="m365-mcp-kernel"\n',
    0o644
  );
  writeFile(path.join(root, 'tools', 'intune-mcp-launch.mjs'), 'export {}\n', 0o644);
  writeFile(
    path.join(root, 'tools', 'm365-mcp-launch-core.mjs'),
    fs.readFileSync(path.join(HERE, 'm365-mcp-launch-core.mjs'))
  );
  writeFile(path.join(root, 'tools', 'intune-mcp-gate.mjs'), 'export {}\n', 0o644);
  writeFile(
    path.join(root, 'tools', 'm365-mcp-gate-lib.mjs'),
    fs.readFileSync(path.join(HERE, 'm365-mcp-gate-lib.mjs'))
  );
  return root;
}

function makeConfig(workspace, { env = validEnv(), envMode = 0o600, parentMode = 0o700, baselineMode = 0o600, baseline } = {}) {
  const configDir = tmpDir('m365-cfg-');
  chmod(configDir, parentMode);
  const baselineDir = path.join(configDir, 'baseline');
  fs.mkdirSync(baselineDir, { mode: 0o700 });
  chmod(baselineDir, 0o700);
  if (env) {
    writeFile(path.join(configDir, DESC.envFileName), envText(env), envMode);
  }
  const manifest = baseline || computeIntegrityManifest(workspace, DESC);
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
    return { on() {} };
  }
  return { spawnImpl, spawned };
}

function launch(configDir, ws, spawnImpl) {
  return runLauncher({
    configDir,
    descriptor: DESC,
    workspaceRoot: ws,
    spawnImpl,
    wait: false,
  });
}

test('missing env file refuses without spawn', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { env: null });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /missing env file/);
  assert.equal(spawned.length, 0);
});

test('env file mode 644 is refused and observed mode printed', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { envMode: 0o644 });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /mode is 644/);
  assert.equal(spawned.length, 0);
});

test('parent directory mode 755 is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { parentMode: 0o755 });
  const { spawnImpl, spawned } = stubSpawn();
  const { error } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(String(error.message), /parent/);
  assert.equal(spawned.length, 0);
});

test('env path symlink is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  const real = path.join(configDir, DESC.envFileName);
  const backup = real + '.real';
  fs.renameSync(real, backup);
  fs.symlinkSync(backup, real);
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /symlink/);
  assert.equal(spawned.length, 0);
});

test('parent symlink is refused', () => {
  const ws = makeWorkspace();
  const real = makeConfig(ws);
  const parent = tmpDir('m365-link-parent-');
  const configDir = path.join(parent, 'cfg');
  fs.symlinkSync(real, configDir);
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /symlink/);
  assert.equal(spawned.length, 0);
});

test('FIFO at env path is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  const envPath = path.join(configDir, DESC.envFileName);
  fs.rmSync(envPath);
  execFileSync('mkfifo', ['-m', '600', envPath]);
  const { error, stderr } = captureStderr(() => {
    readEnvFile(configDir, DESC);
  });
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /not a regular file|FIFO|cannot open/i);
});

test('config-dir resolver ignores HOME', () => {
  const fixtureHome = tmpDir('fake-home-');
  fs.mkdirSync(path.join(fixtureHome, '.config', 'intune-mcp'), { recursive: true });
  writeFile(path.join(fixtureHome, '.config', 'intune-mcp', 'intune-mcp.env'), envText(validEnv()));
  const prev = process.env.HOME;
  process.env.HOME = fixtureHome;
  try {
    const resolved = resolveDefaultConfigDir('intune-mcp');
    const account = resolveAccountHome();
    assert.equal(resolved, path.join(account, '.config', 'intune-mcp'));
    assert.notEqual(resolved, path.join(fixtureHome, '.config', 'intune-mcp'));
  } finally {
    process.env.HOME = prev;
  }
});

test('missing active baseline refuses before env open', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  fs.rmSync(path.join(configDir, 'baseline', 'active.json'));
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.match(stderr, /missing active baseline/);
  assert.equal(error instanceof LaunchError, true);
  assert.equal(spawned.length, 0);
});

test('active baseline mode 644 is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { baselineMode: 0o644 });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.match(stderr, /baseline/);
  assert.equal(error instanceof LaunchError, true);
  assert.equal(spawned.length, 0);
});

test('child environment equals five prefix names plus PATH/locale and drops denylist', () => {
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
    EXO_CLIENT_SECRET: 'foreign-secret',
    SPO_ADMIN_CLIENT_SECRET: 'spo-secret',
    TEAMS_ADMIN_CLIENT_SECRET: 'teams-secret',
  };
  const child = buildChildEnv(fileEnv, parent, DESC);
  assert.deepEqual(Object.keys(child).sort(), [
    'INTUNE_CLIENT_CERTIFICATE_PATH',
    'INTUNE_CLIENT_ID',
    'INTUNE_CLIENT_SECRET',
    'INTUNE_SECRET_EXPIRES',
    'INTUNE_TENANT_ID',
    'LANG',
    'LC_ALL',
    'PATH',
  ]);
  for (const name of BASE_DENYLIST) {
    assert.equal(Object.hasOwn(child, name), false, name);
  }
  assert.equal(Object.hasOwn(child, 'EXO_CLIENT_SECRET'), false);
  assert.equal(Object.hasOwn(child, 'SPO_ADMIN_CLIENT_SECRET'), false);
  assert.equal(Object.hasOwn(child, 'TEAMS_ADMIN_CLIENT_SECRET'), false);
  assert.equal(child.PATH, '/usr/bin:/bin:/usr/sbin:/sbin');
  assert.equal(child.LANG, 'en_US.UTF-8');
  assert.equal(child.INTUNE_CLIENT_CERTIFICATE_PATH, '');
});

test('foreign-prefix secret in parent is absent from child', () => {
  const child = buildChildEnv(validEnv(), { EXO_CLIENT_SECRET: 'should-not-leak' }, DESC);
  assert.equal(child.EXO_CLIENT_SECRET, undefined);
  assert.equal(JSON.stringify(child).includes('should-not-leak'), false);
});

test('missing required vars refused; empty cert placeholder allowed', () => {
  for (const key of ['INTUNE_TENANT_ID', 'INTUNE_CLIENT_ID', 'INTUNE_CLIENT_SECRET', 'INTUNE_SECRET_EXPIRES']) {
    const env = validEnv();
    delete env[key];
    const { error } = captureStderr(() => validateCredentials(env, DESC));
    assert.equal(error instanceof LaunchError, true);
    assert.match(error.message, /missing/);
  }
  const ok = validateCredentials(validEnv({ INTUNE_CLIENT_CERTIFICATE_PATH: '' }), DESC);
  assert.equal(typeof ok.expiresInDays, 'number');
});

test('cert path without secret is refused', () => {
  const env = validEnv();
  delete env.INTUNE_CLIENT_SECRET;
  env.INTUNE_CLIENT_CERTIFICATE_PATH = '/tmp/cert.pem';
  const { error, stderr } = captureStderr(() => validateCredentials(env, DESC));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /certificate path does not satisfy/);
});

test('malformed and past expiry refused; 14-day warning', () => {
  const { error: bad } = captureStderr(() =>
    validateCredentials(validEnv({ INTUNE_SECRET_EXPIRES: 'not-a-date' }), DESC)
  );
  assert.match(bad.message, /malformed/);
  const { error: past } = captureStderr(() =>
    validateCredentials(validEnv({ INTUNE_SECRET_EXPIRES: '2000-01-01T00:00:00Z' }), DESC)
  );
  assert.match(past.message, /past expiry|at or past/);
  const warn = validateCredentials(validEnv({ INTUNE_SECRET_EXPIRES: futureExpiry(7) }), DESC);
  assert.equal(warn.warn, true);
});

test('source hash mismatch refuses with no spawn', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  fs.appendFileSync(
    path.join(ws, 'tools', 'intune-mcp-server', 'src', 'intune_mcp', 'server.py'),
    '# drift\n'
  );
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.match(stderr, /integrity mismatch/);
  assert.equal(error instanceof LaunchError, true);
  assert.equal(spawned.length, 0);
});

test('kernel hash mismatch refuses with no spawn', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  fs.appendFileSync(
    path.join(ws, 'tools', 'm365-mcp-kernel', 'src', 'm365_mcp_kernel', 'graph_client.py'),
    '# kernel drift\n'
  );
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.match(stderr, /integrity mismatch/);
  assert.equal(spawned.length, 0);
});

test('happy path fixture env spawns isolated python -I -B -m intune_mcp', () => {
  const ws = makeWorkspace();
  const secret = 'super-secret-value-not-for-logs';
  const configDir = makeConfig(ws, { env: validEnv({ INTUNE_CLIENT_SECRET: secret }) });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.equal(error, undefined);
  assert.equal(spawned.length, 1);
  assert.equal(path.basename(spawned[0].cmd), 'python');
  assert.deepEqual(spawned[0].args, ['-I', '-B', '-m', 'intune_mcp']);
  assert.equal(spawned[0].opts.stdio, 'inherit');
  assert.equal(spawned[0].opts.env.INTUNE_CLIENT_SECRET, secret);
  assert.equal(stderr.includes(secret), false);
});

test('expiry within 14 days starts with stderr warning', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws, { env: validEnv({ INTUNE_SECRET_EXPIRES: futureExpiry(7) }) });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, ws, spawnImpl));
  assert.equal(error, undefined);
  assert.equal(spawned.length, 1);
  assert.match(stderr, /within 14 days/);
});

test('directory at env path is refused', () => {
  const ws = makeWorkspace();
  const configDir = makeConfig(ws);
  const envPath = path.join(configDir, DESC.envFileName);
  fs.rmSync(envPath);
  fs.mkdirSync(envPath, { mode: 0o700 });
  const { error, stderr } = captureStderr(() => readEnvFile(configDir, DESC));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /not a regular file|EISDIR|cannot open/i);
});

test('prefixEnvNames are five names', () => {
  assert.equal(prefixEnvNames('INTUNE').length, 5);
});

test('hygiene detects sentinel in fixture Codex config', () => {
  const home = tmpDir('hygiene-home-');
  const workspace = tmpDir('hygiene-ws-');
  const evidence = tmpDir('hygiene-ev-');
  chmod(home, 0o700);
  writeFile(path.join(home, '.claude.json'), '{}\n', 0o600);
  writeFile(path.join(home, '.codex', 'config.toml'), 'secret = "sentinel-ABCDEFGH-token"\n', 0o600);
  writeFile(path.join(home, '.grok', 'config.toml'), 'x=1\n', 0o600);
  const surfaces = defaultHygieneSurfaces({
    home,
    workspaceRoot: workspace,
    evidenceDir: evidence,
    registrationName: 'intune-ro',
    preRegistration: true,
  });
  const report = scanHygiene({
    surfaces,
    needles: ['sentinel-ABCDEFGH-token', 'sentinel-', '-token'],
  });
  assert.equal(report.ok, false);
  assert.ok(report.hits >= 1);
  assert.equal(report.statuses.grok_log, 'not_created_pre_registration');
});

test('hygiene permission-denied fails', () => {
  const dir = tmpDir('hygiene-perm-');
  const file = path.join(dir, 'locked.txt');
  writeFile(file, 'ok\n', 0o000);
  const report = scanHygiene({
    surfaces: [{ name: 'locked', path: file, kind: 'file' }],
    needles: ['nope'],
  });
  // unreadable (EACCES) is a fail; restore mode for cleanup
  fs.chmodSync(file, 0o600);
  assert.equal(report.ok, false);
  assert.equal(report.statuses.locked, 'fail');
});

test('hygiene ENOENT grok log pre-registration is not_created_pre_registration', () => {
  const home = tmpDir('hygiene-pre-');
  writeFile(path.join(home, '.claude.json'), '{}\n', 0o600);
  writeFile(path.join(home, '.codex', 'config.toml'), 'x=1\n', 0o600);
  writeFile(path.join(home, '.grok', 'config.toml'), 'x=1\n', 0o600);
  const workspace = tmpDir('hygiene-pre-ws-');
  const evidence = tmpDir('hygiene-pre-ev-');
  const surfaces = defaultHygieneSurfaces({
    home,
    workspaceRoot: workspace,
    evidenceDir: evidence,
    registrationName: 'intune-ro',
    preRegistration: true,
  });
  const report = scanHygiene({ surfaces, needles: ['zzzz-not-present'] });
  assert.equal(report.statuses.grok_log, 'not_created_pre_registration');
  assert.notEqual(report.statuses.grok_log, 'scanned_clean');
  assert.equal(report.ok, true);
});

test('hygiene ENOENT on any other declared surface fails', () => {
  const report = scanHygiene({
    surfaces: [{ name: 'claude_json', path: path.join(tmpDir('missing-'), 'nope.json'), kind: 'file' }],
    needles: ['x'],
  });
  assert.equal(report.ok, false);
  assert.equal(report.statuses.claude_json, 'fail');
});

test('shared-source edit blocks both promoted workloads until both re-run', () => {
  const before = { 'tools/m365-mcp-launch-core.mjs': 'aaa' };
  const after = { 'tools/m365-mcp-launch-core.mjs': 'bbb' };
  const plan = planSharedRelease({
    workloads: [
      { name: 'intune-ro', promoted: true },
      { name: 'spo-admin-ro', promoted: true },
    ],
    sharedBefore: before,
    sharedAfter: after,
  });
  assert.equal(plan.changed, true);
  assert.deepEqual(plan.blocked.sort(), ['intune-ro', 'spo-admin-ro']);
});

test('shared confirm failure coherent rollback or both stopped; never baseline-only success', () => {
  const workloads = [
    { name: 'intune-ro', promoted: true },
    { name: 'spo-admin-ro', promoted: true },
  ];
  const restored = applySharedConfirm({
    workloads,
    confirmResults: { 'intune-ro': 'ok', 'spo-admin-ro': 'fail' },
    restoreShared: () => true,
    restoreWorkload: () => true,
  });
  assert.equal(restored.ok, true);
  assert.equal(restored.mode, 'coherent_rollback');
  assert.equal(restored.restored.length, 2);

  const stopped = applySharedConfirm({
    workloads,
    confirmResults: { 'intune-ro': 'fail', 'spo-admin-ro': 'fail' },
    restoreShared: () => false,
    restoreWorkload: () => true,
  });
  assert.equal(stopped.ok, false);
  assert.equal(stopped.mode, 'all_stopped');
  assert.match(stopped.note, /baseline-only/);
});

test('KTD16 compare helper reports unchanged protected set on identical snapshots', () => {
  const ws = path.resolve(HERE, '..');
  const snap = snapshotEntraProtected({ workspaceRoot: ws });
  const cmp = compareEntraProtected(snap, snap);
  assert.equal(cmp.ok, true);
  assert.deepEqual(cmp.diffs, []);
  assert.equal(snap.protected['~/.config/entra-mcp/entra-mcp.env'].opened, false);
  assert.equal(snap.protected['~/.config/entra-mcp/entra-mcp.env'].hashed, false);
});
