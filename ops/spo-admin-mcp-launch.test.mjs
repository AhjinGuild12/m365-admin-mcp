import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { staticCliCheck } from './m365-mcp-gate-lib.mjs';
import {
  LaunchError,
  buildChildEnv,
  computeIntegrityManifest,
  runLauncher,
} from './m365-mcp-launch-core.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, 'spo-admin-mcp-launch.mjs');

const DESC = {
  envPrefix: 'SPO_ADMIN',
  envFileName: 'spo-admin-mcp.env',
  packageDir: 'tools/spo-admin-mcp-server',
  kernelPackageDir: 'tools/m365-mcp-kernel',
  moduleName: 'spo_admin_mcp',
  launchCliRel: 'tools/spo-admin-mcp-launch.mjs',
  launchCoreRel: 'tools/m365-mcp-launch-core.mjs',
  gateRel: 'tools/spo-admin-mcp-gate.mjs',
  gateLibRel: 'tools/m365-mcp-gate-lib.mjs',
  otherPrefixes: ['INTUNE', 'TEAMS_ADMIN', 'EXO'],
  stderrName: 'spo-admin-mcp-launch',
};

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeFile(target, content, mode = 0o600) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  fs.chmodSync(target, mode);
}

function futureExpiry(days = 60) {
  return new Date(Date.now() + days * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function validEnv(overrides = {}) {
  return {
    SPO_ADMIN_TENANT_ID: 'tenant-id',
    SPO_ADMIN_CLIENT_ID: 'client-id',
    SPO_ADMIN_CLIENT_SECRET: 'spo-fixture-secret',
    SPO_ADMIN_SECRET_EXPIRES: futureExpiry(60),
    SPO_ADMIN_CLIENT_CERTIFICATE_PATH: '',
    ...overrides,
  };
}

function envText(obj) {
  return Object.entries(obj).map(([key, value]) => `${key}=${value}`).join('\n') + '\n';
}

function makeWorkspace() {
  const root = tmpDir('spo-ws-');
  writeFile(path.join(root, 'tools', 'spo-admin-mcp-server', 'src', 'spo_admin_mcp', 'server.py'), 'print(1)\n', 0o644);
  writeFile(path.join(root, 'tools', 'spo-admin-mcp-server', 'pyproject.toml'), '[project]\nname="spo-admin-mcp"\n', 0o644);
  writeFile(path.join(root, 'tools', 'spo-admin-mcp-server', 'uv.lock'), 'version = 1\n', 0o644);
  writeFile(path.join(root, 'tools', 'spo-admin-mcp-server', '.venv', 'pyvenv.cfg'), 'home = /usr\n', 0o644);
  writeFile(path.join(root, 'tools', 'spo-admin-mcp-server', '.venv', 'bin', 'python'), '#!/bin/sh\n', 0o755);
  writeFile(path.join(root, 'tools', 'm365-mcp-kernel', 'src', 'm365_mcp_kernel', 'graph_client.py'), 'x=1\n', 0o644);
  writeFile(path.join(root, 'tools', 'm365-mcp-kernel', 'pyproject.toml'), '[project]\nname="m365-mcp-kernel"\n', 0o644);
  writeFile(path.join(root, 'tools', 'spo-admin-mcp-launch.mjs'), 'export {}\n', 0o644);
  writeFile(path.join(root, 'tools', 'm365-mcp-launch-core.mjs'), fs.readFileSync(path.join(HERE, 'm365-mcp-launch-core.mjs')));
  writeFile(path.join(root, 'tools', 'spo-admin-mcp-gate.mjs'), 'export {}\n', 0o644);
  writeFile(path.join(root, 'tools', 'm365-mcp-gate-lib.mjs'), fs.readFileSync(path.join(HERE, 'm365-mcp-gate-lib.mjs')));
  return root;
}

function makeConfig(workspace, { env = validEnv(), envMode = 0o600, parentMode = 0o700, baselineMode = 0o600 } = {}) {
  const configDir = tmpDir('spo-cfg-');
  fs.chmodSync(configDir, parentMode);
  const baselineDir = path.join(configDir, 'baseline');
  fs.mkdirSync(baselineDir, { mode: 0o700 });
  fs.chmodSync(baselineDir, 0o700);
  if (env) writeFile(path.join(configDir, DESC.envFileName), envText(env), envMode);
  const manifest = computeIntegrityManifest(workspace, DESC);
  manifest.workspaceRoot = workspace;
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

function launch(configDir, workspace, spawnImpl) {
  return runLauncher({
    configDir,
    descriptor: DESC,
    workspaceRoot: workspace,
    spawnImpl,
    wait: false,
  });
}

test('CLI source never reads argv or env', () => {
  const src = fs.readFileSync(CLI, 'utf8');
  const check = staticCliCheck(src);
  assert.equal(check.ok, true, check.reasons.join('; '));
  assert.equal(/process\.argv/.test(src), false);
  assert.equal(/process\.env/.test(src), false);
  assert.match(src, /runLauncher\(/);
  assert.match(src, /spo_admin_mcp/);
  assert.match(src, /SPO_ADMIN/);
  assert.match(src, /spo-admin-mcp\.env/);
  assert.match(src, /tools\/spo-admin-mcp-server/);
  assert.match(src, /\['INTUNE', 'TEAMS_ADMIN', 'EXO'\]/);
});

test('CLI is not executed by this file', () => {
  const self = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8');
  assert.equal(/spo-admin-mcp-launch\.mjs['"]/.test(self) && /spawn\(/.test(self), false);
  assert.doesNotMatch(self, /execFileSync\(\s*process\.execPath/);
});

test('foreign-prefix secrets are stripped from the child env', () => {
  const child = buildChildEnv(
    validEnv(),
    {
      INTUNE_CLIENT_SECRET: 'intune-secret',
      TEAMS_ADMIN_CLIENT_SECRET: 'teams-secret',
      EXO_CLIENT_SECRET: 'exo-secret',
      LANG: 'en_NZ.UTF-8',
    },
    DESC
  );
  assert.deepEqual(Object.keys(child).sort(), [
    'LANG',
    'PATH',
    'SPO_ADMIN_CLIENT_CERTIFICATE_PATH',
    'SPO_ADMIN_CLIENT_ID',
    'SPO_ADMIN_CLIENT_SECRET',
    'SPO_ADMIN_SECRET_EXPIRES',
    'SPO_ADMIN_TENANT_ID',
  ]);
  assert.equal(child.SPO_ADMIN_CLIENT_SECRET, 'spo-fixture-secret');
  assert.equal(JSON.stringify(child).includes('intune-secret'), false);
  assert.equal(JSON.stringify(child).includes('teams-secret'), false);
  assert.equal(JSON.stringify(child).includes('exo-secret'), false);
});

test('missing env file refuses without spawn', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace, { env: null });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /missing env file/);
  assert.equal(spawned.length, 0);
});

test('env file mode 644 is refused', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace, { envMode: 0o644 });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /mode is 644/);
  assert.equal(spawned.length, 0);
});

test('parent directory mode 755 is refused', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace, { parentMode: 0o755 });
  const { spawnImpl, spawned } = stubSpawn();
  const { error } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(String(error.message), /parent/);
  assert.equal(spawned.length, 0);
});

test('missing active baseline refuses before spawn', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace);
  fs.rmSync(path.join(configDir, 'baseline', 'active.json'));
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /missing active baseline/);
  assert.equal(spawned.length, 0);
});

test('past expiry is refused without spawn', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace, {
    env: validEnv({ SPO_ADMIN_SECRET_EXPIRES: '2000-01-01T00:00:00Z' }),
  });
  const { spawnImpl, spawned } = stubSpawn();
  const { error, stderr } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(stderr, /past expiry/);
  assert.equal(stderr.includes('spo-fixture-secret'), false);
  assert.equal(spawned.length, 0);
});

test('accepted fixture spawns python -I -B -m spo_admin_mcp and keeps foreign secrets out', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace);
  const { spawnImpl, spawned } = stubSpawn();
  const prev = process.env.INTUNE_CLIENT_SECRET;
  process.env.INTUNE_CLIENT_SECRET = 'YOUR_CLIENT_SECRET_PLACEHOLDER';
  const { error, stderr } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  if (prev === undefined) delete process.env.INTUNE_CLIENT_SECRET;
  else process.env.INTUNE_CLIENT_SECRET = prev;
  assert.equal(error, undefined);
  assert.equal(stderr.includes('spo-fixture-secret'), false);
  assert.equal(stderr.includes('intune-secret'), false);
  assert.equal(spawned.length, 1);
  assert.deepEqual(spawned[0].args, ['-I', '-B', '-m', 'spo_admin_mcp']);
  assert.equal(spawned[0].opts.cwd, path.join(workspace, 'tools', 'spo-admin-mcp-server'));
  assert.equal(spawned[0].opts.env.SPO_ADMIN_CLIENT_SECRET, 'spo-fixture-secret');
  assert.equal(spawned[0].opts.env.INTUNE_CLIENT_SECRET, undefined);
});
