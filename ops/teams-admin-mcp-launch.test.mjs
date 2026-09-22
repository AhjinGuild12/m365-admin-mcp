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
const CLI = path.join(HERE, 'teams-admin-mcp-launch.mjs');

const DESC = {
  envPrefix: 'TEAMS_ADMIN',
  envFileName: 'teams-admin-mcp.env',
  packageDir: 'packages/teams-admin-mcp-server',
  kernelPackageDir: 'packages/m365-mcp-kernel',
  moduleName: 'teams_admin_mcp',
  launchCliRel: 'ops/teams-admin-mcp-launch.mjs',
  launchCoreRel: 'ops/m365-mcp-launch-core.mjs',
  gateRel: 'ops/teams-admin-mcp-gate.mjs',
  gateLibRel: 'ops/m365-mcp-gate-lib.mjs',
  otherPrefixes: ['ENTRA', 'INTUNE', 'SPO_ADMIN', 'EXO'],
  stderrName: 'teams-admin-mcp-launch',
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

function pastExpiry() {
  return new Date(Date.now() - 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function validEnv(overrides = {}) {
  return {
    TEAMS_ADMIN_TENANT_ID: 'YOUR_TENANT_ID',
    TEAMS_ADMIN_CLIENT_ID: 'YOUR_CLIENT_ID',
    TEAMS_ADMIN_CLIENT_SECRET: 'YOUR_CLIENT_SECRET',
    TEAMS_ADMIN_SECRET_EXPIRES: futureExpiry(60),
    TEAMS_ADMIN_CLIENT_CERTIFICATE_PATH: '',
    ...overrides,
  };
}

function envText(obj) {
  return Object.entries(obj).map(([key, value]) => `${key}=${value}`).join('\n') + '\n';
}

function makeWorkspace() {
  const root = tmpDir('teams-ws-');
  writeFile(path.join(root, 'packages/teams-admin-mcp-server/src/teams_admin_mcp/server.py'), 'print(1)\n', 0o644);
  writeFile(path.join(root, 'packages/teams-admin-mcp-server/pyproject.toml'), '[project]\nname="teams-admin-mcp"\n', 0o644);
  writeFile(path.join(root, 'packages/teams-admin-mcp-server/uv.lock'), 'version = 1\n', 0o644);
  writeFile(path.join(root, 'packages/teams-admin-mcp-server/.venv/pyvenv.cfg'), 'home = /usr\n', 0o644);
  writeFile(path.join(root, 'packages/teams-admin-mcp-server/.venv/bin/python'), '#!/bin/sh\n', 0o755);
  writeFile(path.join(root, 'packages/m365-mcp-kernel/src/m365_mcp_kernel/graph_client.py'), 'x=1\n', 0o644);
  writeFile(path.join(root, 'packages/m365-mcp-kernel/pyproject.toml'), '[project]\nname="m365-mcp-kernel"\n', 0o644);
  writeFile(path.join(root, 'ops/teams-admin-mcp-launch.mjs'), 'export {}\n', 0o644);
  writeFile(path.join(root, 'ops/m365-mcp-launch-core.mjs'), fs.readFileSync(path.join(HERE, 'm365-mcp-launch-core.mjs')));
  writeFile(path.join(root, 'ops/teams-admin-mcp-gate.mjs'), 'export {}\n', 0o644);
  writeFile(path.join(root, 'ops/m365-mcp-gate-lib.mjs'), fs.readFileSync(path.join(HERE, 'm365-mcp-gate-lib.mjs')));
  return root;
}

function makeConfig(workspace, { env = validEnv(), envMode = 0o600, parentMode = 0o700 } = {}) {
  const configDir = tmpDir('teams-cfg-');
  fs.chmodSync(configDir, parentMode);
  const baselineDir = path.join(configDir, 'baseline');
  fs.mkdirSync(baselineDir, { mode: 0o700 });
  fs.chmodSync(baselineDir, 0o700);
  if (env) writeFile(path.join(configDir, DESC.envFileName), envText(env), envMode);
  const manifest = computeIntegrityManifest(workspace, DESC);
  manifest.workspaceRoot = workspace;
  writeFile(path.join(baselineDir, 'active.json'), JSON.stringify(manifest), 0o600);
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

function launch(configDir, workspace, spawnImpl, parentEnv) {
  return runLauncher({
    configDir,
    descriptor: DESC,
    workspaceRoot: workspace,
    spawnImpl,
    wait: false,
    parentEnv,
  });
}

test('CLI source never reads argv or env', () => {
  const src = fs.readFileSync(CLI, 'utf8');
  const check = staticCliCheck(src);
  assert.equal(check.ok, true, check.reasons.join('; '));
  assert.equal(/process\.argv/.test(src), false);
  assert.equal(/process\.env/.test(src), false);
  assert.match(src, /packages\/teams-admin-mcp-server/);
  assert.match(src, /teams_admin_mcp/);
});

test('valid env spawns with only teams vars, PATH, and locale', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace);
  const { spawnImpl, spawned } = stubSpawn();
  launch(configDir, workspace, spawnImpl, {
    LANG: 'en_NZ.UTF-8',
    LC_ALL: 'en_NZ.UTF-8',
    ENTRA_CLIENT_SECRET: 'entra-secret-value',
    INTUNE_CLIENT_SECRET: 'intune-secret-value',
  });
  assert.equal(spawned.length, 1);
  const child = spawned[0].opts.env;
  const keys = Object.keys(child).sort();
  assert.deepEqual(keys, [
    'LANG',
    'LC_ALL',
    'PATH',
    'TEAMS_ADMIN_CLIENT_CERTIFICATE_PATH',
    'TEAMS_ADMIN_CLIENT_ID',
    'TEAMS_ADMIN_CLIENT_SECRET',
    'TEAMS_ADMIN_SECRET_EXPIRES',
    'TEAMS_ADMIN_TENANT_ID',
  ]);
  assert.equal(JSON.stringify(child).includes('entra-secret-value'), false);
  assert.equal(JSON.stringify(child).includes('intune-secret-value'), false);
});

test('foreign secrets are absent from buildChildEnv', () => {
  const child = buildChildEnv(
    validEnv(),
    {
      ENTRA_CLIENT_SECRET: 'entra-secret-value',
      INTUNE_CLIENT_SECRET: 'intune-secret-value',
      LANG: 'C',
    },
    DESC,
  );
  assert.equal(JSON.stringify(child).includes('entra-secret-value'), false);
  assert.equal(JSON.stringify(child).includes('intune-secret-value'), false);
  assert.equal(child.LANG, 'C');
});

test('missing expiry dies before spawn', () => {
  const workspace = makeWorkspace();
  const env = validEnv();
  delete env.TEAMS_ADMIN_SECRET_EXPIRES;
  const configDir = makeConfig(workspace, { env });
  const { spawnImpl, spawned } = stubSpawn();
  const { error } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(String(error.message), /SECRET_EXPIRES/);
  assert.equal(spawned.length, 0);
});

test('past expiry dies before spawn', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace, {
    env: validEnv({ TEAMS_ADMIN_SECRET_EXPIRES: pastExpiry() }),
  });
  const { spawnImpl, spawned } = stubSpawn();
  const { error } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(String(error.message), /past expiry/);
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

test('integrity mismatch against packages dies before spawn', () => {
  const workspace = makeWorkspace();
  const configDir = makeConfig(workspace);
  fs.appendFileSync(
    path.join(workspace, 'packages/teams-admin-mcp-server/src/teams_admin_mcp/server.py'),
    '\n# changed\n',
  );
  const { spawnImpl, spawned } = stubSpawn();
  const { error } = captureStderr(() => launch(configDir, workspace, spawnImpl));
  assert.equal(error instanceof LaunchError, true);
  assert.match(String(error.message), /integrity mismatch/);
  assert.equal(spawned.length, 0);
});
