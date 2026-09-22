#!/usr/bin/env node
/**
 * teams-admin-mcp gate.
 * --stage1 --config-dir <dir>  credential-free, refuses ~/.config
 * --install                     Phase B production baseline (not used in Phase A)
 * --smoke                       Phase B live probes
 * --release-check               Phase B baseline vs published checkout
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  LaunchError,
  assertIntegrity,
  computeIntegrityManifest,
  readActiveBaseline,
  runLauncher,
} from './m365-mcp-launch-core.mjs';
import { evaluateProbe, staticCliCheck } from './m365-mcp-gate-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const WORKSPACE_ROOT = path.resolve(HERE, '..');
export const SERVER_DIR = path.join(WORKSPACE_ROOT, 'packages', 'teams-admin-mcp-server');

export const DESC = Object.freeze({
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
});

export function productionConfigDir(home = os.userInfo().homedir) {
  return path.join(home, '.config', 'teams-admin-mcp');
}

export function assertStage1ConfigDir(configDir, home = os.userInfo().homedir) {
  if (!configDir) {
    throw new Error('stage1 requires --config-dir');
  }
  const resolved = path.resolve(configDir);
  const blocked = path.resolve(home, '.config');
  if (resolved === blocked || resolved.startsWith(blocked + path.sep)) {
    throw new Error('stage1 refuses a config dir under the account .config');
  }
  return resolved;
}

function writeFileMode(target, data, mode) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, data);
  fs.chmodSync(target, mode);
}

function futureExpiry(days) {
  return new Date(Date.now() + days * 86400 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function envText(values) {
  return Object.entries(values)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n') + '\n';
}

export function placeholderEnv(overrides = {}) {
  return {
    TEAMS_ADMIN_TENANT_ID: 'YOUR_TENANT_ID',
    TEAMS_ADMIN_CLIENT_ID: 'YOUR_CLIENT_ID',
    TEAMS_ADMIN_CLIENT_SECRET: 'YOUR_CLIENT_SECRET',
    TEAMS_ADMIN_SECRET_EXPIRES: futureExpiry(90),
    TEAMS_ADMIN_CLIENT_CERTIFICATE_PATH: '',
    ...overrides,
  };
}

export function writeCandidate(configDir, workspaceRoot = WORKSPACE_ROOT) {
  fs.mkdirSync(configDir, { recursive: true });
  fs.chmodSync(configDir, 0o700);
  const bin = path.join(configDir, 'bin');
  const baseline = path.join(configDir, 'baseline');
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(baseline, { recursive: true });
  fs.chmodSync(bin, 0o700);
  fs.chmodSync(baseline, 0o700);
  const launchSrc = path.join(workspaceRoot, DESC.launchCliRel);
  const coreSrc = path.join(workspaceRoot, DESC.launchCoreRel);
  writeFileMode(
    path.join(bin, 'teams-admin-mcp-launch.mjs'),
    fs.readFileSync(launchSrc),
    0o700,
  );
  writeFileMode(path.join(bin, 'm365-mcp-launch-core.mjs'), fs.readFileSync(coreSrc), 0o644);
  const envPath = path.join(configDir, DESC.envFileName);
  if (!fs.existsSync(envPath)) {
    writeFileMode(envPath, envText(placeholderEnv()), 0o600);
  }
  const manifest = computeIntegrityManifest(workspaceRoot, DESC);
  manifest.workspaceRoot = path.resolve(workspaceRoot);
  writeFileMode(path.join(baseline, 'active.json'), JSON.stringify(manifest), 0o600);
  return manifest;
}

function stubWorkspace(root) {
  const files = [
    ['packages/teams-admin-mcp-server/src/teams_admin_mcp/server.py', 'print(1)\n'],
    ['packages/teams-admin-mcp-server/pyproject.toml', '[project]\nname="teams-admin-mcp"\n'],
    ['packages/teams-admin-mcp-server/uv.lock', 'version = 1\n'],
    ['packages/teams-admin-mcp-server/.venv/pyvenv.cfg', 'home = /usr\n'],
    ['packages/teams-admin-mcp-server/.venv/bin/python', '#!/bin/sh\n'],
    ['packages/m365-mcp-kernel/src/m365_mcp_kernel/graph_client.py', 'x=1\n'],
    ['packages/m365-mcp-kernel/pyproject.toml', '[project]\nname="m365-mcp-kernel"\n'],
    ['ops/teams-admin-mcp-launch.mjs', 'export {}\n'],
    ['ops/m365-mcp-launch-core.mjs', 'export {}\n'],
    ['ops/teams-admin-mcp-gate.mjs', 'export {}\n'],
    ['ops/m365-mcp-gate-lib.mjs', 'export {}\n'],
  ];
  for (const [rel, text] of files) {
    const target = path.join(root, rel);
    writeFileMode(target, text, rel.endsWith('/python') ? 0o755 : 0o644);
  }
}

function captureLaunch(fn) {
  const chunks = [];
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...rest) => {
    chunks.push(String(chunk));
    return orig(chunk, ...rest);
  };
  try {
    return { result: fn(), stderr: chunks.join('') };
  } catch (error) {
    return { error, stderr: chunks.join('') };
  } finally {
    process.stderr.write = orig;
  }
}

export function runLauncherRefusals(configDir) {
  const workspace = path.join(configDir, 'refusal-ws');
  stubWorkspace(workspace);
  const badDir = path.join(configDir, 'refusal-bad-mode');
  fs.mkdirSync(badDir, { recursive: true });
  fs.chmodSync(badDir, 0o700);
  const baselineDir = path.join(badDir, 'baseline');
  fs.mkdirSync(baselineDir, { recursive: true });
  fs.chmodSync(baselineDir, 0o700);
  const manifest = computeIntegrityManifest(workspace, DESC);
  manifest.workspaceRoot = workspace;
  writeFileMode(path.join(baselineDir, 'active.json'), JSON.stringify(manifest), 0o600);
  writeFileMode(path.join(badDir, DESC.envFileName), envText(placeholderEnv()), 0o644);
  const mode = captureLaunch(() =>
    runLauncher({
      configDir: badDir,
      descriptor: DESC,
      workspaceRoot: workspace,
      spawnImpl() {
        throw new Error('spawned');
      },
      wait: false,
    }),
  );
  if (!(mode.error instanceof LaunchError)) {
    throw new Error('mode 644 env was accepted');
  }

  const pastDir = path.join(configDir, 'refusal-past');
  fs.mkdirSync(pastDir, { recursive: true });
  fs.chmodSync(pastDir, 0o700);
  const pastBaseline = path.join(pastDir, 'baseline');
  fs.mkdirSync(pastBaseline, { recursive: true });
  fs.chmodSync(pastBaseline, 0o700);
  writeFileMode(path.join(pastBaseline, 'active.json'), JSON.stringify(manifest), 0o600);
  const past = placeholderEnv();
  past.TEAMS_ADMIN_SECRET_EXPIRES = '2000-01-01T00:00:00Z';
  writeFileMode(path.join(pastDir, DESC.envFileName), envText(past), 0o600);
  const expired = captureLaunch(() =>
    runLauncher({
      configDir: pastDir,
      descriptor: DESC,
      workspaceRoot: workspace,
      spawnImpl() {
        throw new Error('spawned');
      },
      wait: false,
    }),
  );
  if (!(expired.error instanceof LaunchError)) {
    throw new Error('past expiry was accepted');
  }
}

export function runStage1({
  configDir,
  home = os.userInfo().homedir,
  workspaceRoot = WORKSPACE_ROOT,
  runPytest = true,
  runRefusal = true,
} = {}) {
  const resolved = assertStage1ConfigDir(configDir, home);
  const cli = fs.readFileSync(path.join(workspaceRoot, DESC.launchCliRel), 'utf8');
  const check = staticCliCheck(cli);
  if (!check.ok) {
    throw new Error(`static CLI check failed: ${check.reasons.join('; ')}`);
  }
  if (runPytest) {
    const pytest = spawnSync('uv', ['run', 'pytest', '-q'], {
      cwd: SERVER_DIR,
      encoding: 'utf8',
    });
    if (pytest.status !== 0) {
      throw new Error(pytest.stdout || pytest.stderr || 'pytest failed');
    }
  }
  writeCandidate(resolved, workspaceRoot);
  if (runRefusal) runLauncherRefusals(resolved);
  return { ok: true, configDir: resolved };
}

export function installBaseline({
  configDir,
  workspaceRoot = WORKSPACE_ROOT,
  rebaseline = false,
  reason = '',
} = {}) {
  if (!configDir) {
    throw new Error('install requires a config dir');
  }
  const active = path.join(configDir, 'baseline', 'active.json');
  if (fs.existsSync(active) && !rebaseline) {
    throw new Error('baseline exists; pass --rebaseline --reason');
  }
  if (rebaseline && !String(reason || '').trim()) {
    throw new Error('rebaseline requires --reason');
  }
  return writeCandidate(configDir, workspaceRoot);
}

export const PROBE_MATRIX = Object.freeze([
  { tool: 'list_teams', bounded: true, target: 'team' },
  { tool: 'get_team_sensitivity_labels', kind: 'single', target: 'team' },
  { tool: 'get_team', kind: 'single', target: 'team' },
  { tool: 'list_user_joined_teams', target: 'user' },
  { tool: 'list_team_members', target: 'team' },
  { tool: 'list_team_owners', target: 'team' },
  { tool: 'list_channels', target: 'team' },
  { tool: 'get_channel', kind: 'single', target: 'channel' },
  { tool: 'list_channel_members', target: 'channel' },
  { tool: 'list_team_installed_apps', target: 'team' },
  { tool: 'list_org_catalog_apps', bounded: true, target: 'none' },
  { tool: 'get_user_teams_policy_assignments', kind: 'single', target: 'user' },
  { tool: 'list_teams_team_activity', target: 'none' },
]);

export function evaluateSmokeMatrix(targets, messages) {
  const team = targets && targets.TEAMS_ADMIN_PROBE_TEAM_ID;
  const channel = targets && targets.TEAMS_ADMIN_PROBE_CHANNEL_ID;
  const user = targets && targets.TEAMS_ADMIN_PROBE_USER_ID;
  const byTool = { team, channel, user, none: 'catalog' };
  return PROBE_MATRIX.map((probe) => {
    const value = byTool[probe.target];
    const missing = probe.target !== 'none' && (!value || String(value).trim() === '');
    const spec = {
      tool: probe.tool,
      bounded: probe.bounded === true,
      kind: probe.kind,
      expectedId: probe.kind === 'single' ? value : undefined,
      targetPresent: !missing,
    };
    const message = messages && messages[probe.tool];
    const verdict = evaluateProbe(spec, missing ? null : message);
    return { tool: probe.tool, ...verdict };
  });
}

export function releaseCheck({ configDir, workspaceRoot = WORKSPACE_ROOT } = {}) {
  const baseline = readActiveBaseline(configDir, DESC);
  const recorded = baseline && baseline.workspaceRoot;
  if (!recorded || path.resolve(recorded) !== path.resolve(workspaceRoot)) {
    throw new Error('baseline workspaceRoot does not match the published checkout');
  }
  assertIntegrity(configDir, workspaceRoot, DESC);
  const python = path.join(workspaceRoot, DESC.packageDir, '.venv', 'bin', 'python');
  return {
    ok: true,
    workspaceRoot: path.resolve(recorded),
    interpreter: python,
    manifest: DESC.packageDir,
  };
}

function parseArgs(argv) {
  const out = {
    stage1: false,
    install: false,
    smoke: false,
    releaseCheck: false,
    rebaseline: false,
    reason: '',
    configDir: '',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--stage1') out.stage1 = true;
    else if (arg === '--install') out.install = true;
    else if (arg === '--smoke') out.smoke = true;
    else if (arg === '--release-check') out.releaseCheck = true;
    else if (arg === '--rebaseline') out.rebaseline = true;
    else if (arg === '--reason') out.reason = argv[(i += 1)] || '';
    else if (arg === '--config-dir') out.configDir = argv[(i += 1)] || '';
    else throw new Error(`unknown argument ${arg}`);
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.stage1) {
    runStage1({ configDir: args.configDir });
    process.stdout.write('stage1 ok\n');
    return;
  }
  if (args.install) {
    const configDir = args.configDir || productionConfigDir();
    installBaseline({
      configDir,
      rebaseline: args.rebaseline,
      reason: args.reason,
    });
    process.stdout.write('install ok\n');
    return;
  }
  if (args.releaseCheck) {
    const configDir = args.configDir || productionConfigDir();
    const result = releaseCheck({ configDir });
    process.stdout.write(`${JSON.stringify({ ok: result.ok })}\n`);
    return;
  }
  if (args.smoke) {
    throw new Error('live smoke is Phase B and is not run from the offline gate');
  }
  throw new Error('pass --stage1 --config-dir, --install, --smoke, or --release-check');
}

const entry = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (entry === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    process.stderr.write(`teams-admin-mcp-gate: ${err.message || err}\n`);
    process.exit(1);
  }
}
