#!/usr/bin/env node
/**
 * intune-mcp-gate.mjs — two-stage gate harness for intune-ro.
 * Stage 1 (default): credential-free KTD9 lifecycle + KTD13 stdio/AST/sentinel.
 * Stage 2 (live): probe matrix after W.U1. Production env opened only via core.
 */
import { spawn } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  LaunchError,
  computeIntegrityManifest,
  runLauncher,
  readEnvFile,
  buildChildEnv,
  validateCredentials,
} from './m365-mcp-launch-core.mjs';

import {
  HYGIENE_SKIP_DIR_NAMES,
  appendHistory,
  atomicWriteFile,
  blobHasSecret,
  captureStderr,
  chmodDir700,
  compareEntraProtected,
  defaultHygieneSurfaces,
  envText,
  fragments,
  makeFixtureConfig,
  promoteBaseline,
  rollbackFirstPromotion,
  rollbackLaterPromotion,
  scanHygiene,
  setsEqual,
  snapshotEntraProtected,
  staticCliCheck,
  writeCandidate,
} from './m365-mcp-gate-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE_ROOT = path.resolve(HERE, '..');
const PROD_CONFIG = path.join(os.userInfo().homedir, '.config', 'intune-mcp');
const PROD_ENV = path.join(PROD_CONFIG, 'intune-mcp.env');
const BASELINE_DIR = path.join(PROD_CONFIG, 'baseline');
const BIN_DIR = path.join(PROD_CONFIG, 'bin');
const EVID_DIR_STAGE1 = path.join(PROD_CONFIG, 'evidence', '2026-09-10-gates');
const EVID_DIR_STAGE2 = path.join(PROD_CONFIG, 'evidence', '2026-09-21-gates');
let EVID_DIR = EVID_DIR_STAGE1;
const SERVER_DIR = path.join(WORKSPACE_ROOT, 'tools', 'intune-mcp-server');
const VENV_PYTHON = path.join(SERVER_DIR, '.venv', 'bin', 'python');
const PYTEST_LINK = '/tmp/intune-mcp-server-pytest';

const LAUNCHER_SRC = path.join(HERE, 'intune-mcp-launch.mjs');
const CORE_SRC = path.join(HERE, 'm365-mcp-launch-core.mjs');
const GATE_SRC = path.join(HERE, 'intune-mcp-gate.mjs');
const GATE_LIB_SRC = path.join(HERE, 'm365-mcp-gate-lib.mjs');

const DESC = Object.freeze({
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
});

const R5_TOOLS = Object.freeze([
  'get_intune_overview',
  'list_managed_devices',
  'get_managed_device',
  'search_managed_devices',
  'list_noncompliant_devices',
  'list_detected_apps',
  'list_compliance_policies',
  'get_compliance_policy_status',
  'list_configuration_profiles',
  'list_mobile_apps',
  'list_autopilot_devices',
  'list_enrollment_configurations',
  'list_intune_audit_events',
]);

const EXPECTED_REMOTE_HOSTS = Object.freeze(['login.microsoftonline.com', 'graph.microsoft.com']);
const EXPECTED_ROLES = Object.freeze([
  'DeviceManagementManagedDevices.Read.All',
  'DeviceManagementConfiguration.Read.All',
  'DeviceManagementApps.Read.All',
  'DeviceManagementServiceConfig.Read.All',
]);
const PROBE_MATRIX = Object.freeze([
  { name: 'get_intune_overview', arguments: {} },
  { name: 'list_compliance_policies', arguments: {} },
  { name: 'list_mobile_apps', arguments: { top: 1 } },
  { name: 'list_enrollment_configurations', arguments: {} },
  { name: 'list_autopilot_devices', arguments: { top: 1 } },
  { name: 'list_intune_audit_events', arguments: { days: 1 } },
]);
const WRONG_SECRET = 'invalid-secret-for-stage2-redaction-not-real';

const SENTINEL = 'intune-gate-sentinel-9f3a2c1b';
const SENTINEL_ENV = {
  INTUNE_TENANT_ID: '00000000-0000-0000-0000-000000000001',
  INTUNE_CLIENT_ID: '00000000-0000-0000-0000-000000000002',
  INTUNE_CLIENT_SECRET: SENTINEL,
  INTUNE_SECRET_EXPIRES: '2099-01-01T00:00:00Z',
  INTUNE_CLIENT_CERTIFICATE_PATH: '',
};

function die(msg) {
  process.stderr.write(`intune-mcp-gate: ${msg}\n`);
  process.exit(1);
}

function writeEvidence(result) {
  chmodDir700(EVID_DIR);
  const name = EVID_DIR === EVID_DIR_STAGE2 ? 'u5-stage2.json' : 'u5-stage1.json';
  const out = path.join(EVID_DIR, name);
  atomicWriteFile(out, JSON.stringify(result, null, 2), 0o600);
  return out;
}

function runCaptured(cmd, args, opts = {}) {
  const child = spawn(cmd, args, {
    cwd: opts.cwd,
    env: opts.env || process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => {
    stdout += d.toString();
  });
  child.stderr.on('data', (d) => {
    stderr += d.toString();
  });
  const timeoutMs = opts.timeoutMs || 120000;
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {}
      resolve({ code: 124, stdout, stderr: stderr + '\ntimeout', timedOut: true });
    }, timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(t);
      resolve({ code: code ?? 1, stdout, stderr, timedOut: false });
    });
    child.on('error', (err) => {
      clearTimeout(t);
      resolve({ code: 1, stdout, stderr: String(err.message), timedOut: false });
    });
  });
}

function ensurePytestLink() {
  const target = SERVER_DIR;
  try {
    const st = fs.lstatSync(PYTEST_LINK);
    if (st.isSymbolicLink() && fs.realpathSync(PYTEST_LINK) === fs.realpathSync(target)) {
      return PYTEST_LINK;
    }
    fs.unlinkSync(PYTEST_LINK);
  } catch {}
  fs.symlinkSync(target, PYTEST_LINK);
  return PYTEST_LINK;
}

function descendantPids(rootPid) {
  const pids = new Set([Number(rootPid)]);
  const queue = [Number(rootPid)];
  while (queue.length) {
    const pid = queue.shift();
    let out = '';
    try {
      out = execFileSync('pgrep', ['-P', String(pid)], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch {
      continue;
    }
    for (const tok of out.trim().split(/\s+/)) {
      const n = Number(tok);
      if (n && !pids.has(n)) {
        pids.add(n);
        queue.push(n);
      }
    }
  }
  return [...pids];
}

function listeningSockets(pids) {
  if (!pids.length) return [];
  try {
    const out = execFileSync(
      'lsof',
      ['-nP', '-p', pids.join(','), '-a', '-iTCP', '-sTCP:LISTEN'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
    );
    return out.split('\n').filter((l) => l && !l.startsWith('COMMAND'));
  } catch (err) {
    if (err && err.code === 'ENOENT') throw new Error('lsof not available');
    const stdout = err.stdout ? String(err.stdout) : '';
    if (err.status === 1) {
      return stdout.split('\n').filter((l) => l && !l.startsWith('COMMAND'));
    }
    throw new Error(`lsof failed: ${err.message || err}`);
  }
}

class McpClient {
  constructor(child) {
    this.child = child;
    this.buf = Buffer.alloc(0);
    this.pending = new Map();
    this.stdout = '';
    this.stderr = '';
    child.stderr.on('data', (d) => {
      this.stderr += d.toString();
    });
    child.stdout.on('data', (d) => this.onData(d));
  }
  onData(chunk) {
    this.stdout += chunk.toString();
    this.buf = Buffer.concat([this.buf, chunk]);
    while (true) {
      const nl = this.buf.indexOf(0x0a);
      if (nl === -1) return;
      const line = this.buf.subarray(0, nl).toString('utf8').replace(/\r$/, '');
      this.buf = this.buf.subarray(nl + 1);
      if (!line.trim()) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (msg.id != null && this.pending.has(msg.id)) {
        this.pending.get(msg.id)(msg);
        this.pending.delete(msg.id);
      }
    }
  }
  send(obj) {
    this.child.stdin.write(JSON.stringify(obj) + '\n');
  }
  call(method, params, timeoutMs = 15000) {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`timeout ${method}`)), timeoutMs);
      this.pending.set(id, (msg) => {
        clearTimeout(t);
        resolve(msg);
      });
      this.send({ jsonrpc: '2.0', id, method, params });
    });
  }
  async close() {
    try {
      this.child.stdin.end();
    } catch {}
    try {
      this.child.kill('SIGTERM');
    } catch {}
    await new Promise((r) => setTimeout(r, 300));
    try {
      this.child.kill('SIGKILL');
    } catch {}
  }
}

function spawnListenerChild() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intune-listen-'));
  const script = path.join(dir, 'listen.mjs');
  fs.writeFileSync(
    script,
    `import net from 'node:net';
const s = net.createServer();
s.listen(0, '127.0.0.1', () => { process.stdout.write('READY\\n'); });
process.stdin.resume();
`
  );
  return spawn(process.execPath, [script], { stdio: ['pipe', 'pipe', 'pipe'] });
}

function spawnGrandchildListener() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'intune-gchild-'));
  const listen = path.join(dir, 'listen.mjs');
  const parent = path.join(dir, 'parent.mjs');
  fs.writeFileSync(
    listen,
    `import net from 'node:net';
const s = net.createServer();
s.listen(0, '127.0.0.1', () => { process.stdout.write('READY\\n'); });
process.stdin.resume();
`
  );
  fs.writeFileSync(
    parent,
    `import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const child = spawn(process.execPath, [path.join(here, 'listen.mjs')], {
  stdio: ['ignore', 'inherit', 'inherit'],
});
child.on('spawn', () => process.stdout.write('PARENT\\n'));
process.stdin.resume();
`
  );
  return spawn(process.execPath, [parent], { stdio: ['pipe', 'pipe', 'pipe'] });
}

function waitLine(stream, match, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => reject(new Error(`timeout waiting for ${match}`)), timeoutMs);
    const onData = (d) => {
      buf += d.toString();
      if (buf.includes(match)) {
        clearTimeout(t);
        stream.off('data', onData);
        resolve(buf);
      }
    };
    stream.on('data', onData);
  });
}

async function killTree(child) {
  if (!child || !child.pid) return;
  const pids = descendantPids(child.pid);
  for (const pid of pids.reverse()) {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {}
  }
}

function firstPartyHttpScan() {
  const src = path.join(SERVER_DIR, 'src', 'intune_mcp');
  const hits = [];
  const re = /streamable[-_]http|mcp\.server\.sse|FastMCP|transport=["']sse["']|transport=["']http["']/i;
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(abs);
      else if (ent.name.endsWith('.py')) {
        const text = fs.readFileSync(abs, 'utf8');
        if (re.test(text)) hits.push(path.relative(src, abs));
      }
    }
  };
  walk(src);
  return hits;
}

function fixtureHygiene() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'intune-hygiene-home-'));
  fs.chmodSync(home, 0o700);
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(home, '.grok'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(home, '.claude.json'), '{}\n');
  fs.writeFileSync(path.join(home, '.codex', 'config.toml'), 'x = 1\n');
  fs.writeFileSync(path.join(home, '.grok', 'config.toml'), 'x = 1\n');
  const evidence = fs.mkdtempSync(path.join(os.tmpdir(), 'intune-hygiene-ev-'));
  const surfaces = defaultHygieneSurfaces({
    home,
    workspaceRoot: SERVER_DIR,
    evidenceDir: evidence,
    registrationName: 'intune-ro',
    preRegistration: true,
  });
  const clean = scanHygiene({
    surfaces,
    needles: fragments(SENTINEL),
    skipDirNames: new Set(HYGIENE_SKIP_DIR_NAMES),
  });
  fs.writeFileSync(path.join(home, '.codex', 'config.toml'), `secret = "${SENTINEL}"\n`);
  const dirty = scanHygiene({
    surfaces,
    needles: fragments(SENTINEL),
    skipDirNames: new Set(HYGIENE_SKIP_DIR_NAMES),
  });
  return { clean, dirty };
}

async function stage1({ rebaseline = false, reason = '' } = {}) {
  const result = {
    as_of_utc: new Date().toISOString(),
    stage: 1,
    ok: false,
    production_env_opened: false,
    production_cli_executed: false,
    sampled_observation_disclaimer:
      'Listening-socket inspection is sampled observation, not proof that no transient listener existed.',
    expected_remote_hosts: [...EXPECTED_REMOTE_HOSTS],
    gates: {},
    lifecycle: {},
  };

  result.gates.production_env = {
    exists: fs.existsSync(PROD_ENV),
    opened: false,
    note: 'stage 1 does not open it',
    ok: true,
  };

  chmodDir700(PROD_CONFIG);
  chmodDir700(BASELINE_DIR);
  chmodDir700(path.join(PROD_CONFIG, 'evidence'));

  const activePath = path.join(BASELINE_DIR, 'active.json');
  const candidatePath = path.join(BASELINE_DIR, 'candidate.json');
  const installedCli = path.join(BIN_DIR, 'intune-mcp-launch.mjs');
  const installedCore = path.join(BIN_DIR, 'm365-mcp-launch-core.mjs');
  const pairExists = fs.existsSync(installedCli) || fs.existsSync(installedCore);
  const activeExists = fs.existsSync(activePath);

  result.lifecycle.bootstrap = {
    active_exists: activeExists,
    installed_pair_exists: pairExists,
    rebaseline,
    reason: reason || null,
  };
  if (rebaseline) {
    if (!reason) {
      writeEvidence(result);
      die('--rebaseline requires --reason <string>');
    }
    result.gates.bootstrap = { ok: true, rebaseline: true, reason };
  } else if (activeExists || pairExists) {
    result.gates.bootstrap = {
      ok: false,
      reason: 'active baseline or installed launcher pair already exists',
    };
    writeEvidence(result);
    die('bootstrap refused: active baseline or installed launcher pair exists');
  } else {
    result.gates.bootstrap = { ok: true, credential_free: true };
  }

  const ktd16BeforePath = path.join(
    PROD_CONFIG,
    'evidence',
    '2026-09-10-u6',
    'ktd16-snapshot-before-wu6.json'
  );
  const ktd16Now = snapshotEntraProtected({ workspaceRoot: WORKSPACE_ROOT });
  let ktd16Ok = true;
  let ktd16Compare = { ok: true, diff_count: 0 };
  if (fs.existsSync(ktd16BeforePath)) {
    const before = JSON.parse(fs.readFileSync(ktd16BeforePath, 'utf8'));
    ktd16Compare = compareEntraProtected(before, ktd16Now);
    ktd16Ok = ktd16Compare.ok === true && (ktd16Compare.diff_count || 0) === 0;
  }
  result.gates.ktd16 = { ok: ktd16Ok, compare: ktd16Compare, opened_entra_env: false };
  if (!ktd16Ok) {
    writeEvidence(result);
    die('KTD16 protected Entra artifacts changed');
  }

  const manifest = computeIntegrityManifest(WORKSPACE_ROOT, DESC);
  if (!manifest.files['tools/intune-mcp-gate.mjs']) {
    result.gates.candidate = { ok: false, reason: 'gate file not in hash scope' };
    writeEvidence(result);
    die('gate file missing from integrity manifest');
  }
  if (!manifest.files['tools/m365-mcp-kernel/src/m365_mcp_kernel/graph_client.py']) {
    result.gates.candidate = { ok: false, reason: 'kernel not in hash scope' };
    writeEvidence(result);
    die('kernel missing from integrity manifest');
  }
  const candidate = {
    state: 'candidate',
    recordedAt: new Date().toISOString(),
    workspaceRoot: WORKSPACE_ROOT,
    files: manifest.files,
    interpreter: manifest.interpreter,
  };
  writeCandidate(BASELINE_DIR, candidate);
  appendHistory(BASELINE_DIR, {
    event: 'candidate',
    gate: manifest.files['tools/intune-mcp-gate.mjs'],
    launcher: manifest.files['tools/intune-mcp-launch.mjs'],
    core: manifest.files['tools/m365-mcp-launch-core.mjs'],
  });
  result.lifecycle.candidate = { path: candidatePath, ok: true };
  result.gates.candidate = { ok: true };

  const pytestLink = ensurePytestLink();
  const pytestPython = path.join(pytestLink, '.venv', 'bin', 'python');
  const pytest = await runCaptured(
    pytestPython,
    ['-I', '-B', '-m', 'pytest', '-q', '--tb=line', `--rootdir=${pytestLink}`, path.join(pytestLink, 'tests')],
    { cwd: pytestLink, timeoutMs: 180000 }
  );
  result.gates.u2_pytest = {
    ok: pytest.code === 0,
    code: pytest.code,
    tail: (pytest.stdout + pytest.stderr).slice(-800),
  };
  if (!result.gates.u2_pytest.ok) {
    writeEvidence(result);
    die('U2 pytest failed');
  }

  const u3core = await runCaptured(process.execPath, ['--test', 'm365-mcp-launch-core.test.mjs'], {
    cwd: HERE,
    timeoutMs: 60000,
  });
  const u3cli = await runCaptured(process.execPath, ['--test', 'intune-mcp-launch.test.mjs'], {
    cwd: HERE,
    timeoutMs: 30000,
  });
  result.gates.u3_tests = {
    ok: u3core.code === 0 && u3cli.code === 0,
    core_code: u3core.code,
    cli_code: u3cli.code,
    tail: (u3core.stdout + u3core.stderr + u3cli.stdout + u3cli.stderr).slice(-800),
  };
  if (!result.gates.u3_tests.ok) {
    writeEvidence(result);
    die('U3 launcher tests failed');
  }

  const verifyCfg = makeFixtureConfig({
    baseline: candidate,
    env: SENTINEL_ENV,
    envFileName: DESC.envFileName,
  });
  const { error: verifyErr, stderr: verifyStderr } = captureStderr(() =>
    runLauncher({
      configDir: verifyCfg,
      descriptor: DESC,
      workspaceRoot: WORKSPACE_ROOT,
      spawnImpl: () => ({ on() {} }),
      wait: false,
    })
  );
  result.gates.verify_candidate_as_active = {
    ok: !verifyErr,
    stderr_has_sentinel: blobHasSecret(verifyStderr, SENTINEL),
  };
  if (verifyErr) {
    result.gates.verify_candidate_as_active.message = verifyErr.message;
    writeEvidence(result);
    die(`candidate failed verify as active: ${verifyErr.message}`);
  }

  const missingCfg = makeFixtureConfig({
    baseline: candidate,
    env: SENTINEL_ENV,
    envFileName: DESC.envFileName,
  });
  fs.unlinkSync(path.join(missingCfg, DESC.envFileName));
  const { error: missErr, stderr: missStderr } = captureStderr(() =>
    runLauncher({
      configDir: missingCfg,
      descriptor: DESC,
      workspaceRoot: WORKSPACE_ROOT,
      spawnImpl: () => {
        throw new Error('must not spawn');
      },
      wait: false,
    })
  );
  result.gates.verify_refusal_missing_env = {
    ok: missErr instanceof LaunchError && /missing env file/.test(missStderr),
    spawned: false,
  };
  if (!result.gates.verify_refusal_missing_env.ok) {
    writeEvidence(result);
    die('verify refusal (missing env) did not fail closed');
  }
  result.lifecycle.verified = { ok: true };

  const hygiene = fixtureHygiene();
  result.gates.fixture_hygiene = {
    ok:
      hygiene.clean.ok === true &&
      hygiene.clean.statuses.grok_log === 'not_created_pre_registration' &&
      hygiene.dirty.ok === false &&
      hygiene.dirty.hits > 0,
    clean_statuses: hygiene.clean.statuses,
    dirty_hits: hygiene.dirty.hits,
  };
  if (!result.gates.fixture_hygiene.ok) {
    writeEvidence(result);
    die('fixture hygiene gate failed');
  }

  let promoted = false;
  try {
    chmodDir700(BIN_DIR);
    const installNames = ['intune-mcp-launch.mjs', 'm365-mcp-launch-core.mjs'];
    if (fs.existsSync(activePath)) {
      atomicWriteFile(path.join(BASELINE_DIR, 'previous.json'), fs.readFileSync(activePath), 0o600);
      for (const rel of installNames) {
        const src = path.join(BIN_DIR, rel);
        if (fs.existsSync(src)) {
          atomicWriteFile(path.join(BIN_DIR, `previous-${rel}`), fs.readFileSync(src), 0o500);
        }
      }
    }
    atomicWriteFile(activePath, JSON.stringify({ ...candidate, state: 'active' }, null, 2), 0o600);
    atomicWriteFile(installedCli, fs.readFileSync(LAUNCHER_SRC), 0o500);
    atomicWriteFile(installedCore, fs.readFileSync(CORE_SRC), 0o500);
    fs.chmodSync(installedCli, 0o500);
    fs.chmodSync(installedCore, 0o500);
    promoted = true;
    appendHistory(BASELINE_DIR, { event: 'promote', active: activePath, bin: BIN_DIR });
    result.lifecycle.promote = { ok: true, active: activePath, bin: BIN_DIR };

    const bytesCli = fs.readFileSync(installedCli).equals(fs.readFileSync(LAUNCHER_SRC));
    const bytesCore = fs.readFileSync(installedCore).equals(fs.readFileSync(CORE_SRC));
    result.gates.installed_bytes = { ok: bytesCli && bytesCore, cli: bytesCli, core: bytesCore };
    if (!result.gates.installed_bytes.ok) throw new Error('installed launcher bytes != workspace source');

    const cliSrc = fs.readFileSync(installedCli, 'utf8');
    result.gates.installed_cli_static = staticCliCheck(cliSrc);
    if (!result.gates.installed_cli_static.ok) {
      throw new Error(`installed CLI wiring: ${result.gates.installed_cli_static.reasons.join('; ')}`);
    }

    const coreMod = await import(pathToFileURL(installedCore).href);
    const confirmCfg = makeFixtureConfig({
      baseline: { ...candidate, state: 'active' },
      env: SENTINEL_ENV,
      envFileName: DESC.envFileName,
    });
    const confirmManifest = coreMod.computeIntegrityManifest(WORKSPACE_ROOT, DESC);
    const filesMatch = JSON.stringify(confirmManifest.files) === JSON.stringify(candidate.files);
    const interpMatch =
      JSON.stringify(confirmManifest.interpreter) === JSON.stringify(candidate.interpreter);
    result.gates.confirm_hash_via_installed_core = { ok: filesMatch && interpMatch };
    if (!result.gates.confirm_hash_via_installed_core.ok) {
      throw new Error('installed core manifest != promoted baseline');
    }

    const { error: cMiss, stderr: cMissErr } = captureStderr(() =>
      coreMod.runLauncher({
        configDir: missingCfg,
        descriptor: DESC,
        workspaceRoot: WORKSPACE_ROOT,
        spawnImpl: () => {
          throw new Error('must not spawn');
        },
        wait: false,
      })
    );
    result.gates.confirm_refusal_via_installed_core = {
      ok: cMiss instanceof coreMod.LaunchError && /missing env file/.test(cMissErr),
    };
    if (!result.gates.confirm_refusal_via_installed_core.ok) {
      throw new Error('installed core missing-env refusal failed');
    }

    let child;
    const { error: spawnErr, stderr: spawnStderr } = captureStderr(() => {
      child = coreMod.runLauncher({
        configDir: confirmCfg,
        descriptor: DESC,
        workspaceRoot: WORKSPACE_ROOT,
        wait: false,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    });
    if (spawnErr) throw spawnErr;
    const client = new McpClient(child);
    const listenSamples = [];
    try {
      const init = await client.call('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'intune-gate', version: '0.1' },
      });
      client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      const listed = await client.call('tools/list', {});
      const names = (listed.result?.tools || []).map((t) => t.name);
      result.gates.initialize = {
        ok: Boolean(init.result?.serverInfo || init.result?.server_info),
        serverInfo: init.result?.serverInfo || init.result?.server_info || null,
      };
      result.gates.allowlist = {
        ok: setsEqual(names, R5_TOOLS),
        advertised: names,
        expected: [...R5_TOOLS],
      };
      result.gates.allowlist_negative = {
        ok: !setsEqual([...R5_TOOLS, 'get_weather'], R5_TOOLS),
        extra_tool: 'get_weather',
      };
      if (!result.gates.initialize.ok) throw new Error('initialize failed');
      if (!result.gates.allowlist.ok) throw new Error('tools/list does not equal gate R5_TOOLS');
      if (!result.gates.allowlist_negative.ok) throw new Error('allowlist negative probe broken');

      for (let i = 0; i < 4; i += 1) {
        const pids = descendantPids(child.pid);
        listenSamples.push({ n: i, pids, listeners: listeningSockets(pids) });
        await new Promise((r) => setTimeout(r, 150));
      }
      const anyListen = listenSamples.some((s) => s.listeners.length > 0);
      result.gates.stdio_sampled_listeners = {
        ok: !anyListen,
        sampled: true,
        not_continuity_proof: true,
        observations: listenSamples.map((s) => ({
          n: s.n,
          pid_count: s.pids.length,
          listener_count: s.listeners.length,
          listeners: s.listeners.slice(0, 8),
        })),
      };
      if (anyListen) throw new Error('process tree had a listening TCP socket (sampled)');

      const combined = `${client.stdout}\n${client.stderr}\n${spawnStderr}\n${JSON.stringify(init)}\n${JSON.stringify(listed)}`;
      result.gates.sentinel = {
        ok: !blobHasSecret(combined, SENTINEL),
        argv_is_python_dash_m: true,
        fragments_checked: fragments(SENTINEL),
      };
      if (!result.gates.sentinel.ok) throw new Error('sentinel or fragment appeared in captures');
    } finally {
      await client.close();
    }

    const httpHits = firstPartyHttpScan();
    result.gates.stdio_construction = {
      ok: httpHits.length === 0,
      http_transport_hits: httpHits,
      entry: 'python -I -B -m intune_mcp / run_stdio',
    };
    if (!result.gates.stdio_construction.ok) {
      throw new Error(`first-party HTTP/SSE transport reference: ${httpHits.join(',')}`);
    }

    const ast = await runCaptured(
      VENV_PYTHON,
      [
        '-I',
        '-B',
        '-c',
        'from pathlib import Path; from m365_mcp_kernel.network_policy import check_tree; v=check_tree(Path("src/intune_mcp")); raise SystemExit(0 if not v else 1)',
      ],
      { cwd: SERVER_DIR, timeoutMs: 20000 }
    );
    const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'intune-ast-'));
    const toolsDir = path.join(fixtureDir, 'tools');
    fs.mkdirSync(toolsDir);
    fs.copyFileSync(
      path.join(SERVER_DIR, 'tests', 'fixtures', 'import_bypass', 'tool_socket.py'),
      path.join(toolsDir, 'tool_socket.py')
    );
    fs.copyFileSync(
      path.join(SERVER_DIR, 'tests', 'fixtures', 'import_bypass', 'tool_dynamic_import.py'),
      path.join(toolsDir, 'tool_dynamic.py')
    );
    fs.copyFileSync(
      path.join(SERVER_DIR, 'tests', 'fixtures', 'import_bypass', 'tool_httpx.py'),
      path.join(toolsDir, 'tool_httpx.py')
    );
    const astFix = await runCaptured(
      VENV_PYTHON,
      [
        '-I',
        '-B',
        '-c',
        `from pathlib import Path; from m365_mcp_kernel.network_policy import check_tree; v=check_tree(Path(${JSON.stringify(fixtureDir)})); msgs=[x.message for x in v]; assert any("socket" in m for m in msgs), msgs; assert any("__import__" in m for m in msgs), msgs; assert any("httpx" in m for m in msgs), msgs`,
      ],
      { cwd: SERVER_DIR, timeoutMs: 20000 }
    );
    result.gates.ast_import_policy = {
      ok: ast.code === 0 && astFix.code === 0,
      real_tree: ast.code === 0,
      socket_dynamic_httpx_fixtures_caught: astFix.code === 0,
      fixture_stderr: astFix.stderr.slice(0, 400),
    };
    if (!result.gates.ast_import_policy.ok) throw new Error('AST import policy failed');

    const listenChild = spawnListenerChild();
    await waitLine(listenChild.stdout, 'READY');
    const listenHit = listeningSockets(descendantPids(listenChild.pid));
    await killTree(listenChild);
    result.gates.listener_fixture_child = {
      ok: listenHit.length > 0,
      sampled: true,
      caught: listenHit.slice(0, 4),
    };
    if (!result.gates.listener_fixture_child.ok) {
      throw new Error('listener fixture child was not observed (gate would false-pass)');
    }

    const gchild = spawnGrandchildListener();
    await waitLine(gchild.stdout, 'READY');
    const gHit = listeningSockets(descendantPids(gchild.pid));
    await killTree(gchild);
    result.gates.listener_fixture_grandchild = {
      ok: gHit.length > 0,
      sampled: true,
      caught: gHit.slice(0, 4),
    };
    if (!result.gates.listener_fixture_grandchild.ok) {
      throw new Error('listening grandchild was not observed (gate would false-pass)');
    }

    const selfHash = computeIntegrityManifest(WORKSPACE_ROOT, DESC);
    result.gates.self_hash_vs_active = {
      ok:
        JSON.stringify(selfHash.files) === JSON.stringify(candidate.files) &&
        JSON.stringify(selfHash.interpreter) === JSON.stringify(candidate.interpreter),
    };
    if (!result.gates.self_hash_vs_active.ok) {
      throw new Error('tree drifted after candidate recording');
    }

    result.lifecycle.confirmed = { ok: true };
    result.ok = Object.values(result.gates).every((g) => g && g.ok !== false);
    if (!result.ok) throw new Error('one or more stage 1 gates not ok');
  } catch (err) {
    result.ok = false;
    result.error = err && err.message ? err.message : String(err);
    if (promoted) {
      if (rebaseline && fs.existsSync(path.join(BASELINE_DIR, 'previous.json'))) {
        rollbackLaterPromotion({
          baselineDir: BASELINE_DIR,
          binDir: BIN_DIR,
          installNames: ['intune-mcp-launch.mjs', 'm365-mcp-launch-core.mjs'],
        });
        result.lifecycle.rollback = { kind: 'later-promotion' };
      } else {
        rollbackFirstPromotion({
          baselineDir: BASELINE_DIR,
          binDir: BIN_DIR,
          installNames: ['intune-mcp-launch.mjs', 'm365-mcp-launch-core.mjs'],
        });
        result.lifecycle.rollback = { kind: 'first-promotion' };
      }
    }
    writeEvidence(result);
    die(result.error);
  }

  const evidence = writeEvidence(result);
  appendHistory(BASELINE_DIR, { event: 'confirm', ok: true, evidence });
  process.stdout.write(
    JSON.stringify(
      {
        ok: true,
        stage: 1,
        evidence: path.relative(os.userInfo().homedir, evidence),
        allowlist: result.gates.allowlist.advertised,
        bootstrap: 'candidate→verified→active→confirmed',
        production_env_opened: false,
        production_cli_executed: false,
        ktd16: 'unchanged',
      },
      null,
      2
    ) + '\n'
  );
}

function parseArgs(argv) {
  const out = { stage: 1, hygiene: false, rebaseline: false, reason: '' };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--hygiene') out.hygiene = true;
    else if (a === '--rebaseline') out.rebaseline = true;
    else if (a === '--reason') out.reason = argv[++i] || '';
    else if (a.startsWith('--reason=')) out.reason = a.slice('--reason='.length);
    else if (a === '--stage') out.stage = Number(argv[++i] || 1);
    else if (a.startsWith('--stage=')) out.stage = Number(a.slice('--stage='.length));
    else if (a === '--stage2') out.stage = 2;
  }
  return out;
}

function rfc1918orLocalIp(ip) {
  const n = ip.split('.').map(Number);
  const multicast = n.length === 4 && n[0] >= 224 && n[0] <= 239;
  const cgnat = n.length === 4 && n[0] === 100 && n[1] >= 64 && n[1] <= 127;
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('169.254.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
    ip.startsWith('fe80:') ||
    ip.startsWith('fd') ||
    ip.startsWith('fc') ||
    multicast ||
    cgnat
  );
}

async function resolveMicrosoftIps() {
  const hosts = [...EXPECTED_REMOTE_HOSTS];
  const map = {};
  for (const host of hosts) {
    const ips = new Set();
    for (const family of [4, 6]) {
      try {
        const recs = await dns.lookup(host, { all: true, family });
        for (const r of recs) if (r.address) ips.add(r.address);
      } catch {}
    }
    try {
      const recs = await dns.lookup(host, { all: true });
      for (const r of recs) if (r.address) ips.add(r.address);
    } catch {}
    map[host] = [...ips];
  }
  return map;
}

function extractObservedRemotes(tcpdumpText, pids) {
  const pidSet = new Set((pids || []).map(String));
  const ips = new Set();
  const re = /(?:^|\s)(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?/g;
  for (const line of String(tcpdumpText || '').split('\n')) {
    if (!line || line.startsWith('tcpdump:')) continue;
    if (pidSet.size) {
      const proc = line.match(/proc [^:]+:(\d+)/);
      if (!proc || !pidSet.has(proc[1])) continue;
    }
    let m;
    const found = [];
    const r = new RegExp(re);
    while ((m = r.exec(line))) found.push(m[1]);
    for (const ip of found) {
      if (!rfc1918orLocalIp(ip)) ips.add(ip);
    }
  }
  return [...ips];
}

function startPktapCapture(pcapPath) {
  process.stdout.write('SUDO NEEDED — Jan type password on this tab\n');
  const askpass = '/tmp/intune-mcp-sudo-askpass.sh';
  fs.writeFileSync(
    askpass,
    `#!/bin/bash
osascript <<'APPLESCRIPT'
tell application "System Events"
  activate
  set r to display dialog "SUDO NEEDED — Jan type macOS password for Intune MCP PKTAP capture" default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with title "intune-mcp-gate"
  return text returned of r
end tell
APPLESCRIPT
`
  );
  fs.chmodSync(askpass, 0o700);
  const env = { ...process.env, SUDO_ASKPASS: askpass };
  return spawn('sudo', ['-A', 'tcpdump', '-i', 'pktap,all', '-k', '-nn', '-w', pcapPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env,
  });
}

function waitCaptureReady(child, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => reject(new Error('tcpdump readiness timeout')), timeoutMs);
    const onErr = (d) => {
      buf += d.toString();
      if (/listening on/i.test(buf)) {
        clearTimeout(t);
        child.stderr.off('data', onErr);
        resolve(buf);
      }
    };
    child.stderr.on('data', onErr);
    child.on('error', (err) => {
      clearTimeout(t);
      reject(err);
    });
    child.on('exit', (code) => {
      if (code) {
        clearTimeout(t);
        reject(new Error(`tcpdump exited before ready: ${code} ${buf}`));
      }
    });
  });
}

async function stopCapture(child) {
  if (!child || !child.pid) return;
  try {
    execFileSync('sudo', ['-n', 'kill', String(child.pid)], { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch {
    try {
      child.kill('SIGINT');
    } catch {}
  }
  await new Promise((r) => setTimeout(r, 800));
}

function readPcapText(pcapPath) {
  try {
    return execFileSync('sudo', ['-n', 'tcpdump', '-nn', '-k', '-r', pcapPath], {
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    return `${err.stdout || ''}\n${err.stderr || ''}`;
  }
}

function mcpToolText(msg) {
  const r = (msg && (msg.result || msg.error)) || {};
  return JSON.stringify(r);
}

function parseProbePayload(msg) {
  const result = msg && msg.result;
  if (!result) return {};
  if (result.structuredContent && typeof result.structuredContent === 'object') {
    return result.structuredContent;
  }
  if (Array.isArray(result.content)) {
    for (const block of result.content) {
      if (block && typeof block.text === 'string') {
        try {
          return JSON.parse(block.text);
        } catch {}
      }
    }
  }
  return result;
}

function collectionMeta(payload) {
  const arrays = [];
  for (const v of Object.values(payload || {})) {
    if (Array.isArray(v)) arrays.push(v.length);
  }
  const n = arrays.length ? Math.max(...arrays) : 0;
  return {
    complete: payload && payload.complete === true,
    truncated: payload && payload.truncated === true,
    items_scanned: payload && payload.items_scanned,
    empty_collection: n === 0,
  };
}

async function decodeTokenRoles(fileEnv) {
  const tenant = String(fileEnv.INTUNE_TENANT_ID).trim();
  const client = String(fileEnv.INTUNE_CLIENT_ID).trim();
  const secret = String(fileEnv.INTUNE_CLIENT_SECRET).trim();
  const body = new URLSearchParams({
    client_id: client,
    client_secret: secret,
    grant_type: 'client_credentials',
    scope: 'https://graph.microsoft.com/.default',
  });
  const res = await fetch(
    `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`,
    { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }
  );
  if (!res.ok) {
    return { ok: false, error: `token_http_${res.status}` };
  }
  const json = await res.json();
  const token = json.access_token;
  if (!token || typeof token !== 'string') return { ok: false, error: 'no_access_token' };
  const parts = token.split('.');
  if (parts.length < 2) return { ok: false, error: 'not_jwt' };
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return { ok: false, error: 'jwt_payload' };
  }
  const roles = Array.isArray(payload.roles) ? [...payload.roles].map(String).sort() : [];
  const expected = [...EXPECTED_ROLES].sort();
  const extra = roles.filter((r) => !expected.includes(r));
  const missing = expected.filter((r) => !roles.includes(r));
  return { ok: extra.length === 0 && missing.length === 0, roles, extra, missing };
}

function productionHygiene(secret) {
  const surfaces = defaultHygieneSurfaces({
    workspaceRoot: WORKSPACE_ROOT,
    evidenceDir: path.join(PROD_CONFIG, 'evidence'),
    registrationName: 'intune-ro',
    preRegistration: true,
  });
  return scanHygiene({
    surfaces,
    needles: fragments(secret),
    skipDirNames: new Set(HYGIENE_SKIP_DIR_NAMES),
  });
}

async function stage2() {
  EVID_DIR = EVID_DIR_STAGE2;
  chmodDir700(PROD_CONFIG);
  chmodDir700(path.dirname(EVID_DIR));
  chmodDir700(EVID_DIR);
  const result = {
    as_of_utc: new Date().toISOString(),
    stage: 2,
    ok: false,
    ktd10_branch: 'unlicensed',
    expected_remote_hosts: [...EXPECTED_REMOTE_HOSTS],
    sampled_observation_disclaimer:
      'Egress is an observed run plus audited architecture, not a network control. Listening-socket inspection is not used as the egress pass.',
    gates: {},
  };

  const corePath = path.join(BIN_DIR, 'm365-mcp-launch-core.mjs');
  if (!fs.existsSync(corePath)) die('installed core missing; stage 1 promote required');
  const coreMod = await import(pathToFileURL(corePath).href);

  let prodEnv;
  try {
    prodEnv = readEnvFile(PROD_CONFIG, DESC);
  } catch (err) {
    die(`cannot read production env via core: ${err.message}`);
  }
  try {
    validateCredentials(prodEnv, DESC);
  } catch (err) {
    die(`production env failed credential validation: ${err.message}`);
  }
  const realSecret = prodEnv.INTUNE_CLIENT_SECRET;
  const childEnv = buildChildEnv(prodEnv, process.env, DESC);

  const rolesGate = await decodeTokenRoles(prodEnv);
  result.gates.token_roles = {
    ok: rolesGate.ok === true,
    roles: rolesGate.roles || [],
    extra: rolesGate.extra || [],
    missing: rolesGate.missing || [],
    error: rolesGate.error || null,
  };
  if (!result.gates.token_roles.ok) {
    writeEvidence(result);
    die('token roles != four Intune application grants');
  }

  result.gates.ktd4_inventory = {
    ok: true,
    recorded: '2026-09-21',
    source: 'docs/plans/2026-09-21-intune-mcp-ro-u1-release.md',
    graph_application_roles: [...EXPECTED_ROLES],
    delegated: false,
    user_consent: 'none',
    directory_roles_assigned_on_enterprise_app: 0,
    note: 'Sanitized U1 inventory; not a self-read of the app.',
  };

  const pcapPath = path.join(EVID_DIR, 'pktap.pcap');
  let capture;
  let captureReady = '';
  try {
    capture = startPktapCapture(pcapPath);
    captureReady = await waitCaptureReady(capture);
    result.gates.capture_ready = { ok: true, note: captureReady.trim().slice(0, 200) };
  } catch (err) {
    result.gates.capture_ready = { ok: false, error: err.message };
    result.gates.egress = { ok: false, inconclusive: true, reason: 'capture failed to start' };
    writeEvidence(result);
    die('stage 2 capture failed to start — fail/inconclusive, never pass');
  }

  let liveChild;
  const treePids = new Set();
  const clientHolder = { client: null };
  try {
    liveChild = coreMod.runLauncher({
      configDir: PROD_CONFIG,
      descriptor: DESC,
      wait: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    for (const p of descendantPids(liveChild.pid)) treePids.add(p);
    const client = new McpClient(liveChild);
    clientHolder.client = client;
    const init = await client.call('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'intune-gate-stage2', version: '0.1' },
    });
    client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    result.gates.initialize = {
      ok: Boolean(init.result?.serverInfo || init.result?.server_info),
      serverInfo: init.result?.serverInfo || init.result?.server_info || null,
    };
    if (!result.gates.initialize.ok) throw new Error('initialize failed');

    const listed = await client.call('tools/list', {});
    const names = (listed.result?.tools || []).map((t) => t.name);
    result.gates.allowlist = {
      ok: setsEqual(names, R5_TOOLS),
      advertised: names,
      expected: [...R5_TOOLS],
    };
    if (!result.gates.allowlist.ok) throw new Error('tools/list does not equal gate R5_TOOLS');

    const probes = [];
    for (const probe of PROBE_MATRIX) {
      const msg = await client.call(
        'tools/call',
        { name: probe.name, arguments: probe.arguments },
        120000
      );
      const text = mcpToolText(msg);
      if (blobHasSecret(text, realSecret) || blobHasSecret(client.stderr, realSecret)) {
        throw new Error(`production secret in live MCP capture (${probe.name})`);
      }
      const failed = Boolean(msg.error) || Boolean(msg.result?.isError);
      const payload = parseProbePayload(msg);
      const meta = collectionMeta(payload);
      const ok = !failed;
      probes.push({
        name: probe.name,
        ok,
        empty_collection: meta.empty_collection,
        complete: meta.complete,
        truncated: meta.truncated,
        items_scanned: meta.items_scanned,
        note: meta.empty_collection
          ? 'empty-but-valid collection; not proof of data-bearing behavior'
          : 'non-empty sanitized payload',
      });
      if (!ok) throw new Error(`probe failed: ${probe.name}`);
    }
    result.gates.probe_matrix = {
      ok: probes.every((p) => p.ok),
      probes,
    };
    if (!result.gates.probe_matrix.ok) throw new Error('probe matrix failed');

    if (liveChild && liveChild.pid) {
      for (const p of descendantPids(liveChild.pid)) treePids.add(p);
    }
    result.gates.capture_pids = { ok: true, root: liveChild.pid, tree: [...treePids] };
    await client.close();
    liveChild = null;
  } catch (err) {
    result.gates.live_read = { ok: false, error: err.message };
    if (clientHolder.client) await clientHolder.client.close();
    await stopCapture(capture);
    writeEvidence(result);
    die(err.message);
  }

  if (liveChild) {
    await killTree(liveChild);
  }
  await new Promise((r) => setTimeout(r, 500));
  await stopCapture(capture);
  try {
    fs.chmodSync(pcapPath, 0o600);
  } catch {}

  const resolutions1 = await resolveMicrosoftIps();
  const pcapText = readPcapText(pcapPath);
  let remotes = extractObservedRemotes(pcapText, [...treePids]);
  let resolutions = resolutions1;
  let extras = remotes.filter(
    (ip) =>
      !(resolutions1['login.microsoftonline.com'] || []).includes(ip) &&
      !(resolutions1['graph.microsoft.com'] || []).includes(ip)
  );
  if (extras.length) {
    resolutions = await resolveMicrosoftIps();
    extras = remotes.filter(
      (ip) =>
        !(resolutions['login.microsoftonline.com'] || []).includes(ip) &&
        !(resolutions['graph.microsoft.com'] || []).includes(ip)
    );
  }
  const includesToken = (resolutions['login.microsoftonline.com'] || []).some((ip) =>
    remotes.includes(ip)
  );
  const includesGraph = (resolutions['graph.microsoft.com'] || []).some((ip) => remotes.includes(ip));
  const drops = /dropped/i.test(pcapText) || /packets dropped/i.test(captureReady);
  const egressOk =
    remotes.length > 0 && includesToken && includesGraph && extras.length === 0 && !drops;
  result.gates.egress = {
    ok: egressOk,
    inconclusive: !egressOk && remotes.length === 0,
    mechanism: 'sudo tcpdump -i pktap,all -k',
    interfaces: 'pktap,all',
    privilege: 'capture only; launcher/server/gate as user',
    observed_remotes: remotes,
    resolutions,
    includes_token_host: includesToken,
    includes_graph_host: includesGraph,
    extras,
    drops,
    statement:
      'observed run plus audited architecture, not a network control. These are global Microsoft endpoints, not tenant-scoped ones.',
  };
  if (!egressOk) {
    writeEvidence(result);
    die('Microsoft-endpoint-only egress failed or inconclusive — never pass');
  }

  const fixtureEnv = {
    INTUNE_TENANT_ID: prodEnv.INTUNE_TENANT_ID,
    INTUNE_CLIENT_ID: prodEnv.INTUNE_CLIENT_ID,
    INTUNE_CLIENT_SECRET: WRONG_SECRET,
    INTUNE_SECRET_EXPIRES: prodEnv.INTUNE_SECRET_EXPIRES,
    INTUNE_CLIENT_CERTIFICATE_PATH: '',
  };
  const active = JSON.parse(fs.readFileSync(path.join(BASELINE_DIR, 'active.json'), 'utf8'));
  const badCfg = makeFixtureConfig({
    baseline: active,
    env: fixtureEnv,
    envFileName: DESC.envFileName,
  });
  let badChild;
  const { stderr: badLaunchStderr } = captureStderr(() => {
    badChild = coreMod.runLauncher({
      configDir: badCfg,
      descriptor: DESC,
      workspaceRoot: WORKSPACE_ROOT,
      wait: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  });
  const badClient = new McpClient(badChild);
  let badCall = {};
  try {
    await badClient.call('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'intune-gate-401', version: '0.1' },
    });
    badClient.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    badCall = await badClient
      .call('tools/call', { name: 'get_intune_overview', arguments: {} }, 45000)
      .catch((e) => ({ error: { message: e.message } }));
  } finally {
    await badClient.close();
  }
  const badBlob = `${badLaunchStderr}\n${badClient.stdout}\n${badClient.stderr}\n${JSON.stringify(badCall)}`;
  const redactionOk =
    !blobHasSecret(badBlob, realSecret) &&
    !blobHasSecret(badBlob, WRONG_SECRET) &&
    !/error_description/i.test(badBlob) &&
    !/AADSTS[0-9]+/.test(badBlob);
  result.gates.redaction = {
    ok: redactionOk,
    production_env_untouched: true,
    used_fixture_config_dir: true,
    home_override: false,
    real_secret_in_output: blobHasSecret(badBlob, realSecret),
    wrong_secret_in_output: blobHasSecret(badBlob, WRONG_SECRET),
    aadsts_or_error_description: /AADSTS[0-9]+/.test(badBlob) || /error_description/i.test(badBlob),
  };
  if (!redactionOk) {
    writeEvidence(result);
    die('auth-failure redaction gate failed');
  }

  result.gates.falcon_sp_sign_in = {
    ok: false,
    inconclusive: true,
    waived: true,
    mandatory_unlicensed: true,
    reason:
      'Jan skipped Falcon SP ingest/alert for intune-mcp-ro (2026-09-21), same as entra-mcp-ro 2026-09-08. Residual: stolen secret may not page. Do not invent a pass.',
  };

  const hyg = productionHygiene(realSecret);
  result.gates.hygiene = {
    ok: hyg.ok,
    hits: hyg.hits,
    unreadable: hyg.unreadable,
    skipped_dirs: hyg.skipped_dirs,
    statuses: hyg.statuses,
    grok_log: hyg.statuses && hyg.statuses.grok_log,
  };
  if (!hyg.ok) {
    writeEvidence(result);
    die('hygiene scan failed');
  }

  result.ok = Object.values(result.gates).every((g) => g && (g.ok === true || g.inconclusive === true));
  const evidence = writeEvidence(result);
  appendHistory(BASELINE_DIR, {
    event: 'stage2',
    ok: result.ok,
    evidence,
    falcon: result.gates.falcon_sp_sign_in,
  });
  process.stdout.write(
    JSON.stringify(
      {
        ok: result.ok,
        stage: 2,
        evidence: evidence.replace(os.userInfo().homedir, '~'),
        token_roles: result.gates.token_roles.ok,
        probes: result.gates.probe_matrix.probes.map((p) => ({
          name: p.name,
          ok: p.ok,
          empty: p.empty_collection,
        })),
        egress: result.gates.egress.ok,
        redaction: result.gates.redaction.ok,
        hygiene: result.gates.hygiene.ok,
        falcon: 'waived',
        production_cli_executed: false,
        production_env_in_chat: false,
      },
      null,
      2
    ) + '\n'
  );
  if (!result.ok) process.exit(2);
}

const args = parseArgs(process.argv.slice(2));

async function main() {
  if (args.hygiene && args.stage !== 2) {
    const fileEnv = readEnvFile(PROD_CONFIG, DESC);
    const report = productionHygiene(fileEnv.INTUNE_CLIENT_SECRET);
    process.stdout.write(report.ok ? 'pass\n' : 'fail\n');
    if (!report.ok) process.exit(1);
    return;
  }
  if (args.rebaseline) {
    await stage1({ rebaseline: true, reason: args.reason });
    return;
  }
  if (args.stage === 2) {
    await stage2();
    return;
  }
  await stage1();
}

main().catch((err) => {
  die(err && err.message ? err.message : String(err));
});
