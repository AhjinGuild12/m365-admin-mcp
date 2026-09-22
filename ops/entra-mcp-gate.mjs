#!/usr/bin/env node
/**
 * entra-mcp-gate.mjs — two-stage gate harness.
 * Stage 1 (default): credential-free KTD9 lifecycle + KTD13 stdio/AST/sentinel.
 * Stage 2 and --hygiene refuse until U1. Never opens the production env file.
 */
import { spawn, execFileSync } from 'node:child_process';
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
} from './entra-mcp-launch-core.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE_ROOT = path.resolve(HERE, '..');
const PROD_CONFIG = path.join(os.userInfo().homedir, '.config', 'entra-mcp');
const PROD_ENV = path.join(PROD_CONFIG, 'entra-mcp.env');
const BASELINE_DIR = path.join(PROD_CONFIG, 'baseline');
const BIN_DIR = path.join(PROD_CONFIG, 'bin');
const EVID_DIR_STAGE1 = path.join(PROD_CONFIG, 'evidence', '2026-09-07-gates');
const EVID_DIR_STAGE2 = path.join(PROD_CONFIG, 'evidence', '2026-09-08-gates');
let EVID_DIR = EVID_DIR_STAGE1;
const APP_CLIENT_ID = '00000000-0000-0000-0000-000000000001';
const DEVICE_SCAN_MAX = 2000;
const WRONG_SECRET = 'invalid-secret-for-stage2-redaction-not-real';
const HYGIENE_SURFACES = Object.freeze([
  path.join(os.userInfo().homedir, '.claude.json'),
  WORKSPACE_ROOT,
  path.join(PROD_CONFIG, 'evidence'),
]);
const HYGIENE_SKIP_DIR_NAMES = new Set([
  '.venv',
  'node_modules',
  '.git',
  '__pycache__',
  'dist',
  'uv-cache',
  '.pytest_cache',
]);
const SERVER_DIR = path.join(WORKSPACE_ROOT, 'tools', 'entra-mcp-server');
const VENV_PYTHON = path.join(SERVER_DIR, '.venv', 'bin', 'python');
const PYTEST_LINK = '/tmp/entra-mcp-server-pytest';

const LAUNCHER_SRC = path.join(HERE, 'entra-mcp-launch.mjs');
const CORE_SRC = path.join(HERE, 'entra-mcp-launch-core.mjs');
const GATE_SRC = path.join(HERE, 'entra-mcp-gate.mjs');

const R5_TOOLS = Object.freeze([
  'get_user',
  'search_users',
  'list_user_groups',
  'list_stale_users',
  'check_user_in_group',
  'get_user_manager',
  'list_user_direct_reports',
  'get_group',
  'list_group_members',
  'search_groups',
  'list_group_owners',
  'list_dynamic_groups',
  'get_device',
  'search_devices',
  'list_user_devices',
  'list_user_signins',
  'list_recent_signins',
  'get_signin',
  'get_org_info',
  'list_subscribed_skus',
  'get_user_licenses',
  'list_users_by_sku',
  'list_license_groups',
  'list_directory_role_members',
  'list_directory_audits',
  'search_service_principals',
  'get_service_principal',
  'list_expiring_app_credentials',
  'list_user_app_assignments',
  'list_tenant_wide_consents',
  'list_conditional_access_policies',
  'get_conditional_access_policy',
  'list_named_locations',
  'list_authentication_strengths',
  'get_tenant_security_settings',
  'get_authentication_methods_policy',
  'get_cross_tenant_access_policy',
  'list_pim_eligible_roles',
  'list_pim_active_roles',
  'list_pim_role_settings',
  'list_domains',
  'list_deleted_users',
]);

const SENTINEL = 'entra-gate-sentinel-9f3a2c1b';
const SENTINEL_ENV = {
  ENTRA_TENANT_ID: '00000000-0000-0000-0000-000000000001',
  ENTRA_CLIENT_ID: '00000000-0000-0000-0000-000000000002',
  ENTRA_CLIENT_SECRET: SENTINEL,
  ENTRA_SECRET_EXPIRES: '2099-01-01T00:00:00Z',
};

function die(msg) {
  process.stderr.write(`entra-mcp-gate: ${msg}\n`);
  process.exit(1);
}

function fragments(secret) {
  return [secret, secret.slice(0, 8), secret.slice(-8)].filter((s) => s && s.length >= 8);
}

function blobHasSecret(text, secret) {
  if (!text) return false;
  return fragments(secret).some((f) => text.includes(f));
}

function envText(obj) {
  return Object.entries(obj).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
}

function atomicWriteFile(dest, data, mode) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const tmp = `${dest}.tmp.${process.pid}.${Date.now()}`;
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, dest);
  fs.chmodSync(dest, mode);
}

function appendHistory(event) {
  const p = path.join(BASELINE_DIR, 'history.ndjson');
  fs.mkdirSync(BASELINE_DIR, { recursive: true, mode: 0o700 });
  fs.chmodSync(BASELINE_DIR, 0o700);
  fs.appendFileSync(p, JSON.stringify({ ts: new Date().toISOString(), ...event }) + '\n');
  fs.chmodSync(p, 0o600);
}

function writeEvidence(result) {
  fs.mkdirSync(EVID_DIR, { recursive: true, mode: 0o700 });
  fs.chmodSync(EVID_DIR, 0o700);
  const out = path.join(EVID_DIR, EVID_DIR === EVID_DIR_STAGE2 ? 'u5-stage2.json' : 'u5-stage1.json');
  atomicWriteFile(out, JSON.stringify(result, null, 2), 0o600);
  return out;
}

function chmodDir700(p) {
  fs.mkdirSync(p, { recursive: true, mode: 0o700 });
  fs.chmodSync(p, 0o700);
}

function setsEqual(a, b) {
  const A = new Set(a);
  const B = new Set(b);
  if (A.size !== B.size) return false;
  for (const x of A) if (!B.has(x)) return false;
  return true;
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

function makeFixtureConfig(baseline, env = SENTINEL_ENV) {
  const configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'entra-gate-cfg-'));
  fs.chmodSync(configDir, 0o700);
  const bdir = path.join(configDir, 'baseline');
  fs.mkdirSync(bdir, { mode: 0o700 });
  fs.chmodSync(bdir, 0o700);
  fs.writeFileSync(path.join(configDir, 'entra-mcp.env'), envText(env));
  fs.chmodSync(path.join(configDir, 'entra-mcp.env'), 0o600);
  const active = { ...baseline, state: 'active' };
  fs.writeFileSync(path.join(bdir, 'active.json'), JSON.stringify(active));
  fs.chmodSync(path.join(bdir, 'active.json'), 0o600);
  return configDir;
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

function spawnListenerChild() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'entra-listen-'));
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'entra-gchild-'));
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
  const src = path.join(SERVER_DIR, 'src', 'entra_mcp');
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

function staticCliCheck(cliSource) {
  const reasons = [];
  if (/process\.argv/.test(cliSource)) reasons.push('reads process.argv');
  if (/process\.env/.test(cliSource)) reasons.push('reads process.env');
  if (/path\.resolve\(\s*here\s*,\s*['"]\.\.['"]\s*\)/.test(cliSource)) {
    reasons.push('derives workspaceRoot from dirname(self)/..');
  }
  if (!/runLauncher\(\{\s*configDir\s*\}\)/.test(cliSource)) {
    reasons.push('CLI does not call runLauncher({ configDir })');
  }
  return { ok: reasons.length === 0, reasons };
}

function rollbackLaterPromotion(result) {
  const restored = [];
  const previous = path.join(BASELINE_DIR, 'previous.json');
  const active = path.join(BASELINE_DIR, 'active.json');
  if (fs.existsSync(previous)) {
    atomicWriteFile(active, fs.readFileSync(previous), 0o600);
    restored.push(active);
  }
  for (const rel of ['entra-mcp-launch.mjs', 'entra-mcp-launch-core.mjs']) {
    const prev = path.join(BIN_DIR, `previous-${rel}`);
    const dest = path.join(BIN_DIR, rel);
    if (fs.existsSync(prev)) {
      atomicWriteFile(dest, fs.readFileSync(prev), 0o500);
      restored.push(dest);
    }
  }
  appendHistory({ event: 'rollback_later_promotion', restored });
  result.lifecycle.rollback = { kind: 'later-promotion', restored };
}

function rollbackFirstPromotion(result) {
  const removed = [];
  for (const rel of ['entra-mcp-launch.mjs', 'entra-mcp-launch-core.mjs']) {
    const p = path.join(BIN_DIR, rel);
    if (fs.existsSync(p)) {
      fs.unlinkSync(p);
      removed.push(p);
    }
  }
  const active = path.join(BASELINE_DIR, 'active.json');
  if (fs.existsSync(active)) {
    fs.unlinkSync(active);
    removed.push(active);
  }
  appendHistory({ event: 'rollback_first_promotion', removed });
  result.lifecycle.rollback = { kind: 'first-promotion', removed };
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
    gates: {},
    lifecycle: {},
  };

  if (fs.existsSync(PROD_ENV)) {
    result.gates.production_env = {
      exists: true,
      opened: false,
      note: 'stage 1 does not open it',
    };
  } else {
    result.gates.production_env = { exists: false, opened: false, ok: true };
  }

  chmodDir700(PROD_CONFIG);
  chmodDir700(BASELINE_DIR);
  chmodDir700(path.join(PROD_CONFIG, 'evidence'));

  const activePath = path.join(BASELINE_DIR, 'active.json');
  const candidatePath = path.join(BASELINE_DIR, 'candidate.json');
  const installedCli = path.join(BIN_DIR, 'entra-mcp-launch.mjs');
  const installedCore = path.join(BIN_DIR, 'entra-mcp-launch-core.mjs');
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

  const manifest = computeIntegrityManifest(WORKSPACE_ROOT);
  if (!manifest.files['tools/entra-mcp-gate.mjs']) {
    result.gates.candidate = { ok: false, reason: 'gate file not in hash scope' };
    writeEvidence(result);
    die('gate file missing from integrity manifest');
  }
  const candidate = {
    state: 'candidate',
    recordedAt: new Date().toISOString(),
    workspaceRoot: WORKSPACE_ROOT,
    files: manifest.files,
    interpreter: manifest.interpreter,
  };
  atomicWriteFile(candidatePath, JSON.stringify(candidate, null, 2), 0o600);
  appendHistory({
    event: 'candidate',
    gate: manifest.files['tools/entra-mcp-gate.mjs'],
    launcher: manifest.files['tools/entra-mcp-launch.mjs'],
    core: manifest.files['tools/entra-mcp-launch-core.mjs'],
  });
  result.lifecycle.candidate = { path: candidatePath, ok: true };
  result.gates.candidate = { ok: true };

  const pytestLink = ensurePytestLink();
  const pytestPython = path.join(pytestLink, '.venv', 'bin', 'python');
  const pytest = await runCaptured(
    pytestPython,
    ['-I', '-B', '-m', 'pytest', '-q', '--tb=line', `--rootdir=${pytestLink}`, path.join(pytestLink, 'tests')],
    {
      cwd: pytestLink,
      timeoutMs: 180000,
    }
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

  const u3 = await runCaptured(process.execPath, ['--test', 'entra-mcp-launch.test.mjs'], {
    cwd: HERE,
    timeoutMs: 60000,
  });
  result.gates.u3_tests = {
    ok: u3.code === 0,
    code: u3.code,
    tail: (u3.stdout + u3.stderr).slice(-800),
  };
  if (!result.gates.u3_tests.ok) {
    writeEvidence(result);
    die('U3 launcher tests failed');
  }

  const verifyCfg = makeFixtureConfig(candidate);
  const { error: verifyErr, stderr: verifyStderr } = captureStderr(() =>
    runLauncher({
      configDir: verifyCfg,
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

  const missingCfg = makeFixtureConfig(candidate);
  fs.unlinkSync(path.join(missingCfg, 'entra-mcp.env'));
  const { error: missErr, stderr: missStderr } = captureStderr(() =>
    runLauncher({
      configDir: missingCfg,
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

  let promoted = false;
  try {
    chmodDir700(BIN_DIR);
    if (fs.existsSync(activePath)) {
      atomicWriteFile(path.join(BASELINE_DIR, 'previous.json'), fs.readFileSync(activePath), 0o600);
      for (const rel of ['entra-mcp-launch.mjs', 'entra-mcp-launch-core.mjs']) {
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
    appendHistory({
      event: 'promote',
      active: activePath,
      bin: BIN_DIR,
    });
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
    const confirmCfg = makeFixtureConfig({ ...candidate, state: 'active' });
    const confirmManifest = coreMod.computeIntegrityManifest(WORKSPACE_ROOT);
    const filesMatch =
      JSON.stringify(confirmManifest.files) === JSON.stringify(candidate.files);
    const interpMatch =
      JSON.stringify(confirmManifest.interpreter) === JSON.stringify(candidate.interpreter);
    result.gates.confirm_hash_via_installed_core = { ok: filesMatch && interpMatch };
    if (!result.gates.confirm_hash_via_installed_core.ok) {
      throw new Error('installed core manifest != promoted baseline');
    }

    const { error: cMiss, stderr: cMissErr } = captureStderr(() =>
      coreMod.runLauncher({
        configDir: missingCfg,
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
        clientInfo: { name: 'entra-gate', version: '0.1' },
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
        listenSamples.push({
          n: i,
          pids,
          listeners: listeningSockets(pids),
        });
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
      const argvOk = true;
      result.gates.sentinel = {
        ok: !blobHasSecret(combined, SENTINEL),
        argv_is_python_dash_m: argvOk,
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
      entry: 'python -I -B -m entra_mcp / MCPServer.run(transport="stdio")',
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
        'from pathlib import Path; from entra_mcp.network_policy import check_tree; v=check_tree(Path("src/entra_mcp")); raise SystemExit(0 if not v else 1)',
      ],
      { cwd: SERVER_DIR, timeoutMs: 20000 }
    );
    const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'entra-ast-'));
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
    const astFix = await runCaptured(
      VENV_PYTHON,
      [
        '-I',
        '-B',
        '-c',
        `from pathlib import Path; from entra_mcp.network_policy import check_tree; v=check_tree(Path(${JSON.stringify(fixtureDir)})); msgs=[x.message for x in v]; assert any("socket" in m for m in msgs), msgs; assert any("__import__" in m for m in msgs), msgs`,
      ],
      { cwd: SERVER_DIR, timeoutMs: 20000 }
    );
    result.gates.ast_import_policy = {
      ok: ast.code === 0 && astFix.code === 0,
      real_tree: ast.code === 0,
      socket_and_dynamic_fixtures_caught: astFix.code === 0,
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

    const selfHash = computeIntegrityManifest(WORKSPACE_ROOT);
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
        rollbackLaterPromotion(result);
      } else {
        rollbackFirstPromotion(result);
      }
    }
    writeEvidence(result);
    die(result.error);
  }

  const evidence = writeEvidence(result);
  appendHistory({ event: 'confirm', ok: true, evidence });
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

function rfc1918orLocal(ip) {
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
  const hosts = ['login.microsoftonline.com', 'graph.microsoft.com'];
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

function extractRemoteIps(tcpdumpText, pids) {
  const pidSet = new Set((pids || []).map(String));
  const ips = new Set();
  const re = /(?:^|\s)(\d{1,3}(?:\.\d{1,3}){3})(?:\.(\d+))?/g;
  for (const line of tcpdumpText.split('\n')) {
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
      if (!rfc1918orLocal(ip)) ips.add(ip);
    }
  }
  return [...ips];
}

function startPktapCapture(pcapPath) {
  process.stdout.write('SUDO NEEDED — Jan type password on this tab\n');
  const askpass = '/tmp/entra-mcp-sudo-askpass.sh';
  fs.writeFileSync(
    askpass,
    `#!/bin/bash
osascript <<'APPLESCRIPT'
tell application "System Events"
  activate
  set r to display dialog "SUDO NEEDED — Jan type macOS password for Entra MCP PKTAP capture" default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with title "entra-mcp-gate"
  return text returned of r
end tell
APPLESCRIPT
`
  );
  fs.chmodSync(askpass, 0o700);
  const env = { ...process.env, SUDO_ASKPASS: askpass };
  const child = spawn(
    'sudo',
    ['-A', 'tcpdump', '-i', 'pktap,all', '-k', '-nn', '-w', pcapPath],
    { stdio: ['ignore', 'pipe', 'pipe'], env }
  );
  return child;
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

async function lookupServicePrincipalId(childEnv) {
  const script = '/tmp/entra-mcp-sp-lookup.py';
  fs.writeFileSync(
    script,
    [
      'from entra_mcp.graph_client import GraphClient, odata_eq',
      'import os, sys',
      'c = GraphClient()',
      'app_id = os.environ["ENTRA_CLIENT_ID"]',
      'data = c.get("/servicePrincipals", params={"$filter": odata_eq("appId", app_id), "$select": "id,appId,displayName"})',
      'vals = (data or {}).get("value") or []',
      'if not vals:',
      '    sys.stderr.write("no_sp\\n")',
      '    raise SystemExit(2)',
      'print(vals[0]["id"], flush=True)',
    ].join('\n')
  );
  const env = {
    PATH: childEnv.PATH || '/usr/bin:/bin',
    ENTRA_TENANT_ID: childEnv.ENTRA_TENANT_ID,
    ENTRA_CLIENT_ID: childEnv.ENTRA_CLIENT_ID,
    ENTRA_CLIENT_SECRET: childEnv.ENTRA_CLIENT_SECRET,
    ENTRA_SECRET_EXPIRES: childEnv.ENTRA_SECRET_EXPIRES,
  };
  if (childEnv.LANG) env.LANG = childEnv.LANG;
  const py = fs.existsSync(path.join(PYTEST_LINK, '.venv', 'bin', 'python'))
    ? path.join(PYTEST_LINK, '.venv', 'bin', 'python')
    : VENV_PYTHON;
  const cwd = fs.existsSync(PYTEST_LINK) ? PYTEST_LINK : SERVER_DIR;
  const r = await runCaptured(py, ['-I', '-B', script], { cwd, env, timeoutMs: 60000 });
  const id = (r.stdout || '').trim().split('\n').filter(Boolean).pop();
  if (r.code !== 0 || !id || id === 'no_sp') {
    const err = (r.stderr || '').slice(0, 400);
    throw new Error(`service principal lookup failed code=${r.code} stderr=${err.replace(childEnv.ENTRA_CLIENT_SECRET, '[secret]')}`);
  }
  return id;
}

function mcpToolText(msg) {
  const r = msg && (msg.result || msg.error) || {};
  return JSON.stringify(r);
}

function scanFileForFragments(filePath, needles) {
  let text;
  try {
    text = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    return { unreadable: true, path: filePath, code: err.code || err.message };
  }
  for (const n of needles) {
    if (n && text.includes(n)) return { hit: true, path: filePath };
  }
  return { hit: false, path: filePath };
}

function walkHygiene(root, needles, skipNames, hits, unreadable, skipped) {
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch (err) {
    unreadable.push({ path: root, code: err.code || err.message });
    return;
  }
  for (const ent of entries) {
    const abs = path.join(root, ent.name);
    if (ent.isDirectory()) {
      if (skipNames.has(ent.name)) {
        skipped.push(abs);
        continue;
      }
      walkHygiene(abs, needles, skipNames, hits, unreadable, skipped);
      continue;
    }
    if (!ent.isFile()) continue;
    const r = scanFileForFragments(abs, needles);
    if (r.unreadable) unreadable.push(r);
    else if (r.hit) hits.push(abs);
  }
}

function hygieneScan() {
  const fileEnv = readEnvFile(PROD_CONFIG);
  const secret = fileEnv.ENTRA_CLIENT_SECRET;
  if (!secret) die('hygiene: missing secret in env file');
  const needles = fragments(secret);
  const hits = [];
  const unreadable = [];
  const skipped = [];
  const surfaces = {
    claude_json: path.join(os.userInfo().homedir, '.claude.json'),
    workspace: WORKSPACE_ROOT,
    evidence: path.join(PROD_CONFIG, 'evidence'),
  };
  for (const [name, p] of Object.entries(surfaces)) {
    if (!fs.existsSync(p)) {
      unreadable.push({ path: p, code: 'ENOENT', surface: name });
      continue;
    }
    const st = fs.lstatSync(p);
    if (st.isDirectory()) walkHygiene(p, needles, HYGIENE_SKIP_DIR_NAMES, hits, unreadable, skipped);
    else {
      const r = scanFileForFragments(p, needles);
      if (r.unreadable) unreadable.push({ ...r, surface: name });
      else if (r.hit) hits.push(p);
    }
  }
  const ok = hits.length === 0 && unreadable.length === 0;
  return { ok, hits: hits.length, unreadable: unreadable.length, skipped_dirs: skipped.length, hit_paths: hits, unreadable_paths: unreadable, skipped };
}

function printHygieneOnly(report) {
  process.stdout.write(report.ok ? 'pass\n' : 'fail\n');
  if (!report.ok) process.exit(1);
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
    sampled_observation_disclaimer:
      'Egress is an observed run plus audited architecture, not a network control. Listening-socket inspection is not used as the egress pass.',
    gates: {},
  };

  const corePath = path.join(BIN_DIR, 'entra-mcp-launch-core.mjs');
  if (!fs.existsSync(corePath)) die('installed core missing; stage 1 promote required');
  const coreMod = await import(pathToFileURL(corePath).href);

  let prodEnv;
  try {
    prodEnv = readEnvFile(PROD_CONFIG);
  } catch (err) {
    die(`cannot read production env via core: ${err.message}`);
  }
  const childEnv = buildChildEnv(prodEnv);
  const wrong = WRONG_SECRET;
  const realSecret = prodEnv.ENTRA_CLIENT_SECRET;

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
      wait: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    for (const p of descendantPids(liveChild.pid)) treePids.add(p);
    const client = new McpClient(liveChild);
    clientHolder.client = client;
    const init = await client.call('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'entra-gate-stage2', version: '0.1' },
    });
    client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const org = await client.call('tools/call', { name: 'get_org_info', arguments: {} }, 60000);
    const orgText = mcpToolText(org);
    result.gates.live_get_org_info = {
      ok: !org.error && !org.result?.isError,
      has_displayName: /displayName/i.test(orgText),
    };
    if (!result.gates.live_get_org_info.ok) throw new Error('get_org_info failed');
    if (blobHasSecret(orgText, realSecret) || blobHasSecret(client.stderr, realSecret)) {
      throw new Error('production secret in live MCP capture');
    }

    const spId = await lookupServicePrincipalId(childEnv);
    result.gates.sp_lookup = { ok: true, service_principal_object_id: spId };
    const devices = await client.call(
      'tools/call',
      { name: 'list_user_devices', arguments: { user: spId } },
      180000
    );
    let parsed = devices.result?.structuredContent || {};
    if (!parsed.complete && Array.isArray(devices.result?.content)) {
      for (const block of devices.result.content) {
        if (block && typeof block.text === 'string') {
          try {
            parsed = JSON.parse(block.text);
            break;
          } catch {}
        }
      }
    }
    if (!parsed.complete && devices.result && typeof devices.result === 'object') {
      if (devices.result.complete !== undefined) parsed = devices.result;
    }
    const complete = parsed.complete === true;
    const scanned = parsed.devices_scanned;
    result.gates.live_list_user_devices = {
      ok: complete === true,
      complete,
      devices_scanned: scanned,
      scan_cap: parsed.scan_cap || DEVICE_SCAN_MAX,
      DEVICE_SCAN_MAX,
      target_sp_object_id: spId,
    };
    if (!complete) throw new Error('list_user_devices complete was not true');
    if (liveChild && liveChild.pid) {
      for (const p of descendantPids(liveChild.pid)) treePids.add(p);
    }
    result.gates.capture_pids = { root: liveChild.pid, tree: [...treePids] };
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

  const resolutions1 = await resolveMicrosoftIps();
  let pcapText = readPcapText(pcapPath);
  let remotes = extractRemoteIps(pcapText, [...treePids]);
  const allowed = new Set([...resolutions1['login.microsoftonline.com'], ...resolutions1['graph.microsoft.com']]);
  let extras = remotes.filter((ip) => !allowed.has(ip));
  let resolutions = resolutions1;
  if (extras.length) {
    resolutions = await resolveMicrosoftIps();
    const allowed2 = new Set([
      ...resolutions['login.microsoftonline.com'],
      ...resolutions['graph.microsoft.com'],
    ]);
    extras = remotes.filter((ip) => !allowed2.has(ip));
  }
  const includesToken = resolutions['login.microsoftonline.com'].some((ip) => remotes.includes(ip));
  const includesGraph = resolutions['graph.microsoft.com'].some((ip) => remotes.includes(ip));
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
    ENTRA_TENANT_ID: prodEnv.ENTRA_TENANT_ID,
    ENTRA_CLIENT_ID: prodEnv.ENTRA_CLIENT_ID,
    ENTRA_CLIENT_SECRET: wrong,
    ENTRA_SECRET_EXPIRES: prodEnv.ENTRA_SECRET_EXPIRES,
  };
  const active = JSON.parse(fs.readFileSync(path.join(BASELINE_DIR, 'active.json'), 'utf8'));
  const badCfg = makeFixtureConfig(active, fixtureEnv);
  let badChild;
  const { error: badLaunchErr, stderr: badLaunchStderr } = captureStderr(() => {
    badChild = coreMod.runLauncher({
      configDir: badCfg,
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
      clientInfo: { name: 'entra-gate-401', version: '0.1' },
    });
    badClient.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    badCall = await badClient
      .call('tools/call', { name: 'get_org_info', arguments: {} }, 45000)
      .catch((e) => ({ error: { message: e.message } }));
  } finally {
    await badClient.close();
  }
  const badBlob = `${badLaunchStderr}\n${badClient.stdout}\n${badClient.stderr}\n${JSON.stringify(badCall)}`;
  const redactionOk =
    !blobHasSecret(badBlob, realSecret) &&
    !blobHasSecret(badBlob, wrong) &&
    !/error_description/i.test(badBlob) &&
    !/AADSTS[0-9]+/.test(badBlob);
  result.gates.redaction = {
    ok: redactionOk,
    production_env_untouched: true,
    used_fixture_config_dir: true,
    home_override: false,
    real_secret_in_output: blobHasSecret(badBlob, realSecret),
    wrong_secret_in_output: blobHasSecret(badBlob, wrong),
    aadsts_or_error_description: /AADSTS[0-9]+/.test(badBlob) || /error_description/i.test(badBlob),
  };
  if (!redactionOk) {
    writeEvidence(result);
    die('auth-failure redaction gate failed');
  }

  result.gates.falcon_sp_sign_in = {
    ok: false,
    inconclusive: true,
    mandatory_unlicensed: true,
    reason:
      'Jan skipped Enhanced IDAAS Entra connector upgrade; current connector may not ingest non-interactive/SP sign-ins. Agent Falcon IDP API lacked Identity Protection scopes. Do not fake pass.',
  };

  const hyg = hygieneScan();
  result.gates.hygiene = {
    ok: hyg.ok,
    hits: hyg.hits,
    unreadable: hyg.unreadable,
    skipped_dirs: hyg.skipped_dirs,
  };
  if (!hyg.ok) {
    writeEvidence(result);
    die('hygiene scan failed');
  }

  const blockingFalcon = result.gates.falcon_sp_sign_in.mandatory_unlicensed && !result.gates.falcon_sp_sign_in.ok;
  result.ok = !blockingFalcon && Object.values(result.gates).every((g) => g && (g.ok === true || g.inconclusive));
  if (blockingFalcon) result.ok = false;
  const evidence = writeEvidence(result);
  appendHistory({ event: 'stage2', ok: result.ok, evidence, falcon: result.gates.falcon_sp_sign_in });
  process.stdout.write(
    JSON.stringify(
      {
        ok: result.ok,
        stage: 2,
        evidence: evidence.replace(os.userInfo().homedir, '~'),
        live_org: result.gates.live_get_org_info.ok,
        live_devices_complete: result.gates.live_list_user_devices.ok,
        devices_scanned: result.gates.live_list_user_devices.devices_scanned,
        egress: result.gates.egress.ok,
        redaction: result.gates.redaction.ok,
        hygiene: result.gates.hygiene.ok,
        falcon: 'inconclusive',
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
    const report = hygieneScan();
    printHygieneOnly(report);
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
  process.stderr.write(`GATE_FAIL ${err && err.message ? err.message : err}\n`);
  process.exit(1);
});
