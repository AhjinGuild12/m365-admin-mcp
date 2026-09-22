#!/usr/bin/env node
/**
 * spo-admin-mcp-gate.mjs — stage 1 is credential-free.
 * --smoke calls get_tenant_sharing_settings through the installed launcher.
 * The production env is opened only by the shared core. Its value is never printed.
 */
import { spawn, execFileSync } from 'node:child_process';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  LaunchError,
  buildChildEnv,
  computeIntegrityManifest,
  readEnvFile,
  runLauncher,
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
  fragments,
  makeFixtureConfig,
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
const PROD_CONFIG = path.join(os.userInfo().homedir, '.config', 'spo-admin-mcp');
const PROD_ENV = path.join(PROD_CONFIG, 'spo-admin-mcp.env');
const BASELINE_DIR = path.join(PROD_CONFIG, 'baseline');
const BIN_DIR = path.join(PROD_CONFIG, 'bin');
const EVID_DIR = path.join(PROD_CONFIG, 'evidence', '2026-09-22-gates');
const SERVER_DIR = path.join(WORKSPACE_ROOT, 'tools', 'spo-admin-mcp-server');
const VENV_PYTHON = path.join(SERVER_DIR, '.venv', 'bin', 'python');
const PYTEST_LINK = '/tmp/spo-admin-mcp-server-pytest';
const LAUNCHER_SRC = path.join(HERE, 'spo-admin-mcp-launch.mjs');
const CORE_SRC = path.join(HERE, 'm365-mcp-launch-core.mjs');
const INSTALL_NAMES = ['spo-admin-mcp-launch.mjs', 'm365-mcp-launch-core.mjs'];

const DESC = Object.freeze({
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
});

const P0_TOOLS = Object.freeze([
  'get_tenant_sharing_settings',
  'get_tenant_access_settings',
  'get_tenant_site_creation_settings',
  'get_tenant_settings',
  'list_site_usage',
  'get_site_usage',
  'get_site_usage_summary',
]);

const SENTINEL = 'spo-gate-sentinel-9f3a2c1b';
const SENTINEL_ENV = {
  SPO_ADMIN_TENANT_ID: '00000000-0000-0000-0000-000000000001',
  SPO_ADMIN_CLIENT_ID: '00000000-0000-0000-0000-000000000002',
  SPO_ADMIN_CLIENT_SECRET: SENTINEL,
  SPO_ADMIN_SECRET_EXPIRES: '2099-01-01T00:00:00Z',
  SPO_ADMIN_CLIENT_CERTIFICATE_PATH: '',
};

function die(msg) {
  process.stderr.write(`spo-admin-mcp-gate: ${msg}\n`);
  process.exit(1);
}

function writeEvidence(name, result) {
  chmodDir700(EVID_DIR);
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
  try {
    const st = fs.lstatSync(PYTEST_LINK);
    if (st.isSymbolicLink() && fs.realpathSync(PYTEST_LINK) === fs.realpathSync(SERVER_DIR)) {
      return PYTEST_LINK;
    }
    fs.unlinkSync(PYTEST_LINK);
  } catch {}
  fs.symlinkSync(SERVER_DIR, PYTEST_LINK);
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
    const out = execFileSync('lsof', ['-nP', '-p', pids.join(','), '-a', '-iTCP', '-sTCP:LISTEN'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return out.split('\n').filter((line) => line && !line.startsWith('COMMAND'));
  } catch (err) {
    if (err && err.code === 'ENOENT') throw new Error('lsof not available');
    const stdout = err.stdout ? String(err.stdout) : '';
    if (err.status === 1) return stdout.split('\n').filter((line) => line && !line.startsWith('COMMAND'));
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
  call(method, params, timeoutMs = 20000) {
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'spo-listen-'));
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'spo-gchild-'));
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
const child = spawn(process.execPath, [path.join(here, 'listen.mjs')], { stdio: ['ignore', 'inherit', 'inherit'] });
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
  for (const pid of descendantPids(child.pid).reverse()) {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {}
  }
}

function firstPartyHttpScan() {
  const src = path.join(SERVER_DIR, 'src', 'spo_admin_mcp');
  const hits = [];
  const re = /streamable[-_]http|mcp\.server\.sse|FastMCP|transport=["']sse["']|transport=["']http["']/i;
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(abs);
      else if (ent.name.endsWith('.py') && re.test(fs.readFileSync(abs, 'utf8'))) {
        hits.push(path.relative(src, abs));
      }
    }
  };
  walk(src);
  return hits;
}

function fixtureHygiene() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'spo-hygiene-home-'));
  fs.chmodSync(home, 0o700);
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(home, '.grok'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(home, '.claude.json'), '{}\n');
  fs.writeFileSync(path.join(home, '.codex', 'config.toml'), 'x = 1\n');
  fs.writeFileSync(path.join(home, '.grok', 'config.toml'), 'x = 1\n');
  const evidence = fs.mkdtempSync(path.join(os.tmpdir(), 'spo-hygiene-ev-'));
  const surfaces = defaultHygieneSurfaces({
    home,
    workspaceRoot: SERVER_DIR,
    evidenceDir: evidence,
    registrationName: 'spo-admin-ro',
    preRegistration: true,
  });
  const clean = scanHygiene({
    surfaces,
    needles: fragments(SENTINEL),
    skipDirNames: new Set(['.venv', 'node_modules', '.git', '__pycache__', 'uv-cache', '.pytest_cache']),
  });
  fs.writeFileSync(path.join(home, '.codex', 'config.toml'), `secret = "${SENTINEL}"\n`);
  const dirty = scanHygiene({
    surfaces,
    needles: fragments(SENTINEL),
    skipDirNames: new Set(['.venv', 'node_modules', '.git', '__pycache__', 'uv-cache', '.pytest_cache']),
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
  const installedCli = path.join(BIN_DIR, 'spo-admin-mcp-launch.mjs');
  const installedCore = path.join(BIN_DIR, 'm365-mcp-launch-core.mjs');
  const pairExists = fs.existsSync(installedCli) || fs.existsSync(installedCore);
  const activeExists = fs.existsSync(activePath);
  result.lifecycle.bootstrap = { active_exists: activeExists, installed_pair_exists: pairExists, rebaseline };
  if (rebaseline) {
    if (!reason) {
      writeEvidence('u5-stage1.json', result);
      die('--rebaseline requires --reason <string>');
    }
    result.gates.bootstrap = { ok: true, rebaseline: true, reason };
  } else if (activeExists || pairExists) {
    result.gates.bootstrap = { ok: false, reason: 'active baseline or installed launcher pair already exists' };
    writeEvidence('u5-stage1.json', result);
    die('bootstrap refused: active baseline or installed launcher pair exists');
  } else {
    result.gates.bootstrap = { ok: true, credential_free: true };
  }

  const beforePath = path.join(PROD_CONFIG, 'evidence', '2026-09-22-u6', 'ktd16-snapshot-before-wu6.json');
  const now = snapshotEntraProtected({ workspaceRoot: WORKSPACE_ROOT });
  const compare = compareEntraProtected(JSON.parse(fs.readFileSync(beforePath, 'utf8')), now);
  result.gates.ktd16 = { ok: compare.ok === true && (compare.diffs || []).length === 0, diffs: compare.diffs || [] };
  if (!result.gates.ktd16.ok) {
    writeEvidence('u5-stage1.json', result);
    die('KTD16 protected Entra artifacts changed');
  }

  const manifest = computeIntegrityManifest(WORKSPACE_ROOT, DESC);
  if (!manifest.files['tools/spo-admin-mcp-gate.mjs']) die('gate file missing from integrity manifest');
  const candidate = {
    state: 'candidate',
    recordedAt: new Date().toISOString(),
    workspaceRoot: WORKSPACE_ROOT,
    files: manifest.files,
    interpreter: manifest.interpreter,
  };
  writeCandidate(BASELINE_DIR, candidate);
  result.gates.candidate = { ok: true };

  const pytestLink = ensurePytestLink();
  const pytest = await runCaptured(
    path.join(pytestLink, '.venv', 'bin', 'python'),
    ['-I', '-B', '-m', 'pytest', '-q', '--tb=line', `--rootdir=${pytestLink}`, path.join(pytestLink, 'tests')],
    { cwd: pytestLink, timeoutMs: 180000 }
  );
  result.gates.u2_pytest = { ok: pytest.code === 0, code: pytest.code, tail: (pytest.stdout + pytest.stderr).slice(-500) };
  if (!result.gates.u2_pytest.ok) {
    writeEvidence('u5-stage1.json', result);
    die('U2 pytest failed');
  }

  const u3cli = await runCaptured(process.execPath, ['--test', 'spo-admin-mcp-launch.test.mjs'], {
    cwd: HERE,
    timeoutMs: 60000,
  });
  result.gates.u3_tests = { ok: u3cli.code === 0, cli_code: u3cli.code, tail: (u3cli.stdout + u3cli.stderr).slice(-400) };
  if (!result.gates.u3_tests.ok) {
    writeEvidence('u5-stage1.json', result);
    die('U3 launcher tests failed');
  }

  const verifyCfg = makeFixtureConfig({ baseline: candidate, env: SENTINEL_ENV, envFileName: DESC.envFileName });
  const { error: verifyErr, stderr: verifyStderr } = captureStderr(() =>
    runLauncher({
      configDir: verifyCfg,
      descriptor: DESC,
      workspaceRoot: WORKSPACE_ROOT,
      spawnImpl: () => ({ on() {} }),
      wait: false,
    })
  );
  result.gates.verify_candidate_as_active = { ok: !verifyErr, stderr_has_sentinel: blobHasSecret(verifyStderr, SENTINEL) };
  if (verifyErr) {
    writeEvidence('u5-stage1.json', result);
    die(`candidate failed verify as active: ${verifyErr.message}`);
  }
  const missingCfg = makeFixtureConfig({ baseline: candidate, env: SENTINEL_ENV, envFileName: DESC.envFileName });
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
  };
  if (!result.gates.verify_refusal_missing_env.ok) {
    writeEvidence('u5-stage1.json', result);
    die('verify refusal (missing env) did not fail closed');
  }

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
    writeEvidence('u5-stage1.json', result);
    die('fixture hygiene gate failed');
  }

  let promoted = false;
  try {
    chmodDir700(BIN_DIR);
    if (rebaseline && fs.existsSync(activePath)) {
      atomicWriteFile(path.join(BASELINE_DIR, 'previous.json'), fs.readFileSync(activePath), 0o600);
      for (const rel of INSTALL_NAMES) {
        const src = path.join(BIN_DIR, rel);
        if (fs.existsSync(src)) atomicWriteFile(path.join(BIN_DIR, `previous-${rel}`), fs.readFileSync(src), 0o500);
      }
    }
    atomicWriteFile(activePath, JSON.stringify({ ...candidate, state: 'active' }, null, 2), 0o600);
    atomicWriteFile(installedCli, fs.readFileSync(LAUNCHER_SRC), 0o500);
    atomicWriteFile(installedCore, fs.readFileSync(CORE_SRC), 0o500);
    fs.chmodSync(installedCli, 0o500);
    fs.chmodSync(installedCore, 0o500);
    promoted = true;
    appendHistory(BASELINE_DIR, { event: 'promote', bin: BIN_DIR });
    result.lifecycle.promote = { ok: true };

    const bytesOk =
      fs.readFileSync(installedCli).equals(fs.readFileSync(LAUNCHER_SRC)) &&
      fs.readFileSync(installedCore).equals(fs.readFileSync(CORE_SRC));
    result.gates.installed_bytes = { ok: bytesOk };
    if (!bytesOk) throw new Error('installed launcher bytes != workspace source');
    result.gates.installed_cli_static = staticCliCheck(fs.readFileSync(installedCli, 'utf8'));
    if (!result.gates.installed_cli_static.ok) throw new Error('installed CLI wiring failed');

    const coreMod = await import(pathToFileURL(installedCore).href);
    const confirmManifest = coreMod.computeIntegrityManifest(WORKSPACE_ROOT, DESC);
    result.gates.confirm_hash_via_installed_core = {
      ok:
        JSON.stringify(confirmManifest.files) === JSON.stringify(candidate.files) &&
        JSON.stringify(confirmManifest.interpreter) === JSON.stringify(candidate.interpreter),
    };
    if (!result.gates.confirm_hash_via_installed_core.ok) throw new Error('installed core manifest != promoted baseline');

    const confirmCfg = makeFixtureConfig({
      baseline: { ...candidate, state: 'active' },
      env: SENTINEL_ENV,
      envFileName: DESC.envFileName,
    });
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
    try {
      const init = await client.call('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'spo-gate', version: '0.1' },
      });
      client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      const listed = await client.call('tools/list', {});
      const names = (listed.result?.tools || []).map((tool) => tool.name);
      const info = init.result?.serverInfo || init.result?.server_info || null;
      result.gates.initialize = { ok: info?.name === 'spo-admin-ro', serverInfo: info };
      result.gates.allowlist = { ok: setsEqual(names, P0_TOOLS), advertised: names };
      result.gates.allowlist_negative = { ok: !setsEqual([...P0_TOOLS, 'list_sites'], P0_TOOLS) };
      if (!result.gates.initialize.ok || !result.gates.allowlist.ok || !result.gates.allowlist_negative.ok) {
        throw new Error('initialize or allowlist failed');
      }
      const listenSamples = [];
      for (let i = 0; i < 4; i += 1) {
        const pids = descendantPids(child.pid);
        listenSamples.push(listeningSockets(pids));
        await new Promise((r) => setTimeout(r, 150));
      }
      const anyListen = listenSamples.some((rows) => rows.length > 0);
      result.gates.stdio_sampled_listeners = { ok: !anyListen, sampled: true };
      if (anyListen) throw new Error('process tree had a listening TCP socket');
      const combined = `${client.stdout}\n${client.stderr}\n${spawnStderr}\n${JSON.stringify(init)}\n${JSON.stringify(listed)}`;
      result.gates.sentinel = { ok: !blobHasSecret(combined, SENTINEL) };
      if (!result.gates.sentinel.ok) throw new Error('sentinel appeared in captures');
    } finally {
      await client.close();
    }

    const httpHits = firstPartyHttpScan();
    result.gates.stdio_construction = { ok: httpHits.length === 0, http_transport_hits: httpHits };
    if (!result.gates.stdio_construction.ok) throw new Error('HTTP transport reference in server source');

    const ast = await runCaptured(
      VENV_PYTHON,
      ['-I', '-B', '-c', 'from pathlib import Path; from m365_mcp_kernel.network_policy import check_tree; v=check_tree(Path("src/spo_admin_mcp")); raise SystemExit(0 if not v else 1)'],
      { cwd: SERVER_DIR, timeoutMs: 20000 }
    );
    result.gates.ast_import_policy = { ok: ast.code === 0, code: ast.code };
    if (!result.gates.ast_import_policy.ok) throw new Error('AST import policy failed');

    const listenChild = spawnListenerChild();
    await waitLine(listenChild.stdout, 'READY');
    const listenHit = listeningSockets(descendantPids(listenChild.pid));
    await killTree(listenChild);
    result.gates.listener_fixture_child = { ok: listenHit.length > 0 };
    if (!result.gates.listener_fixture_child.ok) throw new Error('listener fixture child was not observed');

    const gchild = spawnGrandchildListener();
    await waitLine(gchild.stdout, 'READY');
    const gHit = listeningSockets(descendantPids(gchild.pid));
    await killTree(gchild);
    result.gates.listener_fixture_grandchild = { ok: gHit.length > 0 };
    if (!result.gates.listener_fixture_grandchild.ok) throw new Error('listening grandchild was not observed');

    const selfHash = computeIntegrityManifest(WORKSPACE_ROOT, DESC);
    result.gates.self_hash_vs_active = {
      ok:
        JSON.stringify(selfHash.files) === JSON.stringify(candidate.files) &&
        JSON.stringify(selfHash.interpreter) === JSON.stringify(candidate.interpreter),
    };
    if (!result.gates.self_hash_vs_active.ok) throw new Error('tree drifted after candidate recording');
    result.ok = Object.values(result.gates).every((gate) => gate && gate.ok !== false);
    if (!result.ok) throw new Error('one or more stage 1 gates not ok');
  } catch (err) {
    result.ok = false;
    result.error = err && err.message ? err.message : String(err);
    if (promoted) {
      const later = rebaseline && fs.existsSync(path.join(BASELINE_DIR, 'previous.json'));
      if (later) {
        rollbackLaterPromotion({ baselineDir: BASELINE_DIR, binDir: BIN_DIR, installNames: INSTALL_NAMES });
        result.lifecycle.rollback = { kind: 'later-promotion' };
      } else {
        rollbackFirstPromotion({ baselineDir: BASELINE_DIR, binDir: BIN_DIR, installNames: INSTALL_NAMES });
        result.lifecycle.rollback = { kind: 'first-promotion' };
      }
    }
    writeEvidence('u5-stage1.json', result);
    die(result.error);
  }

  const evidence = writeEvidence('u5-stage1.json', result);
  appendHistory(BASELINE_DIR, { event: 'confirm', ok: true });
  process.stdout.write(
    JSON.stringify(
      {
        ok: true,
        stage: 1,
        evidence: evidence.replace(os.userInfo().homedir, '~'),
        allowlist: result.gates.allowlist.advertised,
        server: 'spo-admin-ro',
        production_env_opened: false,
      },
      null,
      2
    ) + '\n'
  );
}

const EXPECTED_REMOTE_HOSTS = Object.freeze([
  'login.microsoftonline.com',
  'graph.microsoft.com',
  'reports.office.com',
]);
const EXPECTED_ROLES = Object.freeze(['Reports.Read.All', 'SharePointTenantSettings.Read.All']);
const PROBE_MATRIX = Object.freeze([
  { name: 'get_tenant_sharing_settings', arguments: {} },
  { name: 'list_site_usage', arguments: { period: 'D7' } },
]);
const WRONG_SECRET = 'invalid-secret-for-stage2-redaction-not-real';

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
  const map = {};
  for (const host of EXPECTED_REMOTE_HOSTS) {
    const ips = new Set();
    try {
      for (const rec of await dns.lookup(host, { all: true })) if (rec.address) ips.add(rec.address);
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
    const found = [];
    const r = new RegExp(re);
    let match;
    while ((match = r.exec(line))) found.push(match[1]);
    for (const ip of found) if (!rfc1918orLocalIp(ip)) ips.add(ip);
  }
  return [...ips];
}

function startPktapCapture(pcapPath) {
  const askpass = '/tmp/spo-admin-mcp-sudo-askpass.sh';
  fs.writeFileSync(
    askpass,
    `#!/bin/bash
osascript <<'APPLESCRIPT'
tell application "System Events"
  activate
  set r to display dialog "SUDO NEEDED — type the Mac password for the SharePoint MCP network capture" default answer "" with hidden answer buttons {"Cancel", "OK"} default button "OK" with title "spo-admin-mcp-gate"
  return text returned of r
end tell
APPLESCRIPT
`
  );
  fs.chmodSync(askpass, 0o700);
  return spawn('sudo', ['-A', 'tcpdump', '-i', 'pktap,all', '-k', '-nn', '-w', pcapPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, SUDO_ASKPASS: askpass },
  });
}

function waitCaptureReady(child, timeoutMs = 45000) {
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
        reject(new Error(`tcpdump exited before ready: ${code}`));
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

function parseProbePayload(msg) {
  const result = msg && msg.result;
  if (!result) return {};
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

async function decodeTokenRoles(fileEnv) {
  const body = new URLSearchParams({
    client_id: String(fileEnv.SPO_ADMIN_CLIENT_ID).trim(),
    client_secret: String(fileEnv.SPO_ADMIN_CLIENT_SECRET).trim(),
    grant_type: 'client_credentials',
    scope: 'https://graph.microsoft.com/.default',
  });
  const res = await fetch(
    `https://login.microsoftonline.com/${encodeURIComponent(String(fileEnv.SPO_ADMIN_TENANT_ID).trim())}/oauth2/v2.0/token`,
    { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }
  );
  if (!res.ok) return { ok: false, error: `token_http_${res.status}` };
  const json = await res.json();
  const token = json.access_token;
  if (!token) return { ok: false, error: 'no_access_token' };
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  const roles = Array.isArray(payload.roles) ? [...payload.roles].map(String).sort() : [];
  const expected = [...EXPECTED_ROLES].sort();
  return {
    ok: roles.length === expected.length && roles.every((role, i) => role === expected[i]),
    roles,
    extra: roles.filter((role) => !expected.includes(role)),
    missing: expected.filter((role) => !roles.includes(role)),
  };
}

async function stage2() {
  const result = {
    as_of_utc: new Date().toISOString(),
    stage: 2,
    ok: false,
    expected_remote_hosts: [...EXPECTED_REMOTE_HOSTS],
    gates: {},
  };
  const corePath = path.join(BIN_DIR, 'm365-mcp-launch-core.mjs');
  if (!fs.existsSync(corePath)) die('installed core missing; stage 1 promote required');
  const coreMod = await import(pathToFileURL(corePath).href);
  const prodEnv = readEnvFile(PROD_CONFIG, DESC);
  validateCredentials(prodEnv, DESC);
  const realSecret = prodEnv.SPO_ADMIN_CLIENT_SECRET;
  buildChildEnv(prodEnv, process.env, DESC);

  const rolesGate = await decodeTokenRoles(prodEnv);
  result.gates.token_roles = {
    ok: rolesGate.ok === true,
    roles: rolesGate.roles || [],
    extra: rolesGate.extra || [],
    missing: rolesGate.missing || [],
    error: rolesGate.error || null,
  };
  if (!result.gates.token_roles.ok) {
    writeEvidence('u5-stage2.json', result);
    die('token roles are not exactly the two approved permissions');
  }
  result.gates.ktd4_inventory = {
    ok: false,
    partial: true,
    portal_graph_application_permissions: [...EXPECTED_ROLES],
    delegated_user_read_seen: false,
    directory_roles: 'not inventoried in this session',
    note: 'Token roles match. A full control-plane inventory was not supplied.',
  };

  const pcapPath = path.join(EVID_DIR, 'pktap.pcap');
  let capture = null;
  let captureReady = '';
  try {
    capture = startPktapCapture(pcapPath);
    captureReady = await waitCaptureReady(capture);
    result.gates.capture_ready = { ok: true };
  } catch (err) {
    result.gates.capture_ready = { ok: false, error: err.message };
    capture = null;
  }

  const treePids = new Set();
  let liveChild = null;
  const clientHolder = { client: null };
  try {
    liveChild = coreMod.runLauncher({
      configDir: PROD_CONFIG,
      descriptor: DESC,
      wait: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    for (const pid of descendantPids(liveChild.pid)) treePids.add(pid);
    const client = new McpClient(liveChild);
    clientHolder.client = client;
    const init = await client.call('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'spo-gate-stage2', version: '0.1' },
    });
    client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const info = init.result?.serverInfo || init.result?.server_info || {};
    result.gates.initialize = { ok: info.name === 'spo-admin-ro', server: info.name || null };
    const listed = await client.call('tools/list', {});
    const names = (listed.result?.tools || []).map((tool) => tool.name);
    result.gates.allowlist = { ok: setsEqual(names, P0_TOOLS) };
    if (!result.gates.initialize.ok || !result.gates.allowlist.ok) throw new Error('initialize or allowlist failed');
    const probes = [];
    for (const probe of PROBE_MATRIX) {
      const msg = await client.call('tools/call', { name: probe.name, arguments: probe.arguments }, 120000);
      const text = JSON.stringify(msg.result || msg.error || {});
      if (blobHasSecret(text, realSecret) || blobHasSecret(client.stderr, realSecret)) {
        throw new Error(`production secret in live capture (${probe.name})`);
      }
      const failed = Boolean(msg.error) || Boolean(msg.result?.isError);
      const payload = parseProbePayload(msg);
      probes.push({
        name: probe.name,
        ok: !failed,
        complete: payload.complete === true,
        truncated: payload.truncated === true,
        items_scanned: payload.items_scanned ?? null,
        identity_visibility: payload.identity_visibility || null,
        report_refresh_date: payload.report_refresh_date || payload.retrieved_at || null,
        sharing_capability: payload.settings ? payload.settings.sharingCapability || null : null,
      });
      if (failed) throw new Error(`probe failed: ${probe.name}`);
    }
    result.gates.probe_matrix = { ok: probes.every((probe) => probe.ok), probes };
    for (const pid of descendantPids(liveChild.pid)) treePids.add(pid);
    await client.close();
    liveChild = null;
  } catch (err) {
    result.gates.live_read = { ok: false, error: err.message };
    if (clientHolder.client) await clientHolder.client.close();
    if (capture) await stopCapture(capture);
    writeEvidence('u5-stage2.json', result);
    die(err.message);
  }
  if (liveChild) await killTree(liveChild);
  if (capture) await stopCapture(capture);
  try {
    fs.chmodSync(pcapPath, 0o600);
  } catch {}

  if (!result.gates.capture_ready?.ok) {
    result.gates.egress = { ok: false, inconclusive: true, reason: 'capture did not start' };
  } else {
    const resolutions = await resolveMicrosoftIps();
    const pcapText = readPcapText(pcapPath);
    const remotes = extractObservedRemotes(pcapText, [...treePids]);
    const includes = {};
    for (const host of EXPECTED_REMOTE_HOSTS) {
      includes[host] = (resolutions[host] || []).some((ip) => remotes.includes(ip));
    }
    const known = new Set(EXPECTED_REMOTE_HOSTS.flatMap((host) => resolutions[host] || []));
    const extras = remotes.filter((ip) => !known.has(ip));
    const drops = /dropped/i.test(pcapText) || /packets dropped/i.test(captureReady);
    const egressOk = remotes.length > 0 && EXPECTED_REMOTE_HOSTS.every((host) => includes[host]) && extras.length === 0 && !drops;
    result.gates.egress = {
      ok: egressOk,
      inconclusive: remotes.length === 0,
      observed_remote_count: remotes.length,
      includes,
      extra_count: extras.length,
      drops,
    };
  }

  const active = JSON.parse(fs.readFileSync(path.join(BASELINE_DIR, 'active.json'), 'utf8'));
  const badCfg = makeFixtureConfig({
    baseline: active,
    env: {
      SPO_ADMIN_TENANT_ID: prodEnv.SPO_ADMIN_TENANT_ID,
      SPO_ADMIN_CLIENT_ID: prodEnv.SPO_ADMIN_CLIENT_ID,
      SPO_ADMIN_CLIENT_SECRET: WRONG_SECRET,
      SPO_ADMIN_SECRET_EXPIRES: prodEnv.SPO_ADMIN_SECRET_EXPIRES,
      SPO_ADMIN_CLIENT_CERTIFICATE_PATH: '',
    },
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
      clientInfo: { name: 'spo-gate-401', version: '0.1' },
    });
    badClient.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    badCall = await badClient
      .call('tools/call', { name: 'get_tenant_sharing_settings', arguments: {} }, 45000)
      .catch((err) => ({ error: { message: err.message } }));
  } finally {
    await badClient.close();
  }
  const badBlob = `${badLaunchStderr}\n${badClient.stdout}\n${badClient.stderr}\n${JSON.stringify(badCall)}`;
  result.gates.redaction = {
    ok:
      !blobHasSecret(badBlob, realSecret) &&
      !blobHasSecret(badBlob, WRONG_SECRET) &&
      !/error_description/i.test(badBlob) &&
      !/AADSTS[0-9]+/.test(badBlob),
  };

  const surfaces = defaultHygieneSurfaces({
    workspaceRoot: WORKSPACE_ROOT,
    evidenceDir: EVID_DIR,
    registrationName: 'spo-admin-ro',
    preRegistration: true,
  });
  const hygiene = scanHygiene({
    surfaces,
    needles: fragments(realSecret),
    skipDirNames: new Set(HYGIENE_SKIP_DIR_NAMES),
  });
  result.gates.hygiene = {
    ok: hygiene.ok === true,
    hits: hygiene.hits,
    grok_log: hygiene.statuses && hygiene.statuses.grok_log,
  };
  result.gates.falcon_sp_sign_in = {
    ok: false,
    waived: false,
    inconclusive: true,
    note: 'No Falcon detection was checked for this service principal. The intune-ro waiver is not inherited.',
  };
  result.ok =
    result.gates.token_roles.ok &&
    result.gates.probe_matrix.ok &&
    result.gates.redaction.ok &&
    result.gates.hygiene.ok &&
    result.gates.egress.ok === true;
  const evidence = writeEvidence('u5-stage2.json', result);
  process.stdout.write(
    JSON.stringify(
      {
        ok: result.ok,
        stage: 2,
        evidence: evidence.replace(os.userInfo().homedir, '~'),
        roles: result.gates.token_roles.roles,
        probes: result.gates.probe_matrix.probes,
        egress: result.gates.egress,
        redaction: result.gates.redaction.ok,
        hygiene: result.gates.hygiene.ok,
        falcon: 'not proven',
        ktd4: 'partial',
      },
      null,
      2
    ) + '\n'
  );
  if (!result.ok) process.exit(2);
}

async function smoke() {
  const installedCore = path.join(BIN_DIR, 'm365-mcp-launch-core.mjs');
  if (!fs.existsSync(installedCore) || !fs.existsSync(path.join(BASELINE_DIR, 'active.json'))) {
    die('stage 1 baseline is not installed');
  }
  const coreMod = await import(pathToFileURL(installedCore).href);
  let child;
  const { error: spawnErr } = captureStderr(() => {
    child = coreMod.runLauncher({
      configDir: PROD_CONFIG,
      descriptor: DESC,
      wait: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  });
  if (spawnErr) die(spawnErr.message);
  const client = new McpClient(child);
  try {
    const init = await client.call('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'spo-smoke', version: '0.1' },
    });
    client.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const listed = await client.call('tools/list', {});
    const names = (listed.result?.tools || []).map((tool) => tool.name);
    const called = await client.call(
      'tools/call',
      { name: 'get_tenant_sharing_settings', arguments: {} },
      45000
    );
    const text = JSON.stringify(called);
    if (blobHasSecret(text, SENTINEL)) die('sentinel in smoke output');
    const info = init.result?.serverInfo || init.result?.server_info || {};
    const content = called.result?.content || called.error || null;
    process.stdout.write(
      JSON.stringify(
        {
          ok: called.result && !called.result.isError && setsEqual(names, P0_TOOLS) && info.name === 'spo-admin-ro',
          server: info.name || null,
          tools: names,
          tool: 'get_tenant_sharing_settings',
          is_error: Boolean(called.result?.isError || called.error),
          content,
        },
        null,
        2
      ) + '\n'
    );
    if (called.error || called.result?.isError || !setsEqual(names, P0_TOOLS)) process.exit(2);
  } finally {
    await client.close();
  }
}

function parseArgs(argv) {
  const out = { stage: 1, rebaseline: false, reason: '', smoke: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--smoke') out.smoke = true;
    else if (arg === '--rebaseline') out.rebaseline = true;
    else if (arg === '--reason') out.reason = argv[++i] || '';
    else if (arg.startsWith('--reason=')) out.reason = arg.slice('--reason='.length);
    else if (arg === '--stage2' || arg === '--stage=2') out.stage = 2;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const main = args.smoke ? smoke() : args.stage === 2 ? stage2() : stage1({ rebaseline: args.rebaseline, reason: args.reason });
main.catch((err) => die(err && err.message ? err.message : String(err)));
