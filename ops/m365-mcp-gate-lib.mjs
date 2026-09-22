/**
 * m365-mcp-gate-lib.mjs — shared gate helpers. No production constants (KTD1).
 * Copied in spirit from entra-mcp-gate.mjs and parameterized.
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const HYGIENE_SKIP_DIR_NAMES = Object.freeze([
  '.venv',
  'node_modules',
  '.git',
  '__pycache__',
  'dist',
  'uv-cache',
  '.pytest_cache',
]);

export const SHARED_SOURCE_RELS = Object.freeze([
  'tools/m365-mcp-launch-core.mjs',
  'tools/m365-mcp-gate-lib.mjs',
]);

export function fragments(secret) {
  return [secret, secret.slice(0, 8), secret.slice(-8)].filter((s) => s && s.length >= 8);
}

export function blobHasSecret(text, secret) {
  if (!text) return false;
  return fragments(secret).some((f) => text.includes(f));
}

export function envText(obj) {
  return Object.entries(obj).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
}

export function atomicWriteFile(dest, data, mode) {
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

export function chmodDir700(p) {
  fs.mkdirSync(p, { recursive: true, mode: 0o700 });
  fs.chmodSync(p, 0o700);
}

export function setsEqual(a, b) {
  const A = new Set(a);
  const B = new Set(b);
  if (A.size !== B.size) return false;
  for (const x of A) if (!B.has(x)) return false;
  return true;
}

export function appendHistory(baselineDir, event) {
  const p = path.join(baselineDir, 'history.ndjson');
  fs.mkdirSync(baselineDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(baselineDir, 0o700);
  fs.appendFileSync(p, JSON.stringify({ ts: new Date().toISOString(), ...event }) + '\n');
  fs.chmodSync(p, 0o600);
}

export function runCaptured(cmd, args, opts = {}) {
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

export function captureStderr(fn) {
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

export function staticCliCheck(cliSource) {
  const reasons = [];
  if (/process\.argv/.test(cliSource)) reasons.push('reads process.argv');
  if (/process\.env/.test(cliSource)) reasons.push('reads process.env');
  if (/path\.resolve\(\s*here\s*,\s*['"]\.\.['"]\s*\)/.test(cliSource)) {
    reasons.push('derives workspaceRoot from dirname(self)/..');
  }
  if (!/runLauncher\(/.test(cliSource)) {
    reasons.push('CLI does not call runLauncher');
  }
  return { ok: reasons.length === 0, reasons };
}

export function makeFixtureConfig({
  baseline,
  env,
  envFileName,
  parentMode = 0o700,
  envMode = 0o600,
  baselineMode = 0o600,
} = {}) {
  const configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'm365-gate-cfg-'));
  fs.chmodSync(configDir, parentMode);
  const bdir = path.join(configDir, 'baseline');
  fs.mkdirSync(bdir, { mode: 0o700 });
  fs.chmodSync(bdir, 0o700);
  if (env) {
    const dest = path.join(configDir, envFileName);
    fs.writeFileSync(dest, envText(env));
    fs.chmodSync(dest, envMode);
  }
  if (baseline) {
    const active = { ...baseline, state: 'active' };
    fs.writeFileSync(path.join(bdir, 'active.json'), JSON.stringify(active));
    fs.chmodSync(path.join(bdir, 'active.json'), baselineMode);
  }
  return configDir;
}

export function scanFileForFragments(filePath, needles) {
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

export function walkHygiene(root, needles, skipNames, hits, unreadable, skipped) {
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

/**
 * KTD14 hygiene. surfaces: [{name, path, kind:'file'|'dir', role?: 'grok_log_pre_registration'}]
 * ENOENT on grok_log_pre_registration → not_created_pre_registration (never scanned_clean).
 * ENOENT or EACCES on any other declared surface → fail.
 */
export function scanHygiene({
  surfaces,
  needles,
  skipDirNames = new Set(HYGIENE_SKIP_DIR_NAMES),
} = {}) {
  const hits = [];
  const unreadable = [];
  const skipped = [];
  const statuses = {};
  for (const surface of surfaces) {
    let st;
    try {
      st = fs.lstatSync(surface.path);
    } catch (err) {
      if (err && err.code === 'ENOENT' && surface.role === 'grok_log_pre_registration') {
        statuses[surface.name] = 'not_created_pre_registration';
        continue;
      }
      unreadable.push({
        path: surface.path,
        code: (err && err.code) || err.message,
        surface: surface.name,
      });
      statuses[surface.name] = 'fail';
      continue;
    }
    if (st.isDirectory() || surface.kind === 'dir') {
      walkHygiene(surface.path, needles, skipDirNames, hits, unreadable, skipped);
      statuses[surface.name] = hits.some((h) => String(h).startsWith(surface.path))
        ? 'hit'
        : 'scanned_clean';
    } else {
      const r = scanFileForFragments(surface.path, needles);
      if (r.unreadable) {
        unreadable.push({ ...r, surface: surface.name });
        statuses[surface.name] = 'fail';
      } else if (r.hit) {
        hits.push(surface.path);
        statuses[surface.name] = 'hit';
      } else {
        statuses[surface.name] = 'scanned_clean';
      }
    }
  }
  const grokPre = surfaces.find((s) => s.role === 'grok_log_pre_registration');
  if (grokPre && statuses[grokPre.name] === 'not_created_pre_registration') {
    // must not be rewritten as scanned_clean
  }
  const ok = hits.length === 0 && unreadable.length === 0;
  return {
    ok,
    hits: hits.length,
    unreadable: unreadable.length,
    skipped_dirs: skipped.length,
    hit_paths: hits,
    unreadable_paths: unreadable,
    skipped,
    statuses,
  };
}

export function defaultHygieneSurfaces({
  home = os.userInfo().homedir,
  workspaceRoot,
  evidenceDir,
  registrationName,
  preRegistration = false,
} = {}) {
  const grokLog = path.join(home, '.grok', 'logs', 'mcp', `${registrationName}.stderr.log`);
  return [
    { name: 'claude_json', path: path.join(home, '.claude.json'), kind: 'file' },
    { name: 'codex_config', path: path.join(home, '.codex', 'config.toml'), kind: 'file' },
    { name: 'grok_config', path: path.join(home, '.grok', 'config.toml'), kind: 'file' },
    {
      name: 'grok_log',
      path: grokLog,
      kind: 'file',
      role: preRegistration ? 'grok_log_pre_registration' : undefined,
    },
    { name: 'workspace', path: workspaceRoot, kind: 'dir' },
    { name: 'evidence', path: evidenceDir, kind: 'dir' },
  ];
}

function sha256File(filePath) {
  const hash = createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function sha256Symlink(filePath) {
  const target = fs.readlinkSync(filePath);
  return createHash('sha256').update('symlink:' + target).digest('hex');
}

function isForbiddenEnvPath(p) {
  return p.split(path.sep).includes('entra-mcp.env') || path.basename(p) === 'entra-mcp.env';
}

function walkHash(root) {
  const entries = [];
  if (!fs.existsSync(root)) {
    return { exists: false, root, file_count: 0, aggregate_sha256: null, entries };
  }
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let listing;
    try {
      listing = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    listing.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of listing) {
      const abs = path.join(dir, ent.name);
      if (isForbiddenEnvPath(abs)) {
        throw new Error('refused to hash entra-mcp.env');
      }
      if (ent.isDirectory() && !ent.isSymbolicLink()) {
        stack.push(abs);
        continue;
      }
      const rel = path.relative(root, abs);
      if (ent.isSymbolicLink()) {
        entries.push({ path: rel, type: 'symlink', sha256: sha256Symlink(abs) });
      } else if (ent.isFile()) {
        entries.push({ path: rel, type: 'file', sha256: sha256File(abs) });
      }
    }
  }
  entries.sort((a, b) => a.path.localeCompare(b.path));
  const agg = createHash('sha256');
  for (const e of entries) agg.update(`${e.path}|${e.type}|${e.sha256}\n`);
  return {
    exists: true,
    root,
    file_count: entries.length,
    aggregate_sha256: agg.digest('hex'),
    entries,
  };
}

function extractTomlTable(text, tableName) {
  const lines = text.split(/\r?\n/);
  const captured = [];
  let capturing = false;
  for (const line of lines) {
    const stripped = line.trim();
    const m = stripped.match(/^\[([^\]]+)\]$/);
    if (m) {
      const table = m[1];
      const isMatch = table === tableName || table.startsWith(tableName + '.');
      capturing = isMatch;
      if (isMatch) captured.push(line);
      continue;
    }
    if (capturing) captured.push(line);
  }
  return captured.length ? captured.join('\n') + '\n' : null;
}

function hashText(text) {
  return createHash('sha256').update(text == null ? '<missing>' : text).digest('hex');
}

/**
 * KTD16 snapshot. Hashes only. Never opens ~/.config/entra-mcp/entra-mcp.env.
 */
export function snapshotEntraProtected({ workspaceRoot, home = os.userInfo().homedir } = {}) {
  const envPath = path.join(home, '.config', 'entra-mcp', 'entra-mcp.env');
  const claudePath = path.join(home, '.claude.json');
  let claudeEntry = null;
  let claudePresent = false;
  if (fs.existsSync(claudePath)) {
    const data = JSON.parse(fs.readFileSync(claudePath, 'utf8'));
    const servers = data.mcpServers || data.mcp_servers || {};
    claudeEntry = servers['entra-ro'] ?? null;
    claudePresent = claudeEntry != null;
  }
  const codexPath = path.join(home, '.codex', 'config.toml');
  const grokPath = path.join(home, '.grok', 'config.toml');
  const codexTable = fs.existsSync(codexPath)
    ? extractTomlTable(fs.readFileSync(codexPath, 'utf8'), 'mcp_servers.entra-ro')
    : null;
  const grokTable = fs.existsSync(grokPath)
    ? extractTomlTable(fs.readFileSync(grokPath, 'utf8'), 'mcp_servers.entra-ro')
    : null;

  const hashSingle = (p) => {
    if (!fs.existsSync(p)) return { exists: false, path: p };
    if (fs.lstatSync(p).isSymbolicLink()) {
      return { exists: true, path: p, type: 'symlink', sha256: sha256Symlink(p) };
    }
    const st = fs.statSync(p);
    return { exists: true, path: p, type: 'file', sha256: sha256File(p), size: st.size };
  };

  const compact = (walked) => ({
    exists: walked.exists,
    root: walked.root,
    file_count: walked.file_count,
    aggregate_sha256: walked.aggregate_sha256,
  });

  return {
    kind: 'ktd16-snapshot',
    timestamp_utc: new Date().toISOString(),
    protected: {
      'tools/entra-mcp-server': compact(walkHash(path.join(workspaceRoot, 'tools', 'entra-mcp-server'))),
      'tools/entra-mcp-launch.mjs': hashSingle(path.join(workspaceRoot, 'tools', 'entra-mcp-launch.mjs')),
      'tools/entra-mcp-launch-core.mjs': hashSingle(
        path.join(workspaceRoot, 'tools', 'entra-mcp-launch-core.mjs')
      ),
      'tools/entra-mcp-gate.mjs': hashSingle(path.join(workspaceRoot, 'tools', 'entra-mcp-gate.mjs')),
      '~/.config/entra-mcp/bin': compact(walkHash(path.join(home, '.config', 'entra-mcp', 'bin'))),
      '~/.config/entra-mcp/baseline': compact(
        walkHash(path.join(home, '.config', 'entra-mcp', 'baseline'))
      ),
      '~/.config/entra-mcp/entra-mcp.env': {
        exists: fs.existsSync(envPath),
        opened: false,
        hashed: false,
        note: 'never opened',
      },
      'host_entra-ro': {
        claude: {
          exists: fs.existsSync(claudePath),
          present: claudePresent,
          sha256: hashText(JSON.stringify(claudeEntry)),
        },
        codex: {
          exists: fs.existsSync(codexPath),
          present: Boolean(codexTable),
          sha256: hashText(codexTable),
        },
        grok: {
          exists: fs.existsSync(grokPath),
          present: Boolean(grokTable),
          sha256: hashText(grokTable),
        },
      },
    },
  };
}

export function compareEntraProtected(before, after) {
  const diffs = [];
  const a = before.protected || before;
  const b = after.protected || after;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const key of keys) {
    if (key.endsWith('entra-mcp.env')) continue;
    const left = JSON.stringify(a[key]);
    const right = JSON.stringify(b[key]);
    if (left !== right) diffs.push(key);
  }
  return { ok: diffs.length === 0, diffs };
}

/**
 * KTD9 shared-source release rule.
 * A shared edit blocks every promoted workload until each re-runs
 * candidate → verified → promote → confirm (and live stage 2, caller-owned).
 * Confirm failure: coherent rollback of shared tree + each baseline/pair,
 * or all affected left stopped. Baseline-only rollback against changed
 * shared bytes is never success.
 */
export function sharedHashes(workspaceRoot, extraRels = []) {
  const rels = [...SHARED_SOURCE_RELS, ...extraRels];
  const out = {};
  for (const rel of rels) {
    const abs = path.join(workspaceRoot, rel);
    out[rel] = fs.existsSync(abs) && fs.statSync(abs).isFile() ? sha256File(abs) : null;
  }
  const kernelSrc = path.join(workspaceRoot, 'tools', 'm365-mcp-kernel', 'src', 'm365_mcp_kernel');
  if (fs.existsSync(kernelSrc)) {
    const walked = walkHash(kernelSrc);
    out['tools/m365-mcp-kernel/src/m365_mcp_kernel'] = walked.aggregate_sha256;
  }
  return out;
}

export function sharedSourceChanged(before, after) {
  return JSON.stringify(before) !== JSON.stringify(after);
}

export function planSharedRelease({ workloads, sharedBefore, sharedAfter }) {
  const changed = sharedSourceChanged(sharedBefore, sharedAfter);
  const promoted = (workloads || []).filter((w) => w.promoted);
  if (!changed) {
    return { changed: false, blocked: [], action: 'none' };
  }
  return {
    changed: true,
    blocked: promoted.map((w) => w.name),
    action: 'stop_sessions_and_rerun_lifecycle_for_all_promoted',
  };
}

export function applySharedConfirm({
  workloads,
  confirmResults,
  restoreShared,
  restoreWorkload,
}) {
  const failed = (workloads || []).filter((w) => confirmResults[w.name] !== 'ok');
  if (failed.length === 0) {
    return { ok: true, mode: 'all_confirmed' };
  }
  const sharedRestored = typeof restoreShared === 'function' ? restoreShared() : false;
  const restored = [];
  const stopped = [];
  if (sharedRestored) {
    for (const w of workloads) {
      const r = typeof restoreWorkload === 'function' ? restoreWorkload(w) : false;
      if (r) restored.push(w.name);
      else stopped.push(w.name);
    }
    if (restored.length === workloads.length) {
      return { ok: true, mode: 'coherent_rollback', restored, stopped };
    }
    return { ok: false, mode: 'partial_rollback_unavailable', restored, stopped };
  }
  return {
    ok: false,
    mode: 'all_stopped',
    restored: [],
    stopped: workloads.map((w) => w.name),
    note: 'baseline-only rollback against changed shared bytes is not success',
  };
}

export function writeCandidate(baselineDir, candidate) {
  const candidatePath = path.join(baselineDir, 'candidate.json');
  atomicWriteFile(candidatePath, JSON.stringify({ ...candidate, state: 'candidate' }, null, 2), 0o600);
  appendHistory(baselineDir, { event: 'candidate' });
  return candidatePath;
}

export function promoteBaseline({
  baselineDir,
  binDir,
  candidate,
  installFiles = [],
}) {
  chmodDir700(baselineDir);
  chmodDir700(binDir);
  const activePath = path.join(baselineDir, 'active.json');
  if (fs.existsSync(activePath)) {
    atomicWriteFile(path.join(baselineDir, 'previous.json'), fs.readFileSync(activePath), 0o600);
    for (const item of installFiles) {
      const dest = path.join(binDir, item.name);
      if (fs.existsSync(dest)) {
        atomicWriteFile(path.join(binDir, `previous-${item.name}`), fs.readFileSync(dest), 0o500);
      }
    }
  }
  atomicWriteFile(activePath, JSON.stringify({ ...candidate, state: 'active' }, null, 2), 0o600);
  for (const item of installFiles) {
    atomicWriteFile(path.join(binDir, item.name), fs.readFileSync(item.src), 0o500);
  }
  appendHistory(baselineDir, { event: 'promote' });
  return { activePath, binDir };
}

export function rollbackLaterPromotion({ baselineDir, binDir, installNames = [] }) {
  const restored = [];
  const previous = path.join(baselineDir, 'previous.json');
  const active = path.join(baselineDir, 'active.json');
  if (fs.existsSync(previous)) {
    atomicWriteFile(active, fs.readFileSync(previous), 0o600);
    restored.push(active);
  }
  for (const name of installNames) {
    const prev = path.join(binDir, `previous-${name}`);
    const dest = path.join(binDir, name);
    if (fs.existsSync(prev)) {
      atomicWriteFile(dest, fs.readFileSync(prev), 0o500);
      restored.push(dest);
    }
  }
  appendHistory(baselineDir, { event: 'rollback_later_promotion', restored });
  return { kind: 'later-promotion', restored };
}

export function rollbackFirstPromotion({ baselineDir, binDir, installNames = [] }) {
  const removed = [];
  for (const name of installNames) {
    const p = path.join(binDir, name);
    if (fs.existsSync(p)) {
      fs.unlinkSync(p);
      removed.push(p);
    }
  }
  const active = path.join(baselineDir, 'active.json');
  if (fs.existsSync(active)) {
    fs.unlinkSync(active);
    removed.push(active);
  }
  appendHistory(baselineDir, { event: 'rollback_first_promotion', removed });
  return { kind: 'first-promotion', removed };
}

export function rfc1918orLocal(ip) {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('127.')) return true;
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

export function startPktapCapture({ pcapPath, sudo = true } = {}) {
  const args = sudo
    ? ['tcpdump', '-n', '-i', 'pktap,lo0', '-w', pcapPath]
    : ['tcpdump', '-n', '-i', 'lo0', '-w', pcapPath];
  const cmd = sudo ? 'sudo' : args.shift();
  const child = spawn(cmd, sudo ? args : args, { stdio: ['ignore', 'pipe', 'pipe'] });
  return child;
}

export function extractRemoteIps(tcpdumpText, pids) {
  const ips = new Set();
  const pidSet = new Set((pids || []).map(String));
  for (const line of String(tcpdumpText || '').split(/\n/)) {
    const m = line.match(/(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)/);
    if (!m) continue;
    if (pidSet.size && line.includes('pid') && ![...pidSet].some((p) => line.includes(p))) {
      continue;
    }
    ips.add(m[1]);
    ips.add(m[3]);
  }
  return [...ips];
}

export function descendantPids(rootPid) {
  const out = new Set([Number(rootPid)]);
  try {
    const text = fs.readFileSync('/bin/ps', { encoding: 'utf8' });
    void text;
  } catch {
    // ps is a binary; use spawn sync via child_process in callers
  }
  return [...out];
}
