/**
 * m365-mcp-launch-core.mjs — parameterized fail-closed launcher core.
 * Copied from entra-mcp-launch-core.mjs and generalized (KTD1, KTD8, KTD9).
 * No production constants. Caller supplies descriptor {configDir, envPrefix,
 * packageDir, moduleName, ...}. Never logs credential values.
 */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const CHILD_PATH = '/usr/bin:/bin:/usr/sbin:/sbin';
export const ENV_SIZE_CAP = 64 * 1024;
export const EXPIRY_WARN_DAYS = 14;
export const BASE_DENYLIST = Object.freeze([
  'AZURE_CLIENT_ID',
  'AZURE_CLIENT_SECRET',
  'AZURE_TENANT_ID',
  'AZURE_USERNAME',
  'AZURE_PASSWORD',
  'AZURE_CLIENT_CERTIFICATE_PATH',
  'AZURE_FEDERATED_TOKEN_FILE',
  'IDENTITY_ENDPOINT',
  'IDENTITY_HEADER',
  'IDENTITY_SERVER_THUMBPRINT',
  'MSI_ENDPOINT',
  'MSI_SECRET',
  'IMDS_ENDPOINT',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
  'no_proxy',
  'SSLKEYLOGFILE',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'REQUESTS_CA_BUNDLE',
  'CURL_CA_BUNDLE',
  'NODE_EXTRA_CA_CERTS',
  'PYTHONPATH',
  'PYTHONHOME',
  'PYTHONSTARTUP',
  'UV_CACHE_DIR',
]);

export class LaunchError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LaunchError';
  }
}

export function normalizePrefix(prefix) {
  return String(prefix || '').replace(/_+$/, '');
}

export function requiredVars(envPrefix) {
  const p = normalizePrefix(envPrefix);
  return [`${p}_TENANT_ID`, `${p}_CLIENT_ID`, `${p}_CLIENT_SECRET`, `${p}_SECRET_EXPIRES`];
}

export function certVar(envPrefix) {
  return `${normalizePrefix(envPrefix)}_CLIENT_CERTIFICATE_PATH`;
}

export function prefixEnvNames(envPrefix) {
  const p = normalizePrefix(envPrefix);
  return [
    `${p}_TENANT_ID`,
    `${p}_CLIENT_ID`,
    `${p}_CLIENT_SECRET`,
    `${p}_SECRET_EXPIRES`,
    `${p}_CLIENT_CERTIFICATE_PATH`,
  ];
}

export function foreignPrefixDenylist(otherPrefixes = []) {
  const names = [];
  for (const raw of otherPrefixes) {
    names.push(...prefixEnvNames(raw));
  }
  return names;
}

export function denylistFor(descriptor = {}) {
  return [...BASE_DENYLIST, ...foreignPrefixDenylist(descriptor.otherPrefixes || [])];
}

function stderrName(descriptor) {
  return (descriptor && descriptor.stderrName) || 'm365-mcp-launch';
}

export function die(message, descriptor) {
  process.stderr.write(`${stderrName(descriptor)}: ${message}\n`);
  throw new LaunchError(message);
}

export function resolveAccountHome() {
  return os.userInfo().homedir;
}

export function resolveDefaultConfigDir(workloadConfigName) {
  return path.join(resolveAccountHome(), '.config', workloadConfigName);
}

export function parseEnvText(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

function modeOf(stat) {
  return stat.mode & 0o777;
}

function assertOwnerMode(stat, { wantModes, label, uid, descriptor }) {
  if (stat.uid !== uid) {
    die(`${label} owner uid ${stat.uid} != ${uid}`, descriptor);
  }
  const mode = modeOf(stat).toString(8);
  const ok = wantModes.map((m) => m.toString(8));
  if (!ok.includes(mode)) {
    die(`${label} mode is ${mode} (want ${ok.join(' or ')})`, descriptor);
  }
}

export function envFileName(descriptor) {
  if (descriptor.envFileName) return descriptor.envFileName;
  const base = path.basename(descriptor.configDir || '');
  return `${base}.env`;
}

export function readEnvFile(configDir, descriptor = {}) {
  const name = envFileName({ ...descriptor, configDir });
  const envPath = path.join(configDir, name);
  const parentPath = configDir;
  const uid = process.getuid();
  let parent;
  try {
    parent = fs.lstatSync(parentPath);
  } catch {
    die(`missing env parent directory: ${parentPath}`, descriptor);
  }
  if (parent.isSymbolicLink()) die(`env parent is a symlink: ${parentPath}`, descriptor);
  if (!parent.isDirectory()) die(`env parent is not a directory: ${parentPath}`, descriptor);
  assertOwnerMode(parent, { wantModes: [0o700], label: 'env parent', uid, descriptor });

  const flags =
    fs.constants.O_RDONLY |
    fs.constants.O_NOFOLLOW |
    (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(envPath, flags);
  } catch (err) {
    if (err && (err.code === 'ENOENT' || err.code === 'ENOTDIR')) {
      die(`missing env file: ${envPath}`, descriptor);
    }
    if (err && (err.code === 'ELOOP' || err.code === 'EMLINK')) {
      die(`env path is a symlink: ${envPath}`, descriptor);
    }
    die(`cannot open env file (${err.code || err.message})`, descriptor);
  }
  try {
    const st = fs.fstatSync(fd);
    if (st.isSymbolicLink && st.isSymbolicLink()) die(`env path is a symlink: ${envPath}`, descriptor);
    if (!st.isFile()) die(`env path is not a regular file: ${envPath}`, descriptor);
    assertOwnerMode(st, { wantModes: [0o600, 0o400], label: envPath, uid, descriptor });
    if (st.size > ENV_SIZE_CAP) die(`env file too large (${st.size})`, descriptor);
    const buf = Buffer.alloc(st.size);
    fs.readSync(fd, buf, 0, st.size, 0);
    return parseEnvText(buf.toString('utf8'));
  } finally {
    fs.closeSync(fd);
  }
}

export function validateCredentials(fileEnv, descriptor) {
  if (!descriptor || !descriptor.envPrefix) die('missing env prefix', descriptor);
  const certName = certVar(descriptor.envPrefix);
  const secretName = `${normalizePrefix(descriptor.envPrefix)}_CLIENT_SECRET`;
  const cert = fileEnv[certName];
  const secret = fileEnv[secretName];
  if (cert && String(cert).trim() !== '' && (!secret || String(secret).trim() === '')) {
    die('certificate path does not satisfy a missing secret', descriptor);
  }
  const missing = requiredVars(descriptor.envPrefix).filter(
    (k) => !fileEnv[k] || String(fileEnv[k]).trim() === ''
  );
  if (missing.length) {
    die(`missing ${missing.join(' / ')}`, descriptor);
  }
  const expiryName = `${normalizePrefix(descriptor.envPrefix)}_SECRET_EXPIRES`;
  const raw = String(fileEnv[expiryName]).trim();
  const ms = Date.parse(raw);
  if (Number.isNaN(ms)) die(`${expiryName} is malformed`, descriptor);
  const now = Date.now();
  if (ms <= now) die(`${expiryName} is at or past expiry`, descriptor);
  const days = (ms - now) / (86400 * 1000);
  return { expiresInDays: days, warn: days <= EXPIRY_WARN_DAYS };
}

export function buildChildEnv(fileEnv, parentEnv = process.env, descriptor = {}) {
  const names = prefixEnvNames(descriptor.envPrefix);
  const child = { PATH: CHILD_PATH };
  for (const k of names) {
    child[k] = fileEnv[k] != null ? String(fileEnv[k]) : '';
  }
  if (parentEnv.LANG) child.LANG = parentEnv.LANG;
  if (parentEnv.LC_ALL) child.LC_ALL = parentEnv.LC_ALL;
  const deny = denylistFor(descriptor);
  for (const k of deny) {
    if (Object.prototype.hasOwnProperty.call(child, k)) delete child[k];
  }
  return child;
}

function sha256File(filePath) {
  const hash = createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function walkHashed(dir, relBase, files, skipDirNames) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  const sorted = entries.slice().sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of sorted) {
    if (skipDirNames.has(entry.name)) continue;
    const abs = path.join(dir, entry.name);
    const rel = path.join(relBase, entry.name);
    if (entry.isDirectory()) {
      walkHashed(abs, rel, files, skipDirNames);
      continue;
    }
    if (entry.isSymbolicLink()) {
      let real;
      try {
        real = fs.realpathSync(abs);
      } catch {
        files[rel] = { symlink: true, realPath: null, hash: null };
        continue;
      }
      let hash = null;
      try {
        if (fs.statSync(real).isFile()) hash = sha256File(real);
      } catch {
        hash = null;
      }
      files[rel] = { symlink: true, realPath: real, hash };
      continue;
    }
    if (entry.isFile()) {
      files[rel] = sha256File(abs);
    }
  }
}

export function launcherRelativePaths(descriptor) {
  return [
    descriptor.launchCliRel,
    descriptor.launchCoreRel || 'tools/m365-mcp-launch-core.mjs',
    descriptor.gateRel,
    descriptor.gateLibRel || 'tools/m365-mcp-gate-lib.mjs',
  ].filter(Boolean);
}

export function computeIntegrityManifest(workspaceRoot, descriptor = {}) {
  const files = {};
  const packageDir = descriptor.packageDir || 'tools/unknown-mcp-server';
  const kernelDir = descriptor.kernelPackageDir || 'tools/m365-mcp-kernel';
  const serverRoot = path.join(workspaceRoot, packageDir);
  const kernelRoot = path.join(workspaceRoot, kernelDir);
  const srcRoot = path.join(serverRoot, 'src');
  const kernelSrc = path.join(kernelRoot, 'src', 'm365_mcp_kernel');
  walkHashed(srcRoot, path.relative(workspaceRoot, srcRoot), files, new Set(['__pycache__']));
  walkHashed(kernelSrc, path.relative(workspaceRoot, kernelSrc), files, new Set(['__pycache__']));
  for (const abs of [
    path.join(serverRoot, 'pyproject.toml'),
    path.join(serverRoot, 'uv.lock'),
    path.join(kernelRoot, 'pyproject.toml'),
  ]) {
    const rel = path.relative(workspaceRoot, abs);
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) files[rel] = sha256File(abs);
    else files[rel] = null;
  }
  const venv = path.join(serverRoot, '.venv');
  walkHashed(venv, path.relative(workspaceRoot, venv), files, new Set(['__pycache__']));
  const interpreter = {};
  for (const bin of ['python', 'python3']) {
    const p = path.join(venv, 'bin', bin);
    if (!fs.existsSync(p)) continue;
    try {
      const real = fs.realpathSync(p);
      interpreter[bin] = {
        realPath: real,
        hash: fs.statSync(real).isFile() ? sha256File(real) : null,
      };
    } catch {
      interpreter[bin] = { realPath: null, hash: null };
    }
  }
  for (const rel of launcherRelativePaths(descriptor)) {
    const abs = path.join(workspaceRoot, rel);
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) files[rel] = sha256File(abs);
    else files[rel] = null;
  }
  return { files, interpreter };
}

export function readActiveBaseline(configDir, descriptor = {}) {
  const baselinePath = path.join(configDir, 'baseline', 'active.json');
  const uid = process.getuid();
  let st;
  try {
    st = fs.lstatSync(baselinePath);
  } catch {
    die('missing active baseline', descriptor);
  }
  if (st.isSymbolicLink()) die('active baseline is a symlink', descriptor);
  if (!st.isFile()) die('active baseline is not a regular file', descriptor);
  assertOwnerMode(st, { wantModes: [0o600, 0o400], label: 'active baseline', uid, descriptor });
  const parent = fs.lstatSync(path.dirname(baselinePath));
  if (parent.isSymbolicLink() || !parent.isDirectory()) {
    die('baseline parent is not a real directory', descriptor);
  }
  if (parent.uid !== uid) die('baseline parent owner mismatch', descriptor);
  if (modeOf(parent) !== 0o700) {
    die(`baseline parent mode is ${modeOf(parent).toString(8)} (want 700)`, descriptor);
  }
  const raw = fs.readFileSync(baselinePath, 'utf8');
  try {
    return JSON.parse(raw);
  } catch {
    die('active baseline is not valid JSON', descriptor);
  }
}

function stable(obj) {
  return JSON.stringify(obj);
}

export function resolveWorkspaceRoot(configDir, workspaceRoot, descriptor = {}) {
  if (workspaceRoot) return workspaceRoot;
  const expected = readActiveBaseline(configDir, descriptor);
  const root = expected && expected.workspaceRoot;
  if (!root || typeof root !== 'string' || !path.isAbsolute(root)) {
    die('active baseline missing absolute workspaceRoot', descriptor);
  }
  return root;
}

export function assertIntegrity(configDir, workspaceRoot, descriptor = {}) {
  const expected = readActiveBaseline(configDir, descriptor);
  const root = workspaceRoot || expected.workspaceRoot;
  if (!root) die('missing workspace root', descriptor);
  const actual = computeIntegrityManifest(root, descriptor);
  if (stable(expected.files) !== stable(actual.files)) {
    die('integrity mismatch (source, lockfile, or venv)', descriptor);
  }
  if (stable(expected.interpreter || {}) !== stable(actual.interpreter || {})) {
    die('integrity mismatch (interpreter)', descriptor);
  }
  return root;
}

export function serverPaths(workspaceRoot, descriptor) {
  const serverDir = path.join(workspaceRoot, descriptor.packageDir);
  const python = path.join(serverDir, '.venv', 'bin', 'python');
  return { serverDir, python };
}

export function spawnServer({
  workspaceRoot,
  childEnv,
  descriptor,
  spawnImpl = spawn,
  stdio = 'inherit',
  wait = true,
}) {
  const { serverDir, python } = serverPaths(workspaceRoot, descriptor);
  if (!fs.existsSync(python)) die(`missing interpreter: ${python}`, descriptor);
  const args = ['-I', '-B', '-m', descriptor.moduleName];
  const child = spawnImpl(python, args, {
    cwd: serverDir,
    env: childEnv,
    stdio,
  });
  if (!wait) return child;
  child.on('error', (err) => {
    die(`failed to spawn server: ${err.message}`, descriptor);
  });
  child.on('exit', (code, signal) => {
    if (signal) {
      try {
        process.kill(process.pid, signal);
      } catch {
        process.exit(1);
      }
    }
    process.exit(code ?? 1);
  });
  return child;
}

export function runLauncher({
  configDir,
  descriptor,
  workspaceRoot,
  spawnImpl,
  stdio,
  wait = true,
  parentEnv = process.env,
} = {}) {
  if (!configDir) die('missing config dir', descriptor);
  if (!descriptor) die('missing workload descriptor', descriptor);
  if (!descriptor.envPrefix) die('missing env prefix', descriptor);
  if (!descriptor.packageDir) die('missing package dir', descriptor);
  if (!descriptor.moduleName) die('missing module name', descriptor);
  const desc = { ...descriptor, configDir };
  const root = assertIntegrity(configDir, workspaceRoot, desc);
  const fileEnv = readEnvFile(configDir, desc);
  const expiry = validateCredentials(fileEnv, desc);
  if (expiry.warn) {
    process.stderr.write(
      `${stderrName(desc)}: ${normalizePrefix(desc.envPrefix)}_SECRET_EXPIRES is within ${EXPIRY_WARN_DAYS} days\n`
    );
  }
  const childEnv = buildChildEnv(fileEnv, parentEnv, desc);
  return spawnServer({
    workspaceRoot: root,
    childEnv,
    descriptor: desc,
    spawnImpl,
    stdio,
    wait,
  });
}
