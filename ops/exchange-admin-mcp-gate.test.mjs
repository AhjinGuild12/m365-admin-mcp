import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  assertStage1ConfigDir,
  evaluateSmokeMatrix,
  installBaseline,
  PROBE_MATRIX,
  runStage1,
  WORKSPACE_ROOT,
} from './exchange-admin-mcp-gate.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function tmpDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function hashFile(target) {
  return crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
}

test('stage1 refuses a missing config dir and a dir under .config', () => {
  const home = tmpDir('teams-home-');
  assert.throws(() => assertStage1ConfigDir('', home), /config-dir/);
  const blocked = path.join(home, '.config', 'exchange-admin-mcp');
  fs.mkdirSync(blocked, { recursive: true });
  assert.throws(() => assertStage1ConfigDir(blocked, home), /\.config/);
});

test('stage1 leaves a preseeded production dir byte-identical', () => {
  const home = tmpDir('teams-home-');
  const prod = path.join(home, '.config', 'exchange-admin-mcp');
  fs.mkdirSync(prod, { recursive: true });
  const marker = path.join(prod, 'marker');
  fs.writeFileSync(marker, 'keep-me');
  const before = hashFile(marker);
  const configDir = tmpDir('teams-stage1-');
  const result = runStage1({
    configDir,
    home,
    workspaceRoot: WORKSPACE_ROOT,
    runPytest: false,
    runRefusal: true,
  });
  assert.equal(result.ok, true);
  assert.equal(hashFile(marker), before);
  assert.equal(fs.existsSync(path.join(configDir, 'baseline', 'active.json')), true);
  assert.equal(fs.existsSync(path.join(configDir, 'bin', 'exchange-admin-mcp-launch.mjs')), true);
  const outside = fs.readdirSync(path.dirname(configDir)).filter((name) => name.startsWith('teams-stage1-'));
  assert.ok(outside.length >= 1);
  assert.equal(fs.existsSync(path.join(HERE, '..', '..', '.config', 'exchange-admin-mcp')), false);
});

test('install refuses an existing baseline without rebaseline', () => {
  const configDir = tmpDir('teams-install-');
  const workspace = path.join(HERE, '..');
  installBaseline({ configDir, workspaceRoot: workspace, rebaseline: false });
  assert.throws(
    () => installBaseline({ configDir, workspaceRoot: workspace, rebaseline: false }),
    /rebaseline/,
  );
});

test('probe matrix is the frozen fifteen tools', () => {
  const names = PROBE_MATRIX.map((row) => row.tool);
  assert.equal(names.length, 15);
  assert.equal(new Set(names).size, 15);
  const single = PROBE_MATRIX.filter((row) => row.kind === 'single').map((row) => row.tool);
  assert.deepEqual(single, ['get_room']);
  for (const row of PROBE_MATRIX) {
    if (row.tool.startsWith('list_')) assert.equal(row.bounded, true);
  }
  assert.equal(PROBE_MATRIX.find((row) => row.tool === 'get_mailbox').kind, undefined);
  assert.equal(PROBE_MATRIX.find((row) => row.tool === 'get_organization_config').kind, undefined);
});

test('smoke matrix skips missing targets and scores a room by id', () => {
  const room = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const skipped = evaluateSmokeMatrix({}, {});
  const traces = skipped.find((row) => row.tool === 'list_message_traces');
  assert.equal(traces.status, 'skipped');
  const usage = skipped.find((row) => row.tool === 'list_mailbox_usage_report');
  assert.equal(usage.status, 'fail');
  const withRoom = evaluateSmokeMatrix(
    { EXO_PROBE_ROOM: room },
    { get_room: { id: room, displayName: 'Board' } },
  );
  const echoed = withRoom.find((row) => row.tool === 'get_room');
  assert.equal(echoed.status, 'pass');
});
