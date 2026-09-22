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
  runStage1,
  WORKSPACE_ROOT,
} from './teams-admin-mcp-gate.mjs';

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
  const blocked = path.join(home, '.config', 'teams-admin-mcp');
  fs.mkdirSync(blocked, { recursive: true });
  assert.throws(() => assertStage1ConfigDir(blocked, home), /\.config/);
});

test('stage1 leaves a preseeded production dir byte-identical', () => {
  const home = tmpDir('teams-home-');
  const prod = path.join(home, '.config', 'teams-admin-mcp');
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
  assert.equal(fs.existsSync(path.join(configDir, 'bin', 'teams-admin-mcp-launch.mjs')), true);
  const outside = fs.readdirSync(path.dirname(configDir)).filter((name) => name.startsWith('teams-stage1-'));
  assert.ok(outside.length >= 1);
  assert.equal(fs.existsSync(path.join(HERE, '..', '..', '.config', 'teams-admin-mcp')), false);
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

test('smoke matrix skips missing targets and passes an empty policy list', () => {
  const user = '00000000-0000-0000-0000-000000000000';
  const skipped = evaluateSmokeMatrix({}, {});
  const policy = skipped.find((row) => row.tool === 'get_user_teams_policy_assignments');
  assert.equal(policy.status, 'skipped');
  const catalog = skipped.find((row) => row.tool === 'list_org_catalog_apps');
  assert.equal(catalog.status, 'fail');
  const withUser = evaluateSmokeMatrix(
    { TEAMS_ADMIN_PROBE_USER_ID: user },
    {
      get_user_teams_policy_assignments: {
        id: user,
        effectivePolicyAssignments: [],
      },
    },
  );
  const echoed = withUser.find((row) => row.tool === 'get_user_teams_policy_assignments');
  assert.equal(echoed.status, 'pass');
});
