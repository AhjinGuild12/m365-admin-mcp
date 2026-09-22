import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  defaultHygieneSurfaces,
  evaluateProbe,
  scanHygiene,
} from './m365-mcp-gate-lib.mjs';

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('default hygiene surfaces stay at six unless extra surfaces are passed', () => {
  const home = tmpDir('hyg-home-');
  const surfaces = defaultHygieneSurfaces({
    home,
    workspaceRoot: tmpDir('hyg-ws-'),
    evidenceDir: tmpDir('hyg-ev-'),
    registrationName: 'teams-admin-ro',
  });
  assert.equal(surfaces.length, 6);
  assert.equal(surfaces.some((item) => item.name === 'cursor_mcp'), false);
  const cursor = path.join(home, '.cursor', 'mcp.json');
  const withExtra = defaultHygieneSurfaces({
    home,
    workspaceRoot: tmpDir('hyg-ws2-'),
    evidenceDir: tmpDir('hyg-ev2-'),
    registrationName: 'teams-admin-ro',
    extraSurfaces: [{ name: 'cursor_mcp', path: cursor, kind: 'file' }],
  });
  assert.equal(withExtra.length, 7);
  assert.equal(withExtra[6].name, 'cursor_mcp');
});

test('evaluateProbe matches the fail-closed cases', () => {
  const pageError = evaluateProbe(
    { bounded: false },
    { complete: false, stop_reason: 'page_error' },
  );
  assert.equal(pageError.status, 'unresolved');

  const mismatch = evaluateProbe(
    { kind: 'single', expectedId: '00000000-0000-0000-0000-000000000000' },
    { id: 'different' },
  );
  assert.equal(mismatch.status, 'fail');

  const capped = evaluateProbe(
    { bounded: true },
    { complete: false, stop_reason: 'item_cap', items: [] },
  );
  assert.equal(capped.status, 'pass');

  const user = '00000000-0000-0000-0000-000000000000';
  const policy = evaluateProbe(
    { kind: 'single', expectedId: user },
    { id: user, effectivePolicyAssignments: [] },
  );
  assert.equal(policy.status, 'pass');

  const missing = evaluateProbe({ targetPresent: false }, null);
  assert.equal(missing.status, 'skipped');

  const errored = evaluateProbe({ bounded: true }, { error: { message: '4xx graph_error' } });
  assert.equal(errored.status, 'fail');
  assert.equal(errored.statusClass, '4xx');
});

test('hygiene flags a fixture secret and tenant guid in cursor mcp.json', () => {
  const home = tmpDir('hyg-cursor-');
  const cursorDir = path.join(home, '.cursor');
  fs.mkdirSync(cursorDir, { recursive: true });
  const tenant = '00000000-0000-0000-0000-000000000000';
  const secret = 'fixture-secret-not-real';
  const mcp = path.join(cursorDir, 'mcp.json');
  fs.writeFileSync(mcp, `{"note":"${secret}","tenant":"${tenant}"}\n`);
  fs.writeFileSync(path.join(home, '.claude.json'), '{}\n');
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
  fs.writeFileSync(path.join(home, '.codex', 'config.toml'), 'x=1\n');
  fs.mkdirSync(path.join(home, '.grok'), { recursive: true });
  fs.writeFileSync(path.join(home, '.grok', 'config.toml'), 'x=1\n');
  const surfaces = defaultHygieneSurfaces({
    home,
    workspaceRoot: tmpDir('hyg-ws3-'),
    evidenceDir: tmpDir('hyg-ev3-'),
    registrationName: 'teams-admin-ro',
    preRegistration: true,
    extraSurfaces: [{ name: 'cursor_mcp', path: mcp, kind: 'file' }],
  });
  const report = scanHygiene({ surfaces, needles: [secret, tenant] });
  assert.equal(report.ok, false);
  assert.equal(report.statuses.cursor_mcp, 'hit');
  assert.equal(report.statuses.grok_log, 'not_created_pre_registration');
  assert.notEqual(report.statuses.grok_log, 'scanned_clean');
});
