import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { staticCliCheck } from './m365-mcp-gate-lib.mjs';
import { buildChildEnv } from './m365-mcp-launch-core.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, 'intune-mcp-launch.mjs');

const DESC = {
  envPrefix: 'INTUNE',
  otherPrefixes: ['SPO_ADMIN', 'TEAMS_ADMIN', 'EXO'],
};

test('CLI source never reads argv or env', () => {
  const src = fs.readFileSync(CLI, 'utf8');
  const check = staticCliCheck(src);
  assert.equal(check.ok, true, check.reasons.join('; '));
  assert.equal(/process\.argv/.test(src), false);
  assert.equal(/process\.env/.test(src), false);
  assert.match(src, /runLauncher\(/);
  assert.match(src, /descriptor/);
  assert.match(src, /intune_mcp/);
});

test('CLI is not executed by this file', () => {
  const self = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8');
  assert.equal(/intune-mcp-launch\.mjs['"]/.test(self) && /spawn\(/.test(self), false);
  assert.doesNotMatch(self, /execFileSync\(\s*process\.execPath/);
});

test('foreign-prefix secret is stripped from child env', () => {
  const fileEnv = {
    INTUNE_TENANT_ID: 't',
    INTUNE_CLIENT_ID: 'c',
    INTUNE_CLIENT_SECRET: 'intune-secret',
    INTUNE_SECRET_EXPIRES: '2099-01-01T00:00:00Z',
    INTUNE_CLIENT_CERTIFICATE_PATH: '',
  };
  const child = buildChildEnv(fileEnv, { EXO_CLIENT_SECRET: 'foreign-secret' }, DESC);
  assert.equal(child.EXO_CLIENT_SECRET, undefined);
  assert.equal(JSON.stringify(child).includes('foreign-secret'), false);
  assert.equal(child.INTUNE_CLIENT_SECRET, 'intune-secret');
});
