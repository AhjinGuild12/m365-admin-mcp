#!/usr/bin/env node
/**
 * exchange-admin-mcp-launch.mjs — fail-closed CLI. Zero arguments, zero environment inputs.
 * Home comes from the account database, never from HOME.
 * Workspace root comes from the active baseline, never from dirname(self).
 */
import os from 'node:os';
import path from 'node:path';
import { LaunchError, runLauncher } from './m365-mcp-launch-core.mjs';

const configDir = path.join(os.userInfo().homedir, '.config', 'exchange-admin-mcp');
const descriptor = Object.freeze({
  envPrefix: 'EXO',
  envFileName: 'exchange-admin-mcp.env',
  packageDir: 'packages/exchange-admin-mcp-server',
  kernelPackageDir: 'packages/m365-mcp-kernel',
  moduleName: 'exchange_admin_mcp',
  launchCliRel: 'ops/exchange-admin-mcp-launch.mjs',
  launchCoreRel: 'ops/m365-mcp-launch-core.mjs',
  gateRel: 'ops/exchange-admin-mcp-gate.mjs',
  gateLibRel: 'ops/m365-mcp-gate-lib.mjs',
  otherPrefixes: ['ENTRA', 'INTUNE', 'SPO_ADMIN', 'TEAMS_ADMIN'],
  stderrName: 'exchange-admin-mcp-launch',
});

try {
  runLauncher({ configDir, descriptor });
} catch (err) {
  if (!(err instanceof LaunchError)) {
    const msg = err && err.message ? err.message : 'launch failed';
    process.stderr.write(`exchange-admin-mcp-launch: ${msg}\n`);
  }
  process.exit(1);
}
