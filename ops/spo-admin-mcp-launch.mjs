#!/usr/bin/env node
/**
 * spo-admin-mcp-launch.mjs — fail-closed CLI. Zero arguments, zero environment inputs.
 * Home comes from the account database, never from HOME.
 * Workspace root comes from the active baseline (KTD9), never from dirname(self).
 */
import os from 'node:os';
import path from 'node:path';
import { LaunchError, runLauncher } from './m365-mcp-launch-core.mjs';

const configDir = path.join(os.userInfo().homedir, '.config', 'spo-admin-mcp');
const descriptor = Object.freeze({
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

try {
  runLauncher({ configDir, descriptor });
} catch (err) {
  if (!(err instanceof LaunchError)) {
    const msg = err && err.message ? err.message : 'launch failed';
    process.stderr.write(`spo-admin-mcp-launch: ${msg}\n`);
  }
  process.exit(1);
}
