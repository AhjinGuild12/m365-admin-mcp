#!/usr/bin/env node
/**
 * intune-mcp-launch.mjs — fail-closed CLI. Zero arguments, zero environment inputs.
 * Home comes from the account database, never from HOME.
 * Workspace root comes from the active baseline (KTD9), never from dirname(self).
 */
import os from 'node:os';
import path from 'node:path';
import { LaunchError, runLauncher } from './m365-mcp-launch-core.mjs';

const configDir = path.join(os.userInfo().homedir, '.config', 'intune-mcp');
const descriptor = Object.freeze({
  envPrefix: 'INTUNE',
  envFileName: 'intune-mcp.env',
  packageDir: 'tools/intune-mcp-server',
  kernelPackageDir: 'tools/m365-mcp-kernel',
  moduleName: 'intune_mcp',
  launchCliRel: 'tools/intune-mcp-launch.mjs',
  launchCoreRel: 'tools/m365-mcp-launch-core.mjs',
  gateRel: 'tools/intune-mcp-gate.mjs',
  gateLibRel: 'tools/m365-mcp-gate-lib.mjs',
  otherPrefixes: ['SPO_ADMIN', 'TEAMS_ADMIN', 'EXO'],
  stderrName: 'intune-mcp-launch',
});

try {
  runLauncher({ configDir, descriptor });
} catch (err) {
  if (!(err instanceof LaunchError)) {
    const msg = err && err.message ? err.message : 'launch failed';
    process.stderr.write(`intune-mcp-launch: ${msg}\n`);
  }
  process.exit(1);
}
