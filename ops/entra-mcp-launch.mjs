#!/usr/bin/env node
/**
 * entra-mcp-launch.mjs — fail-closed CLI. Zero arguments, zero environment inputs.
 * Home comes from the account database, never from HOME.
 * Workspace root comes from the active baseline (KTD9), never from dirname(self).
 */
import os from 'node:os';
import path from 'node:path';
import { LaunchError, runLauncher } from './entra-mcp-launch-core.mjs';

const configDir = path.join(os.userInfo().homedir, '.config', 'entra-mcp');

try {
  runLauncher({ configDir });
} catch (err) {
  if (!(err instanceof LaunchError)) {
    const msg = err && err.message ? err.message : 'launch failed';
    process.stderr.write(`entra-mcp-launch: ${msg}\n`);
  }
  process.exit(1);
}
