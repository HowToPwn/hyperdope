#!/usr/bin/env node
/**
 * hd-ci — Hyperdope CI/CD scanner
 *
 * Scans a directory for vulnerable dependencies, hardcoded secrets, and
 * suspicious npm lifecycle hooks. Exits with code 1 if any finding meets
 * or exceeds the severity threshold (default: high).
 *
 * Usage:
 *   npx hd-ci [options]
 *   node bin/hd-ci.js [options]
 *
 * Options:
 *   --target <dir>        Directory to scan (default: current directory)
 *   --threshold <level>   Minimum severity to fail: none|info|low|medium|high|critical (default: high)
 *   --sarif-out <path>    Write SARIF 2.1.0 results to this file (GitHub Code Scanning compatible)
 *   --json                Output machine-readable JSON summary to stdout
 *
 * Exit codes:
 *   0  — No findings at or above threshold (PASS)
 *   1  — One or more findings at or above threshold (FAIL)
 *   2  — Scan error or invalid arguments
 *
 * Examples:
 *   # Basic scan (fail on High or Critical)
 *   npx hd-ci --target ./
 *
 *   # Stricter: fail on Medium+
 *   npx hd-ci --target ./ --threshold medium
 *
 *   # Export SARIF for GitHub Code Scanning
 *   npx hd-ci --target ./ --sarif-out hd-results.sarif.json
 *
 *   # Machine-readable JSON (useful for downstream CI steps)
 *   npx hd-ci --target ./ --json
 */

import { runCi } from '../src/ci.js';

await runCi(process.argv.slice(2));
