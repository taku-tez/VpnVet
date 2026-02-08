#!/usr/bin/env node
/**
 * VpnVet CLI
 * 
 * VPN device detection and vulnerability scanner for ASM.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VpnScanner } from './scanner.js';
import { getAllVendors } from './fingerprints/index.js';
import { setVerbose, logError, logInfo } from './utils.js';
import { resolveVendor } from './vendor.js';
import { formatOutput, listVendors, listVulnerabilities } from './formatters.js';
import type { ScanOptions } from './types.js';

// Get version from package.json
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgPath = path.join(__dirname, '..', 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
const VERSION = pkg.version;

interface CliOptions extends ScanOptions {
  format: 'json' | 'sarif' | 'csv' | 'table';
  output?: string;
  quiet?: boolean;
  verbose?: boolean;
}

function printHelp(): void {
  console.log(`
VpnVet v${VERSION} - VPN Device Detection & Vulnerability Scanner

USAGE:
  vpnvet scan <target>              Scan a single target
  vpnvet scan --targets <file>      Scan multiple targets from file
  vpnvet list vendors               List supported VPN vendors
  vpnvet list vulns                 List known vulnerabilities
  vpnvet version                    Show version

SCAN OPTIONS:
  -t, --targets <file>     File containing targets (one per line)
  -o, --output <file>      Output file path
  -f, --format <fmt>       Output format: json, sarif, csv, table (default: table)
  --timeout <ms>           Request timeout in milliseconds (default: 10000)
  --ports <list>           Comma-separated ports to scan (default: 443,10443,8443,4433)
  --skip-vuln              Skip vulnerability check
  --skip-version           Skip version detection
  -q, --quiet              Suppress progress output
  -v, --verbose            Verbose output
  --vendor <name>          Test specific vendor only (faster)
  --concurrency <n>        Max concurrent scans (default: 5, max: 100)

EXAMPLES:
  vpnvet scan vpn.example.com
  vpnvet scan vpn.example.com -f json -o result.json
  vpnvet scan --targets domains.txt -f sarif
  vpnvet list vendors
  vpnvet list vulns --severity critical
`);
}

function printVersion(): void {
  console.log(`VpnVet v${VERSION}`);
}

/** Per-subcommand allowed flags for validation */
const SCAN_FLAGS = new Set([
  '-t', '--targets', '-o', '--output', '-f', '--format',
  '--timeout', '--ports', '--vendor',
  '--skip-vuln', '--skip-version', '--fast', '--concurrency',
  '-q', '--quiet', '-v', '--verbose',
]);

const LIST_VENDORS_FLAGS = new Set<string>([]);
const LIST_VULNS_FLAGS = new Set(['--severity']);

const VALID_FORMATS = ['json', 'sarif', 'csv', 'table'] as const;
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

/**
 * Require the next argument as a value for the given option.
 * Exits with error if missing or looks like another flag.
 */
function requireArg(args: string[], i: number, optionName: string): string {
  const next = args[i + 1];
  if (next === undefined || next.startsWith('-')) {
    logError(`Option ${optionName} requires a value.`);
    process.exit(1);
  }
  return next;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }
  
  if (args[0] === 'version' || args[0] === '--version') {
    printVersion();
    process.exit(0);
  }
  
  const command = args[0];
  
  if (command === 'list') {
    const subCommand = args[1];
    if (subCommand === 'vendors') {
      const unknownFlags = args.slice(2).filter(a => a.startsWith('-') && !LIST_VENDORS_FLAGS.has(a));
      if (unknownFlags.length > 0) {
        logError(`Unknown option: ${unknownFlags[0]}`);
        process.exit(1);
      }
      listVendors();
    } else if (subCommand === 'vulns') {
      const unknownFlags = args.slice(2).filter(a => a.startsWith('-') && !LIST_VULNS_FLAGS.has(a));
      if (unknownFlags.length > 0) {
        logError(`Unknown option: ${unknownFlags[0]}. Allowed: ${[...LIST_VULNS_FLAGS].join(', ')}`);
        process.exit(1);
      }
      const severityIdx = args.indexOf('--severity');
      if (severityIdx !== -1) {
        const severity = requireArg(args, severityIdx, '--severity');
        if (!(VALID_SEVERITIES as readonly string[]).includes(severity)) {
          logError(`Invalid --severity value: "${severity}". Must be one of: ${VALID_SEVERITIES.join(', ')}`);
          process.exit(1);
        }
        listVulnerabilities(severity);
      } else {
        listVulnerabilities();
      }
    } else {
      logError('Unknown list command. Use: list vendors | list vulns');
      process.exit(1);
    }
    process.exit(0);
  }
  
  if (command === 'scan') {
    const options: CliOptions = {
      format: 'table',
      timeout: 10000,
      ports: [443, 10443, 8443, 4433],
    };
    
    let targets: string[] = [];
    
    for (let i = 1; i < args.length; i++) {
      const arg = args[i];
      
      if (arg === '-t' || arg === '--targets') {
        const file = requireArg(args, i, arg);
        i++;
        if (!fs.existsSync(file)) {
          logError(`Targets file not found: ${file}`);
          process.exit(1);
        }
        const content = fs.readFileSync(file, 'utf-8');
        const parsedTargets = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
        targets.push(...parsedTargets);
      } else if (arg === '-o' || arg === '--output') {
        options.output = requireArg(args, i, arg);
        i++;
      } else if (arg === '-f' || arg === '--format') {
        const fmt = requireArg(args, i, arg);
        i++;
        if (!(VALID_FORMATS as readonly string[]).includes(fmt)) {
          logError(`Invalid --format value: "${fmt}". Must be one of: ${VALID_FORMATS.join(', ')}`);
          process.exit(1);
        }
        options.format = fmt as CliOptions['format'];
      } else if (arg === '--timeout') {
        const raw = requireArg(args, i, arg);
        i++;
        if (!/^\d+$/.test(raw)) {
          logError('Invalid --timeout value. Must be a positive integer (in milliseconds).');
          process.exit(1);
        }
        const timeoutVal = Number(raw);
        if (timeoutVal <= 0) {
          logError('Invalid --timeout value. Must be a positive integer (in milliseconds).');
          process.exit(1);
        }
        if (timeoutVal > 120000) {
          logError('Invalid --timeout value. Maximum allowed is 120000ms (2 minutes).');
          process.exit(1);
        }
        options.timeout = timeoutVal;
      } else if (arg === '--ports') {
        const raw = requireArg(args, i, arg);
        i++;
        const parts = raw.split(',');
        for (const part of parts) {
          const trimmed = part.trim();
          if (trimmed === '' || !/^\d+$/.test(trimmed)) {
            logError(`Invalid --ports value: "${part.trim() || '(empty)'}". Each port must be a positive integer.`);
            process.exit(1);
          }
          const portNum = Number(trimmed);
          if (portNum < 1 || portNum > 65535) {
            logError(`Invalid --ports value: ${portNum}. Ports must be between 1-65535.`);
            process.exit(1);
          }
        }
        const parsedPorts = [...new Set(parts.map(p => Number(p.trim())))];
        options.ports = parsedPorts;
      } else if (arg === '--skip-vuln') {
        options.skipVulnCheck = true;
      } else if (arg === '--skip-version') {
        options.skipVersionDetection = true;
      } else if (arg === '-q' || arg === '--quiet') {
        options.quiet = true;
      } else if (arg === '-v' || arg === '--verbose') {
        options.verbose = true;
      } else if (arg === '--vendor') {
        options.vendor = requireArg(args, i, arg);
        i++;
      } else if (arg === '--fast') {
        options.fast = true;
      } else if (arg === '--concurrency') {
        const raw = requireArg(args, i, arg);
        i++;
        if (!/^\d+$/.test(raw)) {
          logError('Invalid --concurrency value. Must be a positive integer (1-100).');
          process.exit(1);
        }
        const concurrencyVal = Number(raw);
        if (concurrencyVal < 1 || concurrencyVal > 100) {
          logError('Invalid --concurrency value. Must be a positive integer (1-100).');
          process.exit(1);
        }
        options.concurrency = concurrencyVal;
      } else if (arg.startsWith('-')) {
        if (!SCAN_FLAGS.has(arg)) {
          logError(`Unknown option: "${arg}". Run vpnvet --help for usage.`);
          process.exit(1);
        }
        logError(`Unhandled option: "${arg}". Run vpnvet --help for usage.`);
        process.exit(1);
      } else {
        targets.push(arg);
      }
    }
    
    if (options.vendor) {
      const knownVendors = getAllVendors();
      const resolved = resolveVendor(options.vendor, knownVendors);
      if (!resolved) {
        logError(`Unknown vendor: "${options.vendor}". Known vendors: ${knownVendors.join(', ')}`);
        process.exit(1);
      }
      options.vendor = resolved;
    }

    targets = [...new Set(targets.map(t => t.trim()).filter(t => t))];

    if (targets.length === 0) {
      logError('No targets specified. Provide a target or use --targets <file>');
      process.exit(1);
    }
    
    if (options.verbose) {
      setVerbose(true);
    }
    
    if (!options.quiet) {
      logInfo(`VpnVet v${VERSION} - Scanning ${targets.length} target(s)...`);
    }
    
    const scanner = new VpnScanner(options);
    const results = await scanner.scanMultiple(targets);
    
    if (!options.quiet) {
      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (result.device) {
          console.error(`[${i + 1}/${targets.length}] ${result.target} ✓ ${result.device.vendor} ${result.device.product} (${result.device.confidence}%)`);
        } else if (result.scanErrors && result.scanErrors.length > 0) {
          const kinds = result.scanErrors.map(e => e.kind).filter((v, i, a) => a.indexOf(v) === i).join('/');
          console.error(`[${i + 1}/${targets.length}] ${result.target} ⚠ Connection failed (${kinds})`);
        } else if (result.errors.length > 0) {
          console.error(`[${i + 1}/${targets.length}] ${result.target} ✗ Error: ${result.errors[0]}`);
        } else {
          console.error(`[${i + 1}/${targets.length}] ${result.target} - No VPN detected`);
        }
      }
    }
    
    if (options.quiet) {
      const detected = results.filter(r => r.device).length;
      const connFailed = results.filter(r => !r.device && r.scanErrors && r.scanErrors.length > 0).length;
      const clean = results.length - detected - connFailed;
      console.error(`Scanned ${results.length} target(s): ${detected} detected, ${connFailed} connection failed, ${clean} clean`);
    }

    const output = formatOutput(results, options.format, VERSION);
    
    if (options.output) {
      const outputPath = path.resolve(options.output);
      fs.writeFileSync(outputPath, output);
      if (!options.quiet) {
        console.error(`\nResults written to: ${outputPath}`);
      }
    } else {
      console.log(output);
    }
    
    const hasVulnerabilities = results.some(r => r.vulnerabilities.length > 0);
    const hasCritical = results.some(r => 
      r.vulnerabilities.some(v => v.vulnerability.severity === 'critical')
    );
    
    if (hasCritical) {
      process.exit(2);
    } else if (hasVulnerabilities) {
      process.exit(1);
    }
    
    process.exit(0);
  }
  
  logError(`Unknown command: "${command}". Run vpnvet --help for usage.`);
  printHelp();
  process.exit(1);
}

main().catch(err => {
  logError(`Fatal error: ${err}`);
  process.exit(1);
});
