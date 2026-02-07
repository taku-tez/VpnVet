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
import { fingerprints } from './fingerprints/index.js';
import { vulnerabilities } from './vulnerabilities.js';
import { setVerbose, logProgress, logError, logInfo, formatVendorName } from './utils.js';
import type { ScanResult, ScanOptions } from './types.js';

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

function listVendors(): void {
  console.log('\nSupported VPN Vendors:\n');
  
  const vendorProducts = new Map<string, string[]>();
  
  for (const fp of fingerprints) {
    const existing = vendorProducts.get(fp.vendor) || [];
    if (!existing.includes(fp.product)) {
      existing.push(fp.product);
    }
    vendorProducts.set(fp.vendor, existing);
  }
  
  for (const [vendor, products] of vendorProducts) {
    const displayName = formatVendorName(vendor as Parameters<typeof formatVendorName>[0]);
    console.log(`  ${displayName} (${vendor})`);
    for (const product of products) {
      console.log(`    - ${product}`);
    }
  }
  
  console.log(`\nTotal: ${vendorProducts.size} vendors, ${fingerprints.length} fingerprints`);
}

function listVulnerabilities(severity?: string): void {
  console.log('\nKnown VPN Vulnerabilities:\n');
  
  let vulns = vulnerabilities;
  
  if (severity) {
    vulns = vulns.filter(v => v.severity === severity);
  }
  
  // Group by vendor
  const byVendor = new Map<string, typeof vulnerabilities>();
  
  for (const vuln of vulns) {
    const vendors = [...new Set(vuln.affected.map(a => a.vendor))];
    for (const vendor of vendors) {
      const existing = byVendor.get(vendor) || [];
      existing.push(vuln);
      byVendor.set(vendor, existing);
    }
  }
  
  for (const [vendor, vendorVulns] of byVendor) {
    console.log(`  ${vendor.toUpperCase()}`);
    for (const vuln of vendorVulns) {
      const kev = vuln.cisaKev ? ' [KEV]' : '';
      const exploit = vuln.exploitAvailable ? ' [EXPLOIT]' : '';
      console.log(`    ${vuln.cve} (${vuln.severity.toUpperCase()}, CVSS ${vuln.cvss})${kev}${exploit}`);
      console.log(`      ${vuln.description}`);
    }
    console.log();
  }
  
  const kevCount = vulns.filter(v => v.cisaKev).length;
  console.log(`Total: ${vulns.length} CVEs (${kevCount} in CISA KEV)`);
}

function formatTable(results: ScanResult[]): string {
  const lines: string[] = [];
  
  for (const result of results) {
    lines.push(`\n${'='.repeat(60)}`);
    lines.push(`Target: ${result.target}`);
    lines.push(`Scanned: ${result.timestamp}`);
    
    if (result.errors.length > 0) {
      lines.push(`Errors: ${result.errors.join(', ')}`);
    }
    
    if (result.device) {
      const d = result.device;
      lines.push(`\nDevice Detected:`);
      lines.push(`  Vendor: ${d.vendor}`);
      lines.push(`  Product: ${d.product}`);
      if (d.version) lines.push(`  Version: ${d.version}`);
      lines.push(`  Confidence: ${d.confidence}%`);
      lines.push(`  Detection Methods: ${d.detectionMethod.join(', ')}`);
      if (d.endpoints.length > 0) {
        lines.push(`  Endpoints: ${d.endpoints.join(', ')}`);
      }
      
      if (result.vulnerabilities.length > 0) {
        lines.push(`\nPotential Vulnerabilities:`);
        for (const vuln of result.vulnerabilities) {
          const v = vuln.vulnerability;
          const kev = v.cisaKev ? ' 🚨 CISA KEV' : '';
          lines.push(`  [${v.severity.toUpperCase()}] ${v.cve} (CVSS ${v.cvss})${kev}`);
          lines.push(`    ${v.description}`);
          lines.push(`    Confidence: ${vuln.confidence}`);
          lines.push(`    Evidence: ${vuln.evidence}`);
        }
      } else {
        lines.push(`\nNo known vulnerabilities detected.`);
      }
    } else {
      lines.push(`\nNo VPN device detected.`);
    }
  }
  
  return lines.join('\n');
}

function formatJson(results: ScanResult[]): string {
  return JSON.stringify(results, null, 2);
}

function formatSarif(results: ScanResult[]): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'VpnVet',
            version: VERSION,
            informationUri: 'https://github.com/taku-tez/VpnVet',
            rules: vulnerabilities.map(v => ({
              id: v.cve,
              name: v.cve,
              shortDescription: { text: v.description },
              helpUri: v.references[0],
              properties: {
                severity: v.severity,
                cvss: v.cvss,
                cisaKev: v.cisaKev,
              },
            })),
          },
        },
        results: results.flatMap(result =>
          result.vulnerabilities.map(vuln => ({
            ruleId: vuln.vulnerability.cve,
            level: vuln.vulnerability.severity === 'critical' ? 'error' : 
                   vuln.vulnerability.severity === 'high' ? 'error' :
                   vuln.vulnerability.severity === 'medium' ? 'warning' : 'note',
            message: { text: vuln.evidence },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: result.target,
                  },
                },
              },
            ],
            properties: {
              confidence: vuln.confidence,
              device: result.device,
            },
          }))
        ),
      },
    ],
  };
  
  return JSON.stringify(sarif, null, 2);
}

function formatCsv(results: ScanResult[]): string {
  const lines = ['target,vendor,product,version,confidence,cve,severity,cvss,vuln_confidence,cisa_kev'];
  
  for (const result of results) {
    if (result.device) {
      if (result.vulnerabilities.length > 0) {
        for (const vuln of result.vulnerabilities) {
          lines.push([
            result.target,
            result.device.vendor,
            result.device.product,
            result.device.version || '',
            String(result.device.confidence),
            vuln.vulnerability.cve,
            vuln.vulnerability.severity,
            String(vuln.vulnerability.cvss),
            vuln.confidence,
            String(vuln.vulnerability.cisaKev),
          ].join(','));
        }
      } else {
        lines.push([
          result.target,
          result.device.vendor,
          result.device.product,
          result.device.version || '',
          String(result.device.confidence),
          '', '', '', '', '',
        ].join(','));
      }
    } else {
      lines.push([result.target, '', '', '', '', '', '', '', '', ''].join(','));
    }
  }
  
  return lines.join('\n');
}

function formatOutput(results: ScanResult[], format: string): string {
  switch (format) {
    case 'json':
      return formatJson(results);
    case 'sarif':
      return formatSarif(results);
    case 'csv':
      return formatCsv(results);
    case 'table':
    default:
      return formatTable(results);
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }
  
  if (args.includes('version') || args.includes('--version')) {
    printVersion();
    process.exit(0);
  }
  
  const command = args[0];
  
  if (command === 'list') {
    const subCommand = args[1];
    if (subCommand === 'vendors') {
      listVendors();
    } else if (subCommand === 'vulns') {
      const severityIdx = args.indexOf('--severity');
      const severity = severityIdx !== -1 ? args[severityIdx + 1] : undefined;
      listVulnerabilities(severity);
    } else {
      console.error('Unknown list command. Use: list vendors | list vulns');
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
    
    // Parse arguments
    for (let i = 1; i < args.length; i++) {
      const arg = args[i];
      
      if (arg === '-t' || arg === '--targets') {
        const file = args[++i];
        if (!file || !fs.existsSync(file)) {
          console.error(`Targets file not found: ${file}`);
          process.exit(1);
        }
        const content = fs.readFileSync(file, 'utf-8');
        targets = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      } else if (arg === '-o' || arg === '--output') {
        options.output = args[++i];
      } else if (arg === '-f' || arg === '--format') {
        options.format = args[++i] as CliOptions['format'];
      } else if (arg === '--timeout') {
        options.timeout = parseInt(args[++i], 10);
      } else if (arg === '--ports') {
        const rawPorts = args[++i].split(',').map(p => parseInt(p, 10));
        const validPorts = [...new Set(rawPorts)].filter(p => !isNaN(p) && p >= 1 && p <= 65535);
        if (validPorts.length === 0) {
          logError('Invalid --ports value. Ports must be numbers between 1-65535.');
          process.exit(1);
        }
        options.ports = validPorts;
      } else if (arg === '--skip-vuln') {
        options.skipVulnCheck = true;
      } else if (arg === '--skip-version') {
        options.skipVersionDetection = true;
      } else if (arg === '-q' || arg === '--quiet') {
        options.quiet = true;
      } else if (arg === '-v' || arg === '--verbose') {
        options.verbose = true;
      } else if (arg === '--vendor') {
        options.vendor = args[++i];
      } else if (arg === '--fast') {
        options.fast = true;
      } else if (!arg.startsWith('-')) {
        targets.push(arg);
      }
    }
    
    if (targets.length === 0) {
      logError('No targets specified. Provide a target or use --targets <file>');
      process.exit(1);
    }
    
    // Set verbose mode for logging
    if (options.verbose) {
      setVerbose(true);
    }
    
    if (!options.quiet) {
      logInfo(`VpnVet v${VERSION} - Scanning ${targets.length} target(s)...`);
    }
    
    const scanner = new VpnScanner(options);
    const results: ScanResult[] = [];
    
    for (let i = 0; i < targets.length; i++) {
      const target = targets[i];
      
      if (!options.quiet) {
        process.stdout.write(`[${i + 1}/${targets.length}] Scanning ${target}...`);
      }
      
      const result = await scanner.scan(target);
      results.push(result);
      
      if (!options.quiet) {
        if (result.device) {
          console.log(` ✓ ${result.device.vendor} ${result.device.product} (${result.device.confidence}%)`);
        } else if (result.errors.length > 0) {
          console.log(` ✗ Error: ${result.errors[0]}`);
        } else {
          console.log(' - No VPN detected');
        }
      }
    }
    
    const output = formatOutput(results, options.format);
    
    if (options.output) {
      const outputPath = path.resolve(options.output);
      fs.writeFileSync(outputPath, output);
      if (!options.quiet) {
        console.log(`\nResults written to: ${outputPath}`);
      }
    } else if (options.format !== 'table' || options.quiet) {
      console.log(output);
    } else {
      console.log(output);
    }
    
    // Exit code based on findings
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
  
  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
