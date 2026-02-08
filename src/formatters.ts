/**
 * VpnVet Output Formatters
 *
 * Converts ScanResult arrays into various output formats:
 * JSON, SARIF, CSV, and human-readable table.
 */

import { vulnerabilities } from './vulnerabilities.js';
import { fingerprints } from './fingerprints/index.js';
import { formatVendorName, normalizeTargetUri } from './utils.js';
import type { ScanResult } from './types.js';

// ---------------------------------------------------------------------------
// List commands
// ---------------------------------------------------------------------------

export function listVendors(): void {
  console.log('\nSupported VPN Vendors:\n');
  
  const vendorProducts = new Map<string, string[]>();
  
  for (const fp of fingerprints) {
    const existing = vendorProducts.get(fp.vendor) || [];
    if (!existing.includes(fp.product)) {
      existing.push(fp.product);
    }
    vendorProducts.set(fp.vendor, existing);
  }
  
  const sortedVendors = [...vendorProducts.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  for (const [vendor, products] of sortedVendors) {
    const displayName = formatVendorName(vendor as Parameters<typeof formatVendorName>[0]);
    console.log(`  ${displayName} (${vendor})`);
    for (const product of products) {
      console.log(`    - ${product}`);
    }
  }
  
  console.log(`\nTotal: ${vendorProducts.size} vendors, ${fingerprints.length} fingerprints`);
}

export function listVulnerabilities(severity?: string): void {
  console.log('\nKnown VPN Vulnerabilities:\n');
  
  let vulns = vulnerabilities;
  
  if (severity) {
    vulns = vulns.filter(v => v.severity === severity);
  }
  
  const byVendor = new Map<string, typeof vulnerabilities>();
  
  for (const vuln of vulns) {
    const vendors = [...new Set(vuln.affected.map(a => a.vendor))];
    for (const vendor of vendors) {
      const existing = byVendor.get(vendor) || [];
      existing.push(vuln);
      byVendor.set(vendor, existing);
    }
  }
  
  const sortedVulnVendors = [...byVendor.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  for (const [vendor, vendorVulns] of sortedVulnVendors) {
    console.log(`  ${vendor.toUpperCase()}`);
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    vendorVulns.sort((a, b) => {
      const sevDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
      if (sevDiff !== 0) return sevDiff;
      return a.cve.localeCompare(b.cve);
    });
    for (const vuln of vendorVulns) {
      const kev = vuln.cisaKev ? ' [KEV]' : '';
      const exploit = vuln.exploitAvailable ? ' [EXPLOIT]' : '';
      const ransomware = vuln.knownRansomware ? ' [RANSOMWARE]' : '';
      console.log(`    ${vuln.cve} (${vuln.severity.toUpperCase()}, CVSS ${vuln.cvss})${kev}${exploit}${ransomware}`);
      console.log(`      ${vuln.description}`);
    }
    console.log();
  }
  
  const kevCount = vulns.filter(v => v.cisaKev).length;
  console.log(`Total: ${vulns.length} CVEs (${kevCount} in CISA KEV)`);
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

export function formatTable(results: ScanResult[]): string {
  const lines: string[] = [];
  
  for (const result of results) {
    lines.push(`\n${'='.repeat(60)}`);
    lines.push(`Target: ${result.target}`);
    lines.push(`Scanned: ${result.timestamp}`);
    
    if (result.errors.length > 0) {
      lines.push(`Errors: ${result.errors.join(', ')}`);
    }
    if (result.scanErrors && result.scanErrors.length > 0) {
      for (const se of result.scanErrors) {
        lines.push(`  [${se.kind}] ${se.message}${se.statusCode ? ` (HTTP ${se.statusCode})` : ''}`);
      }
    }
    
    if (result.device) {
      const d = result.device;
      lines.push(`\nDevice Detected:`);
      lines.push(`  Vendor: ${formatVendorName(d.vendor)}`);
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
          const ransomware = v.knownRansomware ? ' 💀 Ransomware' : '';
          lines.push(`  [${v.severity.toUpperCase()}] ${v.cve} (CVSS ${v.cvss})${kev}${ransomware}`);
          lines.push(`    ${v.description}`);
          lines.push(`    Confidence: ${vuln.confidence}`);
          lines.push(`    Evidence: ${vuln.evidence}`);
        }
      } else {
        lines.push(`\nNo known vulnerabilities detected.`);
      }

      if (result.coverageWarning) {
        lines.push(`\n⚠️  Coverage Warning: ${result.coverageWarning}`);
      }
    } else if (result.scanErrors && result.scanErrors.length > 0) {
      const kinds = result.scanErrors.map(e => e.kind).filter((v, i, a) => a.indexOf(v) === i).join('/');
      lines.push(`\n⚠ Connection failed (${kinds})`);
    } else {
      lines.push(`\n✗ No VPN device detected`);
    }
  }
  
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

export function formatJson(results: ScanResult[]): string {
  return JSON.stringify(results, null, 2);
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
  properties: Record<string, unknown>;
}

export function formatSarif(results: ScanResult[], version: string): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'VpnVet',
            version,
            informationUri: 'https://github.com/taku-tez/VpnVet',
            rules: [
              ...vulnerabilities.map(v => ({
                id: v.cve,
                name: v.cve,
                shortDescription: { text: v.description },
                helpUri: v.references[0],
                properties: {
                  severity: v.severity,
                  cvss: v.cvss,
                  cisaKev: v.cisaKev,
                  knownRansomware: v.knownRansomware || false,
                },
              })),
              {
                id: 'VPNVET-COVERAGE-WARNING',
                name: 'CoverageWarning',
                shortDescription: { text: 'VPN device detected but no CVE mappings available for this product' },
                properties: {
                  severity: 'note',
                },
              },
            ],
          },
        },
        results: results.flatMap(result => {
          const { uri, originalTarget } = normalizeTargetUri(result.target);
          const vulnResults: SarifResult[] = result.vulnerabilities.map(vuln => ({
            ruleId: vuln.vulnerability.cve,
            level: vuln.vulnerability.severity === 'critical' ? 'error' : 
                   vuln.vulnerability.severity === 'high' ? 'error' :
                   vuln.vulnerability.severity === 'medium' ? 'warning' : 'note',
            message: { text: vuln.evidence },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri,
                  },
                },
              },
            ],
            properties: {
              confidence: vuln.confidence,
              device: result.device,
              ...(originalTarget ? { originalTarget } : {}),
              ...(result.coverageWarning ? { coverageWarning: result.coverageWarning } : {}),
              ...(result.scanErrors?.length ? { scanErrors: result.scanErrors } : {}),
            },
          }));

          if (result.coverageWarning) {
            vulnResults.push({
              ruleId: 'VPNVET-COVERAGE-WARNING',
              level: 'note',
              message: { text: result.coverageWarning },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri,
                    },
                  },
                },
              ],
              properties: {
                confidence: 'informational',
                device: result.device,
                ...(originalTarget ? { originalTarget } : {}),
              },
            });
          }

          return vulnResults;
        }),
      },
    ],
  };
  
  return JSON.stringify(sarif, null, 2);
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

function escapeCsvCell(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function formatCsv(results: ScanResult[]): string {
  const lines = ['target,vendor,product,version,confidence,cve,severity,cvss,vuln_confidence,cisa_kev,known_ransomware,coverage_warning,scan_error_kinds'];
  
  for (const result of results) {
    const errorKinds = result.scanErrors?.map(e => e.kind).join(';') || '';
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
            vuln.vulnerability.cvss != null ? String(vuln.vulnerability.cvss) : '',
            vuln.confidence,
            vuln.vulnerability.cisaKev != null ? String(vuln.vulnerability.cisaKev) : '',
            vuln.vulnerability.knownRansomware ? 'true' : 'false',
            result.coverageWarning || '',
            errorKinds,
          ].map(escapeCsvCell).join(','));
        }
      } else {
        lines.push([
          result.target,
          result.device.vendor,
          result.device.product,
          result.device.version || '',
          String(result.device.confidence),
          '', '', '', '', '',
          result.coverageWarning || '',
          errorKinds,
        ].map(escapeCsvCell).join(','));
      }
    } else {
      lines.push([result.target, '', '', '', '', '', '', '', '', '', '', errorKinds].map(escapeCsvCell).join(','));
    }
  }
  
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

export function formatOutput(results: ScanResult[], format: string, version?: string): string {
  switch (format) {
    case 'json':
      return formatJson(results);
    case 'sarif':
      return formatSarif(results, version || 'unknown');
    case 'csv':
      return formatCsv(results);
    case 'table':
    default:
      return formatTable(results);
  }
}
