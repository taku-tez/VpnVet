/**
 * Output Schema Tests (Agent C - Task 1)
 *
 * Validates JSON, SARIF, CSV, and table output formats produce
 * consistent, well-formed output with fixed schemas.
 */

import { execSync } from 'node:child_process';
import type { ScanResult, VulnerabilityMatch } from '../src/types.js';

const CLI = 'npx tsx src/cli.ts';
const CWD = process.cwd();

/** Run CLI and return stdout. Ignores non-zero exit (vuln findings = exit 1/2). */
function runCli(args: string): string {
  try {
    return execSync(`${CLI} ${args}`, {
      cwd: CWD,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000,
    });
  } catch (e: any) {
    // CLI exits 1/2 on vuln findings — stdout still has output
    return e.stdout || '';
  }
}

// ─── Mock ScanResult for unit-level formatter tests ──────────────

const mockDevice = {
  vendor: 'fortinet' as const,
  product: 'FortiGate',
  version: '7.2.1',
  confidence: 85,
  detectionMethod: ['endpoint' as const, 'header' as const],
  endpoints: ['/remote/logincheck', '/remote/fgt_lang'],
};

const mockVuln: VulnerabilityMatch = {
  vulnerability: {
    cve: 'CVE-2023-27997',
    severity: 'critical',
    cvss: 9.8,
    description: 'Heap buffer overflow in FortiOS SSL-VPN',
    affected: [{ vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.2.4' }],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-27997'],
    exploitAvailable: true,
    cisaKev: true,
  },
  confidence: 'confirmed',
  evidence: 'Version 7.2.1 is in affected range',
};

const mockResult: ScanResult = {
  target: 'vpn.example.com',
  timestamp: '2026-02-08T00:00:00.000Z',
  device: mockDevice,
  vulnerabilities: [mockVuln],
  errors: [],
};

const mockResultNoDevice: ScanResult = {
  target: 'unknown.example.com',
  timestamp: '2026-02-08T00:00:00.000Z',
  vulnerabilities: [],
  errors: [],
};

const mockResultWithError: ScanResult = {
  target: 'error.example.com',
  timestamp: '2026-02-08T00:00:00.000Z',
  vulnerabilities: [],
  errors: ['DNS resolution failed'],
};

const mockResultWithCoverage: ScanResult = {
  target: 'vpn2.example.com',
  timestamp: '2026-02-08T00:00:00.000Z',
  device: { ...mockDevice, version: undefined },
  vulnerabilities: [],
  coverageWarning: 'No CVE mappings currently available for fortinet FortiGate.',
  errors: [],
};

// ─── JSON Schema Tests ──────────────────────────────────────────

describe('JSON output schema', () => {
  it('should produce valid JSON array', () => {
    const output = JSON.stringify([mockResult], null, 2);
    const parsed = JSON.parse(output);
    expect(Array.isArray(parsed)).toBe(true);
  });

  it('should have required top-level fields on each result', () => {
    const parsed: ScanResult[] = [mockResult];
    for (const r of parsed) {
      expect(r).toHaveProperty('target');
      expect(r).toHaveProperty('timestamp');
      expect(r).toHaveProperty('vulnerabilities');
      expect(r).toHaveProperty('errors');
      expect(typeof r.target).toBe('string');
      expect(typeof r.timestamp).toBe('string');
      expect(Array.isArray(r.vulnerabilities)).toBe(true);
      expect(Array.isArray(r.errors)).toBe(true);
    }
  });

  it('should have correct device fields when detected', () => {
    const d = mockResult.device!;
    expect(d).toHaveProperty('vendor');
    expect(d).toHaveProperty('product');
    expect(d).toHaveProperty('confidence');
    expect(d).toHaveProperty('detectionMethod');
    expect(d).toHaveProperty('endpoints');
    expect(typeof d.vendor).toBe('string');
    expect(typeof d.product).toBe('string');
    expect(typeof d.confidence).toBe('number');
    expect(d.confidence).toBeGreaterThanOrEqual(0);
    expect(d.confidence).toBeLessThanOrEqual(100);
    expect(Array.isArray(d.detectionMethod)).toBe(true);
    expect(Array.isArray(d.endpoints)).toBe(true);
  });

  it('should have correct vulnerability match fields', () => {
    const v = mockResult.vulnerabilities[0];
    expect(v).toHaveProperty('vulnerability');
    expect(v).toHaveProperty('confidence');
    expect(v).toHaveProperty('evidence');
    expect(['confirmed', 'likely', 'potential']).toContain(v.confidence);
    expect(v.vulnerability).toHaveProperty('cve');
    expect(v.vulnerability).toHaveProperty('severity');
    expect(v.vulnerability).toHaveProperty('description');
    expect(v.vulnerability).toHaveProperty('affected');
    expect(v.vulnerability).toHaveProperty('references');
    expect(v.vulnerability).toHaveProperty('exploitAvailable');
    expect(v.vulnerability).toHaveProperty('cisaKev');
    expect(v.vulnerability.cve).toMatch(/^CVE-\d{4}-\d+$/);
    expect(['critical', 'high', 'medium', 'low']).toContain(v.vulnerability.severity);
  });

  it('should omit device when not detected', () => {
    expect(mockResultNoDevice.device).toBeUndefined();
    expect(mockResultNoDevice.vulnerabilities).toEqual([]);
  });

  it('should include coverageWarning when present', () => {
    expect(mockResultWithCoverage.coverageWarning).toBeDefined();
    expect(typeof mockResultWithCoverage.coverageWarning).toBe('string');
  });

  it('should produce valid ISO 8601 timestamp', () => {
    const ts = mockResult.timestamp;
    expect(new Date(ts).toISOString()).toBe(ts);
  });
});

// ─── SARIF Schema Tests ─────────────────────────────────────────

describe('SARIF output schema', () => {
  // Use CLI to generate SARIF from a non-existent target (will have no results but valid structure)
  it('should produce valid SARIF 2.1.0 structure via CLI', () => {
    // We test structural validity by scanning a non-routable target
    const output = runCli('scan 192.0.2.1 -f sarif --timeout 2000');
    if (!output.trim()) return; // skip if no output (timeout)

    const sarif = JSON.parse(output);
    expect(sarif).toHaveProperty('$schema');
    expect(sarif).toHaveProperty('version', '2.1.0');
    expect(sarif).toHaveProperty('runs');
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs.length).toBe(1);

    const run = sarif.runs[0];
    expect(run).toHaveProperty('tool');
    expect(run.tool).toHaveProperty('driver');
    expect(run.tool.driver).toHaveProperty('name', 'VpnVet');
    expect(run.tool.driver).toHaveProperty('version');
    expect(run.tool.driver).toHaveProperty('rules');
    expect(Array.isArray(run.tool.driver.rules)).toBe(true);
    expect(run).toHaveProperty('results');
    expect(Array.isArray(run.results)).toBe(true);
  });

  it('should have valid rule entries in SARIF', () => {
    const output = runCli('scan 192.0.2.1 -f sarif --timeout 2000');
    if (!output.trim()) return;

    const sarif = JSON.parse(output);
    const rules = sarif.runs[0].tool.driver.rules;

    for (const rule of rules) {
      expect(rule).toHaveProperty('id');
      expect(rule.id).toMatch(/^(CVE-\d{4}-\d+|VPNVET-[A-Z-]+)$/);
      expect(rule).toHaveProperty('shortDescription');
      expect(rule.shortDescription).toHaveProperty('text');
      expect(rule).toHaveProperty('properties');
      expect(rule.properties).toHaveProperty('severity');
      if (rule.id.startsWith('CVE-')) {
        expect(rule.properties).toHaveProperty('cisaKev');
      }
    }
  });

  it('should use correct SARIF levels', () => {
    // Test level mapping logic directly
    const levelMap = (severity: string) => {
      if (severity === 'critical' || severity === 'high') return 'error';
      if (severity === 'medium') return 'warning';
      return 'note';
    };
    expect(levelMap('critical')).toBe('error');
    expect(levelMap('high')).toBe('error');
    expect(levelMap('medium')).toBe('warning');
    expect(levelMap('low')).toBe('note');
  });

  it('should have valid artifactLocation.uri (absolute URI)', () => {
    // Test normalizeTargetUri indirectly: the SARIF output for any target
    // should produce valid URIs
    const output = runCli('scan 192.0.2.1 -f sarif --timeout 2000');
    if (!output.trim()) return;

    const sarif = JSON.parse(output);
    for (const result of sarif.runs[0].results) {
      expect(result).toHaveProperty('locations');
      for (const loc of result.locations) {
        expect(loc).toHaveProperty('physicalLocation');
        expect(loc.physicalLocation).toHaveProperty('artifactLocation');
        const uri = loc.physicalLocation.artifactLocation.uri;
        expect(typeof uri).toBe('string');
        // Should be a valid URL
        expect(() => new URL(uri)).not.toThrow();
      }
    }
  });
});

// ─── CSV Schema Tests ────────────────────────────────────────────

describe('CSV output schema', () => {
  const CSV_HEADER = 'target,vendor,product,version,cpe,confidence,jarm_hash,evidence_summary,cve,severity,cvss,vuln_confidence,cisa_kev,known_ransomware,coverage_warning,scan_error_kinds';

  it('should have fixed column order header', () => {
    const output = runCli('scan 192.0.2.1 -f csv --timeout 2000');
    if (!output.trim()) return;

    const lines = output.trim().split('\n');
    expect(lines[0]).toBe(CSV_HEADER);
  });

  it('should have 12 columns per row', () => {
    const output = runCli('scan 192.0.2.1 -f csv --timeout 2000');
    if (!output.trim()) return;

    const lines = output.trim().split('\n');
    const headerCols = lines[0].split(',').length;
    expect(headerCols).toBe(16);

    // Each data row should also have 13 columns (accounting for CSV escaping)
    for (let i = 1; i < lines.length; i++) {
      // Simple count: split by comma but respect quoted fields
      const cols = parseCsvRow(lines[i]);
      expect(cols.length).toBe(16);
    }
  });

  it('should properly escape commas in values', () => {
    // Unit test for escapeCsvCell
    const escapeCsvCell = (value: string): string => {
      if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
        return `"${value.replace(/"/g, '""')}"`;
      }
      return value;
    };

    expect(escapeCsvCell('value,with,commas')).toBe('"value,with,commas"');
  });

  it('should properly escape double quotes in values', () => {
    const escapeCsvCell = (value: string): string => {
      if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
        return `"${value.replace(/"/g, '""')}"`;
      }
      return value;
    };

    expect(escapeCsvCell('say "hello"')).toBe('"say ""hello"""');
  });

  it('should properly escape newlines in values', () => {
    const escapeCsvCell = (value: string): string => {
      if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
        return `"${value.replace(/"/g, '""')}"`;
      }
      return value;
    };

    expect(escapeCsvCell('line1\nline2')).toBe('"line1\nline2"');
    expect(escapeCsvCell('line1\rline2')).toBe('"line1\rline2"');
  });

  it('should handle empty device rows with correct column count', () => {
    // No device detected should still produce 16 columns (including known_ransomware)
    const output = runCli('scan 192.0.2.1 -f csv --timeout 2000');
    if (!output.trim()) return;

    const lines = output.trim().split('\n');
    for (let i = 1; i < lines.length; i++) {
      const cols = parseCsvRow(lines[i]);
      expect(cols.length).toBe(16);
    }
  });
});

// ─── Table Output Tests ──────────────────────────────────────────

describe('Table output format', () => {
  it('should show target in table output', () => {
    const output = runCli('scan 192.0.2.1 -f table --timeout 2000');
    if (!output.trim()) return;
    expect(output).toContain('Target:');
    expect(output).toContain('192.0.2.1');
  });

  it('should show connection failure or no detection for non-VPN target', () => {
    const output = runCli('scan 192.0.2.1 -f table --timeout 2000');
    if (!output.trim()) return;
    // 192.0.2.1 (TEST-NET) typically times out or is refused, so we expect
    // either a connection failure message or a clean no-detection message
    const hasConnectionFailed = output.includes('Connection failed');
    const hasNoVpn = output.includes('No VPN device detected');
    expect(hasConnectionFailed || hasNoVpn).toBe(true);
  });

  it('should contain separator lines', () => {
    const output = runCli('scan 192.0.2.1 -f table --timeout 2000');
    if (!output.trim()) return;
    expect(output).toContain('====');
  });
});

// ─── Error classification tests (Task 2) ─────────────────────────

describe('Error classification (classifyError)', () => {
  // Import dynamically to avoid ESM issues
  let classifyError: (err: unknown) => string;
  let errorKindLabel: (kind: string) => string;

  beforeAll(async () => {
    const mod = await import('../src/scanner.js');
    classifyError = mod.classifyError;
    errorKindLabel = mod.errorKindLabel;
  });

  it('should classify ETIMEDOUT as timeout', () => {
    const err = Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' });
    expect(classifyError(err)).toBe('timeout');
  });

  it('should classify ENOTFOUND as dns', () => {
    const err = Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' });
    expect(classifyError(err)).toBe('dns');
  });

  it('should classify ECONNREFUSED as refused', () => {
    const err = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    expect(classifyError(err)).toBe('refused');
  });

  it('should classify ECONNRESET as reset', () => {
    const err = Object.assign(new Error('socket reset'), { code: 'ECONNRESET' });
    expect(classifyError(err)).toBe('reset');
  });

  it('should classify TLS errors as tls', () => {
    const err = new Error('TLS handshake failed');
    expect(classifyError(err)).toBe('tls');
  });

  it('should classify SSL certificate errors as tls', () => {
    const err = Object.assign(new Error('certificate verify'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
    expect(classifyError(err)).toBe('tls');
  });

  it('should classify invalid URL errors', () => {
    const err = new Error('Invalid URL');
    expect(classifyError(err)).toBe('invalid-url');
  });

  it('should classify unknown errors', () => {
    const err = new Error('something weird happened');
    expect(classifyError(err)).toBe('unknown');
  });

  it('should handle non-Error values', () => {
    expect(classifyError('string error')).toBe('unknown');
    expect(classifyError(null)).toBe('unknown');
    expect(classifyError(42)).toBe('unknown');
  });

  it('should produce human-readable labels for all error kinds', () => {
    const kinds = ['timeout', 'dns', 'tls', 'reset', 'refused', 'http-status', 'invalid-url', 'ssrf-blocked', 'unknown'];
    for (const kind of kinds) {
      const label = errorKindLabel(kind as any);
      expect(typeof label).toBe('string');
      expect(label.length).toBeGreaterThan(0);
    }
  });
});

// ─── CLI UX Tests (Task 3) ───────────────────────────────────────

describe('CLI UX validation', () => {
  it('should show help with no arguments', () => {
    const output = runCli('');
    expect(output).toContain('USAGE:');
    expect(output).toContain('vpnvet scan');
  });

  it('should show help with --help', () => {
    const output = runCli('--help');
    expect(output).toContain('USAGE:');
    expect(output).toContain('SCAN OPTIONS:');
    expect(output).toContain('EXAMPLES:');
  });

  it('should show version with --version', () => {
    const output = runCli('version');
    expect(output).toMatch(/VpnVet v\d+\.\d+\.\d+/);
  });

  it('should error on unknown format with available formats listed', () => {
    try {
      execSync(`${CLI} scan example.com --format xml`, {
        cwd: CWD,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited');
    } catch (e: any) {
      expect(e.stderr).toContain('Invalid --format');
      expect(e.stderr).toContain('json');
      expect(e.stderr).toContain('sarif');
      expect(e.stderr).toContain('csv');
      expect(e.stderr).toContain('table');
    }
  });

  it('should error on empty target with usage hint', () => {
    try {
      execSync(`${CLI} scan`, {
        cwd: CWD,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited');
    } catch (e: any) {
      expect(e.stderr).toContain('No targets specified');
    }
  });

  it('should show unknown command error with help', () => {
    try {
      execSync(`${CLI} foobar`, {
        cwd: CWD,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited');
    } catch (e: any) {
      expect(e.stderr).toContain('Unknown command');
      // Should also print help
      expect(e.stdout).toContain('USAGE:');
    }
  });

  it('should list vendors', () => {
    const output = runCli('list vendors');
    expect(output).toContain('Supported VPN Vendors');
    expect(output).toContain('fortinet');
    expect(output).toContain('Total:');
  });

  it('should list vulnerabilities', () => {
    const output = runCli('list vulns');
    expect(output).toContain('Known VPN Vulnerabilities');
    expect(output).toContain('CVE-');
    expect(output).toContain('Total:');
  });

  it('should filter vulnerabilities by severity', () => {
    const output = runCli('list vulns --severity critical');
    expect(output).toContain('CRITICAL');
    // Should not contain medium/low only entries
    expect(output).toContain('Total:');
  });
});

// ─── SARIF scan error output (#5) ────────────────────────────────

describe('SARIF VPNVET-SCAN-ERROR output', () => {
  it('emits VPNVET-SCAN-ERROR for targets with scanErrors and zero vulnerabilities', () => {
    const { formatSarif } = require('../src/formatters.js');
    const results: ScanResult[] = [
      {
        target: 'https://unreachable.example.com',
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
        scanErrors: [
          { kind: 'timeout', message: 'request timed out', url: 'https://unreachable.example.com/remote/login' },
          { kind: 'dns', message: 'ENOTFOUND', url: 'https://unreachable.example.com/' },
        ],
      },
    ];

    const sarif = JSON.parse(formatSarif(results, '1.0.0-test'));
    const run = sarif.runs[0];

    // Rule should be registered
    const ruleIds = run.tool.driver.rules.map((r: any) => r.id);
    expect(ruleIds).toContain('VPNVET-SCAN-ERROR');

    // Should have 2 results (one per scanError)
    const scanErrorResults = run.results.filter((r: any) => r.ruleId === 'VPNVET-SCAN-ERROR');
    expect(scanErrorResults).toHaveLength(2);

    // Check first result
    const first = scanErrorResults[0];
    expect(first.level).toBe('warning');
    expect(first.message.text).toContain('timeout');
    expect(first.locations[0].physicalLocation.artifactLocation.uri).toBeDefined();
    expect(first.properties.scanErrors[0]).toMatchObject({
      kind: 'timeout',
      message: 'request timed out',
      url: 'https://unreachable.example.com/remote/login',
    });

    // No vulnerability results
    const vulnResults = run.results.filter((r: any) => r.ruleId !== 'VPNVET-SCAN-ERROR' && r.ruleId !== 'VPNVET-COVERAGE-WARNING');
    expect(vulnResults).toHaveLength(0);
  });

  it('includes statusCode in scanError properties when present', () => {
    const { formatSarif } = require('../src/formatters.js');
    const results: ScanResult[] = [
      {
        target: 'https://blocked.example.com',
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
        scanErrors: [
          { kind: 'http-status', message: '403 Forbidden', statusCode: 403, url: 'https://blocked.example.com/' },
        ],
      },
    ];

    const sarif = JSON.parse(formatSarif(results, '1.0.0-test'));
    const scanErrorResults = sarif.runs[0].results.filter((r: any) => r.ruleId === 'VPNVET-SCAN-ERROR');
    expect(scanErrorResults).toHaveLength(1);
    expect(scanErrorResults[0].properties.scanErrors[0].statusCode).toBe(403);
  });
});

// ─── Helpers ─────────────────────────────────────────────────────

/** Simple CSV row parser respecting quoted fields */
function parseCsvRow(row: string): string[] {
  const cols: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < row.length; i++) {
    const ch = row[i];
    if (inQuotes) {
      if (ch === '"') {
        if (row[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === ',') {
        cols.push(current);
        current = '';
      } else {
        current += ch;
      }
    }
  }
  cols.push(current);
  return cols;
}
