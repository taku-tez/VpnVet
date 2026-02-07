/**
 * Agent S: CLI output logic & list ordering tests (#4, #5, #6)
 */
import { execSync } from 'node:child_process';
import * as path from 'node:path';

const CLI_PATH = path.join(__dirname, '..', 'dist', 'cli.js');

function runCli(args: string): string {
  try {
    return execSync(`node ${CLI_PATH} ${args}`, {
      encoding: 'utf-8',
      timeout: 10000,
      env: { ...process.env, NODE_NO_WARNINGS: '1' },
    });
  } catch (e: any) {
    return e.stdout || e.stderr || '';
  }
}

describe('list vendors ordering (#6)', () => {
  it('outputs vendors in alphabetical order', () => {
    const output = runCli('list vendors');
    const vendorLines = output.split('\n')
      .filter(l => /^\s{2}\S/.test(l) && l.includes('('))
      .map(l => {
        const match = l.match(/\((\S+)\)/);
        return match ? match[1] : '';
      })
      .filter(Boolean);

    expect(vendorLines.length).toBeGreaterThan(0);
    const sorted = [...vendorLines].sort((a, b) => a.localeCompare(b));
    expect(vendorLines).toEqual(sorted);
  });
});

describe('list vulns ordering (#6)', () => {
  it('outputs vendor groups in alphabetical order', () => {
    const output = runCli('list vulns');
    const vendorHeaders = output.split('\n')
      .filter(l => /^\s{2}[A-Z]/.test(l) && !l.includes('CVE-'))
      .map(l => l.trim());

    expect(vendorHeaders.length).toBeGreaterThan(0);
    const sorted = [...vendorHeaders].sort((a, b) => a.localeCompare(b));
    expect(vendorHeaders).toEqual(sorted);
  });

  it('within a vendor, CVEs are sorted by severity then CVE id', () => {
    const output = runCli('list vulns');
    const lines = output.split('\n');
    const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

    let currentVendorCves: { severity: string; cve: string }[] = [];

    for (const line of lines) {
      const cveMatch = line.match(/^\s{4}(CVE-\S+)\s+\((\w+),/);
      if (cveMatch) {
        currentVendorCves.push({ cve: cveMatch[1], severity: cveMatch[2] });
      } else if (/^\s{2}[A-Z]/.test(line) && !line.includes('CVE-')) {
        // New vendor group - verify previous group was sorted
        if (currentVendorCves.length > 1) {
          const sorted = [...currentVendorCves].sort((a, b) => {
            const sevDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
            if (sevDiff !== 0) return sevDiff;
            return a.cve.localeCompare(b.cve);
          });
          expect(currentVendorCves).toEqual(sorted);
        }
        currentVendorCves = [];
      }
    }
  });
});

describe('CLI output logic (#5)', () => {
  it('prints formatted output to stdout when no --output specified', () => {
    const output = runCli('scan 127.0.0.1 --skip-vuln --skip-version -q -f json');
    expect(output.trim()).toMatch(/^\[/); // JSON array
  });
});
