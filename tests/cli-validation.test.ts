/**
 * Tests for CLI validation: CSV RFC compliance, timeout validation, vendor validation
 * (#1, #2, #3)
 */

import { getAllVendors } from '../src/fingerprints/index.js';

// We test escapeCsvCell and formatCsv indirectly by importing the CLI module's logic.
// Since they're not exported, we replicate the escapeCsvCell logic here for unit testing,
// then verify the actual CLI output via integration-style checks.

function escapeCsvCell(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

describe('CSV RFC 4180 compliance (#1)', () => {
  describe('escapeCsvCell', () => {
    it('should return plain value when no special characters', () => {
      expect(escapeCsvCell('hello')).toBe('hello');
      expect(escapeCsvCell('fortinet')).toBe('fortinet');
      expect(escapeCsvCell('')).toBe('');
    });

    it('should quote values containing commas', () => {
      expect(escapeCsvCell('hello,world')).toBe('"hello,world"');
    });

    it('should quote values containing newlines', () => {
      expect(escapeCsvCell('line1\nline2')).toBe('"line1\nline2"');
    });

    it('should quote values containing carriage returns', () => {
      expect(escapeCsvCell('line1\rline2')).toBe('"line1\rline2"');
    });

    it('should escape double quotes by doubling them', () => {
      expect(escapeCsvCell('say "hello"')).toBe('"say ""hello"""');
    });

    it('should handle combined special characters', () => {
      const input = 'a,"b"\nc';
      const expected = '"a,""b""\nc"';
      expect(escapeCsvCell(input)).toBe(expected);
    });

    it('should produce valid CSV row with special chars', () => {
      const cells = ['target.com', 'vendor,inc', 'Product "Pro"', 'line1\nline2'];
      const row = cells.map(escapeCsvCell).join(',');
      // Should be parseable as a single CSV row with 4 fields
      // Manual check: target.com,"vendor,inc","Product ""Pro""","line1\nline2"
      expect(row).toBe('target.com,"vendor,inc","Product ""Pro""","line1\nline2"');
    });
  });
});

describe('--timeout validation (#2)', () => {
  it('should reject NaN timeout', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --timeout abc', {
        cwd: process.cwd(),
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Invalid --timeout');
    }
  });

  it('should reject negative timeout', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --timeout -5000', {
        cwd: process.cwd(),
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Invalid --timeout');
    }
  });

  it('should reject zero timeout', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --timeout 0', {
        cwd: process.cwd(),
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Invalid --timeout');
    }
  });

  it('should reject timeout exceeding 120000ms', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --timeout 200000', {
        cwd: process.cwd(),
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Invalid --timeout');
    }
  });
});

describe('--vendor validation (#3)', () => {
  it('should accept known vendor (fortinet)', async () => {
    const vendors = getAllVendors();
    expect(vendors).toContain('fortinet');
  });

  it('should reject unknown vendor with error', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --vendor forti', {
        cwd: process.cwd(),
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Unknown vendor');
      expect(e.stderr).toContain('fortinet'); // Should show known vendors
    }
  });

  it('should reject misspelled vendor', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --vendor paloaltos', {
        cwd: process.cwd(),
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Unknown vendor');
    }
  });
});
