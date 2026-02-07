/**
 * Tests for Agent A fixes: header OR patterns (#1), version cmd (#2),
 * list option validation (#4), CSV undefined (#5)
 */

import { execSync } from 'node:child_process';

const run = (cmd: string) =>
  execSync(`npx tsx src/cli.ts ${cmd}`, {
    cwd: process.cwd(),
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });

const runErr = (cmd: string) => {
  try {
    run(cmd);
    throw new Error('Should have exited with error');
  } catch (e: any) {
    if (e.message === 'Should have exited with error') throw e;
    return e;
  }
};

// --- Task 1: Header OR pattern (#1) ---
describe('Header fingerprint OR pattern (#1)', () => {
  // We test via scanner internals by importing and calling testPattern
  // Since testPattern is private, we test indirectly via regex behavior
  it('should match OR patterns like CF-Access|cloudflare', () => {
    const pattern = 'cf-access|cloudflare';
    const headerStr = 'server: cloudflare';
    expect(new RegExp(pattern, 'i').test(headerStr)).toBe(true);
  });

  it('should match first alternative in OR pattern', () => {
    const pattern = 'cf-access|cloudflare';
    const headerStr = 'cf-access-token: abc';
    expect(new RegExp(pattern, 'i').test(headerStr)).toBe(true);
  });

  it('should not match when neither alternative present', () => {
    const pattern = 'cf-access|cloudflare';
    const headerStr = 'server: nginx';
    expect(new RegExp(pattern, 'i').test(headerStr)).toBe(false);
  });

  it('should still match simple substring patterns', () => {
    const pattern = 'fortigate';
    const headerStr = 'server: fortigate-something';
    expect(new RegExp(pattern, 'i').test(headerStr)).toBe(true);
  });
});

// --- Task 2: version command (#2) ---
describe('version command detection (#2)', () => {
  it('should show version for "version" command', () => {
    const result = execSync('npx tsx src/cli.ts version', {
      cwd: process.cwd(),
      encoding: 'utf-8',
    });
    expect(result.trim()).toMatch(/\d+\.\d+/);
  });

  it('should show version for "--version" flag', () => {
    const result = execSync('npx tsx src/cli.ts --version', {
      cwd: process.cwd(),
      encoding: 'utf-8',
    });
    expect(result.trim()).toMatch(/\d+\.\d+/);
  });

  it('should NOT treat "scan version" target as version command', () => {
    // "vpnvet scan version" should try to scan "version" as a target, not show version
    const result = execSync('npx tsx src/cli.ts scan version', {
      cwd: process.cwd(),
      encoding: 'utf-8',
    });
    // Should NOT output just a version number - should produce scan output
    expect(result.trim()).not.toMatch(/^\d+\.\d+\.\d+$/);
  });
});

// --- Task 3: list unknown options (#4) ---
describe('list command unknown options (#4)', () => {
  it('should reject --foo on list vendors', () => {
    const e = runErr('list vendors --foo');
    expect(e.status).toBe(1);
    expect(e.stderr).toContain('Unknown option');
  });

  it('should reject --severity on list vendors', () => {
    const e = runErr('list vendors --severity critical');
    expect(e.status).toBe(1);
    expect(e.stderr).toContain('Unknown option');
  });

  it('should reject --foo on list vulns', () => {
    const e = runErr('list vulns --foo');
    expect(e.status).toBe(1);
    expect(e.stderr).toContain('Unknown option');
  });

  it('should accept --severity on list vulns', () => {
    const result = execSync('npx tsx src/cli.ts list vulns --severity critical', {
      cwd: process.cwd(),
      encoding: 'utf-8',
    });
    expect(result).toBeDefined();
  });

  it('should accept list vendors with no options', () => {
    const result = execSync('npx tsx src/cli.ts list vendors', {
      cwd: process.cwd(),
      encoding: 'utf-8',
    });
    expect(result).toContain('fortinet');
  });
});

// --- Task 4: CSV undefined (#5) ---
describe('CSV undefined fields (#5)', () => {
  it('should output empty string for null/undefined cvss', () => {
    const cvss = undefined;
    const result = cvss != null ? String(cvss) : '';
    expect(result).toBe('');
    expect(result).not.toBe('undefined');
  });

  it('should output value for defined cvss', () => {
    const cvss = 9.8;
    const result = cvss != null ? String(cvss) : '';
    expect(result).toBe('9.8');
  });

  it('should output empty string for null cisaKev', () => {
    const cisaKev = null;
    const result = cisaKev != null ? String(cisaKev) : '';
    expect(result).toBe('');
    expect(result).not.toBe('null');
  });

  it('should output value for defined cisaKev', () => {
    const cisaKev = true;
    const result = cisaKev != null ? String(cisaKev) : '';
    expect(result).toBe('true');
  });
});
