/**
 * Agent H: UX improvements (#3 SARIF URI, #4 vendor case, #7 KNOWN_FLAGS)
 */
import { normalizeTargetUri } from '../src/utils';

describe('SARIF URI normalization (#3)', () => {
  it('should prepend https:// to bare hostname', () => {
    const result = normalizeTargetUri('vpn.example.com');
    expect(result.uri).toBe('https://vpn.example.com');
    expect(result.originalTarget).toBeUndefined();
  });

  it('should keep existing https:// scheme', () => {
    const result = normalizeTargetUri('https://vpn.example.com');
    expect(result.uri).toBe('https://vpn.example.com');
  });

  it('should keep existing http:// scheme', () => {
    const result = normalizeTargetUri('http://vpn.example.com');
    expect(result.uri).toBe('http://vpn.example.com');
  });

  it('should handle hostname with port', () => {
    const result = normalizeTargetUri('vpn.example.com:8443');
    expect(result.uri).toBe('https://vpn.example.com:8443');
  });

  it('should handle hostname with path', () => {
    const result = normalizeTargetUri('vpn.example.com/login');
    expect(result.uri).toBe('https://vpn.example.com/login');
  });

  it('should trim whitespace', () => {
    const result = normalizeTargetUri('  vpn.example.com  ');
    expect(result.uri).toBe('https://vpn.example.com');
  });
});

describe('--vendor case-insensitive matching (#4)', () => {
  it('should accept lowercase vendor (fortinet)', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --vendor fortinet --timeout 1000', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000,
      });
    } catch (e: any) {
      // Should NOT fail with "Unknown vendor"
      expect(e.stderr || '').not.toContain('Unknown vendor');
    }
  });

  it('should accept uppercase vendor (Fortinet)', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --vendor Fortinet --timeout 1000', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000,
      });
    } catch (e: any) {
      expect(e.stderr || '').not.toContain('Unknown vendor');
    }
  });

  it('should accept mixed case vendor (FORTINET)', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --vendor FORTINET --timeout 1000', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000,
      });
    } catch (e: any) {
      expect(e.stderr || '').not.toContain('Unknown vendor');
    }
  });

  it('should accept alias palo-alto → paloalto', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --vendor palo-alto --timeout 1000', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000,
      });
    } catch (e: any) {
      expect(e.stderr || '').not.toContain('Unknown vendor');
    }
  });

  it('should accept alias Palo-Alto (case+alias)', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --vendor Palo-Alto --timeout 1000', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000,
      });
    } catch (e: any) {
      expect(e.stderr || '').not.toContain('Unknown vendor');
    }
  });

  it('should reject truly unknown vendor with helpful message', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts scan example.com --vendor NotAVendor', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Unknown vendor');
      expect(e.stderr).toContain('NotAVendor');
      expect(e.stderr).toContain('fortinet');
    }
  });
});

describe('KNOWN_FLAGS per-subcommand validation (#7)', () => {
  it('should reject --vendor on list vendors subcommand', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts list vendors --vendor fortinet', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Unknown option');
    }
  });

  it('should reject --timeout on list vulns subcommand', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts list vulns --timeout 5000', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'],
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.status).toBe(1);
      expect(e.stderr).toContain('Unknown option');
    }
  });

  it('should allow --severity on list vulns', async () => {
    const { execSync } = await import('node:child_process');
    const output = execSync('npx tsx src/cli.ts list vulns --severity critical', {
      cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 15000,
    });
    expect(output).toContain('CVE');
  });
});
