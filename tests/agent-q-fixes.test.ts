/**
 * Agent Q: vendor shared normalization (#3), SARIF URI hashing (#4),
 * logError unification (#5)
 */
import { resolveVendor, VENDOR_ALIASES } from '../src/vendor';
import { getAllVendors } from '../src/fingerprints/index';
import { VpnScanner } from '../src/scanner';
import { normalizeTargetUri } from '../src/utils';

describe('resolveVendor shared function (#3)', () => {
  const knownVendors = getAllVendors();

  it('should resolve direct vendor name', () => {
    expect(resolveVendor('fortinet', knownVendors)).toBe('fortinet');
  });

  it('should resolve case-insensitive', () => {
    expect(resolveVendor('FORTINET', knownVendors)).toBe('fortinet');
    expect(resolveVendor('Cisco', knownVendors)).toBe('cisco');
  });

  it('should resolve aliases', () => {
    expect(resolveVendor('palo-alto', knownVendors)).toBe('paloalto');
    expect(resolveVendor('Palo_Alto', knownVendors)).toBe('paloalto');
    expect(resolveVendor('sonic-wall', knownVendors)).toBe('sonicwall');
    expect(resolveVendor('check-point', knownVendors)).toBe('checkpoint');
    expect(resolveVendor('pulse-secure', knownVendors)).toBe('pulse');
  });

  it('should return null for unknown vendors', () => {
    expect(resolveVendor('nonexistent', knownVendors)).toBeNull();
    expect(resolveVendor('', knownVendors)).toBeNull();
  });
});

describe('Scanner vendor normalization via API (#3)', () => {
  it('should accept alias via API constructor', () => {
    // Should not throw
    const scanner = new VpnScanner({ vendor: 'palo-alto' });
    expect(scanner).toBeInstanceOf(VpnScanner);
  });

  it('should accept case-insensitive vendor via API', () => {
    const scanner = new VpnScanner({ vendor: 'FORTINET' });
    expect(scanner).toBeInstanceOf(VpnScanner);
  });

  it('should throw on unknown vendor via API', () => {
    expect(() => new VpnScanner({ vendor: 'nonexistent-vendor' }))
      .toThrow('Unknown vendor');
  });
});

describe('SARIF URI hashing for invalid targets (#4)', () => {
  it('should produce unique URIs for different invalid targets', () => {
    const r1 = normalizeTargetUri(':::invalid1');
    const r2 = normalizeTargetUri(':::invalid2');
    expect(r1.uri).not.toBe(r2.uri);
    expect(r1.originalTarget).toBe(':::invalid1');
    expect(r2.originalTarget).toBe(':::invalid2');
  });

  it('should not use unknown-host fallback', () => {
    const r = normalizeTargetUri(':::bad');
    expect(r.uri).not.toContain('unknown-host');
    expect(r.uri).toMatch(/^https:\/\/invalid-target-[0-9a-f]{12}$/);
  });

  it('should still work for valid targets', () => {
    const r = normalizeTargetUri('vpn.example.com');
    expect(r.uri).toBe('https://vpn.example.com');
    expect(r.originalTarget).toBeUndefined();
  });
});

describe('logError unification (#5)', () => {
  it('should use [vpnvet] ERROR prefix on stderr for unknown command', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts badcommand', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000,
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.stderr).toContain('[vpnvet] ERROR:');
      expect(e.stderr).toContain('badcommand');
    }
  });

  it('should use [vpnvet] ERROR prefix for unknown list subcommand', async () => {
    const { execSync } = await import('node:child_process');
    try {
      execSync('npx tsx src/cli.ts list badsubcmd', {
        cwd: process.cwd(), encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 15000,
      });
      fail('Should have exited with error');
    } catch (e: any) {
      expect(e.stderr).toContain('[vpnvet] ERROR:');
    }
  });
});
