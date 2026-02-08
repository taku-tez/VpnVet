/**
 * Version Detection Tests
 *
 * Validates versionExtract regex patterns for Tier 1 vendors.
 */

import { tier1enterpriseFingerprints } from '../src/fingerprints/tier1-enterprise.js';

function getPatterns(vendor: string) {
  const fp = tier1enterpriseFingerprints.find(f => f.vendor === vendor);
  if (!fp) throw new Error(`Vendor ${vendor} not found`);
  return fp.patterns.filter(p => p.versionExtract);
}

describe('Version Detection - Tier 1 Enterprise', () => {
  // ============================================================
  // Fortinet
  // ============================================================
  describe('Fortinet version extraction', () => {
    const patterns = getPatterns('fortinet');

    it('should have at least 2 versionExtract patterns', () => {
      expect(patterns.length).toBeGreaterThanOrEqual(2);
    });

    it('should extract version from firmware API response', () => {
      const p = patterns.find(p => p.path === '/api/v2/monitor/system/firmware');
      expect(p).toBeDefined();
      const body = '{"version": "v7.4.3", "build": "2573"}';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('7.4.3');
    });

    it('should extract version without v prefix from firmware API', () => {
      const p = patterns.find(p => p.path === '/api/v2/monitor/system/firmware');
      const body = '{"version": "7.2.5", "serial": "FGT60F"}';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('7.2.5');
    });

    it('should extract FortiOS version from login page', () => {
      const p = patterns.find(p => p.path === '/remote/login');
      expect(p).toBeDefined();
      const body = '<title>FortiOS v7.0.14 SSL VPN</title>';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('7.0.14');
    });

    it('should extract build number from fgt_lang', () => {
      const p = patterns.find(p => p.path === '/remote/fgt_lang?lang=en');
      expect(p).toBeDefined();
      const body = '{"msg": {"login": "Please login"}, "build": "2573"}';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('2573');
    });
  });

  // ============================================================
  // Palo Alto
  // ============================================================
  describe('Palo Alto version extraction', () => {
    const patterns = getPatterns('paloalto');

    it('should have at least 2 versionExtract patterns', () => {
      expect(patterns.length).toBeGreaterThanOrEqual(2);
    });

    it('should extract PAN-OS version from prelogin.esp', () => {
      const p = patterns.find(p => p.path === '/global-protect/prelogin.esp');
      expect(p).toBeDefined();
      const body = '<prelogin-response><status>success</status><panos-version>11.1.2-h3</panos-version></prelogin-response>';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('11.1.2-h3');
    });

    it('should extract PAN-OS version from ssl-vpn prelogin', () => {
      const p = patterns.find(p => p.path === '/ssl-vpn/prelogin.esp');
      expect(p).toBeDefined();
      const body = '<prelogin-response><panos-version>10.2.9</panos-version></prelogin-response>';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('10.2.9');
    });
  });

  // ============================================================
  // Cisco
  // ============================================================
  describe('Cisco version extraction', () => {
    const patterns = getPatterns('cisco');

    it('should have at least 2 versionExtract patterns', () => {
      expect(patterns.length).toBeGreaterThanOrEqual(2);
    });

    it('should extract ASA version from config-auth XML', () => {
      const p = patterns.find(p => p.path === '/CSCOSSLC/config-auth');
      expect(p).toBeDefined();
      const body = '<config-auth client="vpn"><version who="sg">9.18.3</version></config-auth>';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('9.18.3');
    });

    it('should extract version from logon page', () => {
      const p = patterns.find(p => p.path === '/+CSCOE+/logon.html');
      expect(p).toBeDefined();
      const body = '<p>Cisco ASA Version 9.16.4(57)</p>';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('9.16.4(57)');
    });

    it('should extract X-Transcend-Version', () => {
      const p = patterns.find(p => p.type === 'header' && String(p.match).includes('X-Transcend-Version'));
      expect(p).toBeDefined();
      const header = 'X-Transcend-Version: 1';
      const match = p!.versionExtract!.exec(header);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('1');
    });
  });

  // ============================================================
  // Ivanti / Pulse Connect Secure
  // ============================================================
  describe('Ivanti/Pulse version extraction', () => {
    const ivantiPatterns = getPatterns('ivanti');
    const pulsePatterns = getPatterns('pulse');

    it('Ivanti should have at least 2 versionExtract patterns', () => {
      expect(ivantiPatterns.length).toBeGreaterThanOrEqual(2);
    });

    it('Pulse should have at least 2 versionExtract patterns', () => {
      expect(pulsePatterns.length).toBeGreaterThanOrEqual(2);
    });

    it('should extract ProductVersion from welcome.cgi (Ivanti)', () => {
      const p = ivantiPatterns.find(p => p.path === '/dana-na/auth/url_default/welcome.cgi');
      expect(p).toBeDefined();
      const body = '<INPUT TYPE="hidden" NAME="ProductVersion" VALUE="22.7.1.3456">';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('22.7.1.3456');
    });

    it('should extract ProductVersion from welcome.cgi (Pulse)', () => {
      const p = pulsePatterns.find(p => p.path === '/dana-na/auth/url_default/welcome.cgi');
      expect(p).toBeDefined();
      const body = '<INPUT TYPE="hidden" NAME="ProductVersion" VALUE="9.1.18.3456">';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('9.1.18.3456');
    });

    it('should extract version from HostChecker installer', () => {
      const p = ivantiPatterns.find(p => p.path?.includes('HostCheckerInstaller'));
      expect(p).toBeDefined();
      const body = '<plist><dict><key>CFBundleVersion</key><string>22.7.1.3456</string></dict></plist>';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('22.7.1.3456');
    });
  });

  // ============================================================
  // Citrix
  // ============================================================
  describe('Citrix version extraction', () => {
    const patterns = getPatterns('citrix');

    it('should have at least 2 versionExtract patterns', () => {
      expect(patterns.length).toBeGreaterThanOrEqual(2);
    });

    it('should extract plugin version from pluginlist.xml', () => {
      const p = patterns.find(p => p.path === '/vpn/pluginlist.xml');
      expect(p).toBeDefined();
      const body = '<plugin name="Netscaler Gateway EPA plug-in" type="WIN-EPA" version="23.5.1.3" path="/epa/scripts/win/nsepa_setup.exe"/>';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('23.5.1.3');
    });

    it('should extract build hash from vpn/index.html', () => {
      const p = patterns.find(p => p.path === '/vpn/index.html' && p.versionExtract);
      expect(p).toBeDefined();
      const body = '<link rel="stylesheet" href="/vpn/css/ctxs.css?v=dc8897f429a694d44934954b47118908">';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('dc8897f429a694d44934954b47118908');
    });

    it('should extract hash from LogonPoint index.html', () => {
      const p = patterns.find(p => p.path === '/logon/LogonPoint/index.html');
      expect(p).toBeDefined();
      const body = '<script src="/logon/LogonPoint/bundle.js?v=43a8abf580ea09a5fa8aa1bd579280b9"></script>';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe('43a8abf580ea09a5fa8aa1bd579280b9');
    });
  });

  // ============================================================
  // Citrix EPA macOS/Linux and NSAPI patterns (Feb 2026 additions)
  // ============================================================
  describe('Citrix EPA extended paths', () => {
    const citrix = tier1enterpriseFingerprints.find(f => f.vendor === 'citrix');
    const patterns = citrix!.patterns;

    it('should have macOS EPA installer path', () => {
      const p = patterns.find(p => p.path === '/epa/scripts/mac/nsepa_setup.dmg');
      expect(p).toBeDefined();
      expect(p!.method).toBe('HEAD');
      expect(p!.weight).toBe(8);
    });

    it('should have Linux EPA installer path', () => {
      const p = patterns.find(p => p.path === '/epa/scripts/linux/nsepa_setup.sh');
      expect(p).toBeDefined();
      expect(p!.method).toBe('HEAD');
    });

    it('should have NSAPI version endpoint', () => {
      const p = patterns.find(p => p.path === '/nitro/v1/config/nsversion');
      expect(p).toBeDefined();
      expect(p!.versionExtract).toBeDefined();
    });

    it('should extract version from NSAPI response', () => {
      const p = patterns.find(p => p.path === '/nitro/v1/config/nsversion');
      const body = '{"nsversion": {"version": "NS14.1 Build 30.52"}}';
      const match = p!.versionExtract!.exec(body);
      expect(match).not.toBeNull();
    });

    it('should have DTLS/nsap.js detection', () => {
      const p = patterns.find(p => p.path === '/cginfra/https/scripts/ctxnsap.js');
      expect(p).toBeDefined();
      expect(p!.weight).toBe(8);
    });
  });

  // ============================================================
  // Cross-vendor: all versionExtract regexes should be valid
  // ============================================================
  describe('All versionExtract patterns are valid RegExp', () => {
    for (const fp of tier1enterpriseFingerprints) {
      for (const pattern of fp.patterns) {
        if (pattern.versionExtract) {
          it(`${fp.vendor}/${fp.product} - ${pattern.path || pattern.match} regex is valid`, () => {
            expect(pattern.versionExtract).toBeInstanceOf(RegExp);
            // Ensure it has at least one capture group
            const src = pattern.versionExtract!.source;
            expect(src).toMatch(/\(/);
          });
        }
      }
    }
  });
});
