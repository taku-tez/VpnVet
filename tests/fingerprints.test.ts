/**
 * Fingerprint Tests
 */

import { fingerprints, getFingerprintsByVendor, getAllVendors } from '../src/fingerprints/index.js';

describe('Fingerprints', () => {
  describe('fingerprints database', () => {
    it('should have fingerprints for major vendors', () => {
      const vendors = getAllVendors();
      
      // Original 9 vendors
      expect(vendors).toContain('fortinet');
      expect(vendors).toContain('paloalto');
      expect(vendors).toContain('cisco');
      expect(vendors).toContain('pulse');
      expect(vendors).toContain('ivanti');
      expect(vendors).toContain('sonicwall');
      expect(vendors).toContain('checkpoint');
      expect(vendors).toContain('citrix');
      expect(vendors).toContain('openvpn');
      
      // New vendors
      expect(vendors).toContain('f5');
      expect(vendors).toContain('juniper');
      expect(vendors).toContain('zyxel');
      expect(vendors).toContain('sophos');
      expect(vendors).toContain('watchguard');
      expect(vendors).toContain('barracuda');
      expect(vendors).toContain('sangfor');
      expect(vendors).toContain('array');
    });

    it('should have at least 35 vendors', () => {
      const vendors = getAllVendors();
      expect(vendors.length).toBeGreaterThanOrEqual(35);
    });

    it('should have valid fingerprint structure', () => {
      for (const fp of fingerprints) {
        expect(fp.vendor).toBeDefined();
        expect(fp.product).toBeDefined();
        expect(Array.isArray(fp.patterns)).toBe(true);
        expect(fp.patterns.length).toBeGreaterThan(0);

        for (const pattern of fp.patterns) {
          expect(pattern.type).toBeDefined();
          expect(pattern.match).toBeDefined();
          expect(typeof pattern.weight).toBe('number');
          expect(pattern.weight).toBeGreaterThanOrEqual(1);
          expect(pattern.weight).toBeLessThanOrEqual(10);
        }
      }
    });
  });

  describe('getFingerprintsByVendor', () => {
    it('should return fingerprints for fortinet', () => {
      const fortinet = getFingerprintsByVendor('fortinet');
      expect(fortinet.length).toBeGreaterThan(0);
      expect(fortinet[0].vendor).toBe('fortinet');
    });

    it('should return empty array for unknown vendor', () => {
      const unknown = getFingerprintsByVendor('unknown-vendor');
      expect(unknown).toEqual([]);
    });
  });

  describe('FortiGate patterns', () => {
    it('should have /remote/login endpoint pattern', () => {
      const fortinet = getFingerprintsByVendor('fortinet')[0];
      const loginPattern = fortinet.patterns.find(
        p => p.type === 'endpoint' && p.path === '/remote/login'
      );
      expect(loginPattern).toBeDefined();
      expect(loginPattern?.weight).toBeGreaterThanOrEqual(8);
    });

    it('should have SVPNCOOKIE header pattern', () => {
      const fortinet = getFingerprintsByVendor('fortinet')[0];
      const cookiePattern = fortinet.patterns.find(
        p => p.type === 'header' && String(p.match).includes('SVPNCOOKIE')
      );
      expect(cookiePattern).toBeDefined();
    });
  });

  describe('Palo Alto patterns', () => {
    it('should have GlobalProtect endpoint patterns', () => {
      const paloalto = getFingerprintsByVendor('paloalto')[0];
      const gpPattern = paloalto.patterns.find(
        p => p.type === 'endpoint' && p.path?.includes('global-protect')
      );
      expect(gpPattern).toBeDefined();
    });
  });

  describe('Cisco patterns', () => {
    it('should have AnyConnect endpoint patterns', () => {
      const cisco = getFingerprintsByVendor('cisco')[0];
      const anyconnectPattern = cisco.patterns.find(
        p => p.type === 'endpoint' && p.path?.includes('CSCOE')
      );
      expect(anyconnectPattern).toBeDefined();
    });
  });

  describe('Pulse/Ivanti patterns', () => {
    it('should have dana-na endpoint patterns', () => {
      const pulse = getFingerprintsByVendor('pulse')[0];
      const danaPattern = pulse.patterns.find(
        p => p.type === 'endpoint' && p.path?.includes('dana-na')
      );
      expect(danaPattern).toBeDefined();
    });
  });

  describe('Citrix patterns', () => {
    it('should have NetScaler/Gateway patterns', () => {
      const citrix = getFingerprintsByVendor('citrix')[0];
      const citrixPattern = citrix.patterns.find(
        p => p.type === 'endpoint' && (p.path?.includes('vpn') || p.path?.includes('logon'))
      );
      expect(citrixPattern).toBeDefined();
    });
  });

  describe('F5 BIG-IP patterns', () => {
    it('should have APM endpoint patterns', () => {
      const f5 = getFingerprintsByVendor('f5')[0];
      expect(f5).toBeDefined();
      expect(f5.product).toBe('BIG-IP APM');
      
      const policyPattern = f5.patterns.find(
        p => p.type === 'endpoint' && p.path?.includes('my.policy')
      );
      expect(policyPattern).toBeDefined();
    });

    it('should have BIGipServer cookie pattern', () => {
      const f5 = getFingerprintsByVendor('f5')[0];
      const cookiePattern = f5.patterns.find(
        p => p.type === 'header' && String(p.match).includes('BIGipServer')
      );
      expect(cookiePattern).toBeDefined();
    });
  });

  describe('Zyxel patterns', () => {
    it('should have USG/ZyWALL patterns', () => {
      const zyxel = getFingerprintsByVendor('zyxel')[0];
      expect(zyxel).toBeDefined();
      expect(zyxel.product).toBe('USG/ZyWALL');
    });

    it('should have firmware info API endpoint pattern', () => {
      const zyxel = getFingerprintsByVendor('zyxel')[0];
      const apiPattern = zyxel.patterns.find(p => p.path === '/api/firmware/info');
      expect(apiPattern).toBeDefined();
      expect(apiPattern?.versionExtract).toBeDefined();
    });

    it('should extract version from firmware info', () => {
      const zyxel = getFingerprintsByVendor('zyxel')[0];
      const apiPattern = zyxel.patterns.find(p => p.path === '/api/firmware/info');
      const match = '{"fw_ver": "V5.40(ABCD.0)"}' .match(apiPattern!.versionExtract!);
      expect(match?.[1]).toBe('5.40');
    });
  });

  describe('WatchGuard patterns', () => {
    it('should have Firebox patterns with admin wizard endpoint', () => {
      const wg = getFingerprintsByVendor('watchguard')[0];
      expect(wg).toBeDefined();
      const wizardPattern = wg.patterns.find(p => p.path === '/wizard/Wizard_Portal.html');
      expect(wizardPattern).toBeDefined();
      expect(wizardPattern?.weight).toBe(9);
    });

    it('should have Fireware Web UI title pattern', () => {
      const wg = getFingerprintsByVendor('watchguard')[0];
      const titlePattern = wg.patterns.find(p =>
        p.type === 'body' && p.match?.includes('Fireware')
      );
      expect(titlePattern).toBeDefined();
      expect(titlePattern?.versionExtract).toBeDefined();
    });
  });

  describe('SonicWall patterns', () => {
    it('should have SonicOS 7.x version extraction', () => {
      const sw = getFingerprintsByVendor('sonicwall')[0];
      const sonicui = sw.patterns.find(p => p.path === '/sonicui/7/login/');
      expect(sonicui).toBeDefined();
      expect(sonicui?.versionExtract).toBeDefined();
    });

    it('should have API version endpoint', () => {
      const sw = getFingerprintsByVendor('sonicwall')[0];
      const apiPattern = sw.patterns.find(p => p.path === '/api/sonicos/version');
      expect(apiPattern).toBeDefined();
      expect(apiPattern?.versionExtract).toBeDefined();
    });

    it('should extract SonicOS version', () => {
      const sw = getFingerprintsByVendor('sonicwall')[0];
      const sonicui = sw.patterns.find(p => p.path === '/sonicui/7/login/');
      const match = 'SonicOS 7.1.1-7040'.match(sonicui!.versionExtract!);
      expect(match?.[1]).toBe('7.1.1-7040');
    });
  });

  describe('Sophos patterns', () => {
    it('should have XG Firewall patterns', () => {
      const sophos = getFingerprintsByVendor('sophos')[0];
      expect(sophos).toBeDefined();
      expect(sophos.product).toBe('XG Firewall');
    });
  });

  describe('no duplicate vendor+product combinations', () => {
    it('should not have duplicate vendor+product pairs', () => {
      const seen = new Set<string>();
      const duplicates: string[] = [];
      for (const fp of fingerprints) {
        const key = `${fp.vendor}:${fp.product}`;
        if (seen.has(key)) {
          duplicates.push(key);
        }
        seen.add(key);
      }
      expect(duplicates).toEqual([]);
    });
  });

  describe('required fields', () => {
    it('should have non-empty vendor and product strings', () => {
      for (const fp of fingerprints) {
        expect(fp.vendor.length).toBeGreaterThan(0);
        expect(fp.product.length).toBeGreaterThan(0);
      }
    });

    it('every pattern should have a valid type', () => {
      const validTypes = ['endpoint', 'header', 'body', 'title', 'certificate', 'favicon'];
      for (const fp of fingerprints) {
        for (const p of fp.patterns) {
          expect(validTypes).toContain(p.type);
        }
      }
    });
  });

  describe('Sangfor patterns', () => {
    it('should have SSL VPN patterns', () => {
      const sangfor = getFingerprintsByVendor('sangfor')[0];
      expect(sangfor).toBeDefined();
      
      // Should detect Chinese manufacturer patterns
      const chinesePattern = sangfor.patterns.find(
        p => String(p.match).includes('深信服')
      );
      expect(chinesePattern).toBeDefined();
    });
  });
});
