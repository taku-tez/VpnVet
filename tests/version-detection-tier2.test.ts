/**
 * Version Detection Tests for Tier 2 Enterprise Vendors
 */

import { tier2enterpriseFingerprints } from '../src/fingerprints/tier2-enterprise.js';
import type { Fingerprint, FingerprintPattern } from '../src/types.js';

function getVendorFingerprint(vendor: string): Fingerprint | undefined {
  return tier2enterpriseFingerprints.find((fp) => fp.vendor === vendor);
}

function getVersionPatterns(vendor: string): FingerprintPattern[] {
  const fp = getVendorFingerprint(vendor);
  if (!fp) return [];
  return fp.patterns.filter((p) => p.versionExtract);
}

describe('Tier 2 Version Detection', () => {
  const vendorsWithVersionExtract = [
    'f5',
    'juniper',
    'sonicwall',
    'zyxel',
    'sophos',
    'checkpoint',
    'watchguard',
  ];

  for (const vendor of vendorsWithVersionExtract) {
    describe(vendor, () => {
      it('should have at least 1 versionExtract pattern', () => {
        const patterns = getVersionPatterns(vendor);
        expect(patterns.length).toBeGreaterThanOrEqual(1);
      });

      it('should have valid versionExtract regex', () => {
        const patterns = getVersionPatterns(vendor);
        for (const p of patterns) {
          expect(p.versionExtract).toBeInstanceOf(RegExp);
          // Regex should have at least one capture group
          expect(p.versionExtract!.source).toMatch(/\(/);
        }
      });
    });
  }

  describe('F5 BIG-IP version extraction', () => {
    it('should extract version from TMUI login page', () => {
      const patterns = getVersionPatterns('f5');
      const tmui = patterns.find((p) => p.path === '/tmui/login.jsp');
      expect(tmui).toBeDefined();
      const match = 'BIG-IP 16.1.3.1 Configuration Utility'.match(tmui!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('16.1.3.1');
    });

    it('should extract version from iControl REST API', () => {
      const patterns = getVersionPatterns('f5');
      const api = patterns.find((p) => p.path === '/mgmt/tm/sys/version');
      expect(api).toBeDefined();
      const match = '{"version": "15.1.8.2"}'.match(api!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('15.1.8.2');
    });
  });

  describe('Juniper version extraction', () => {
    it('should extract Junos version from body', () => {
      const patterns = getVersionPatterns('juniper');
      const body = patterns.find((p) => p.type === 'body');
      expect(body).toBeDefined();
      const match = 'JUNOS 22.4R1.10'.match(body!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('22.4R1.10');
    });

    it('should extract Junos version from J-Web system-information API', () => {
      const patterns = getVersionPatterns('juniper');
      const sysInfo = patterns.find((p) => p.path === '/api/v1/system-information');
      expect(sysInfo).toBeDefined();
      const match = '"junos-version": "23.4R2-S5"'.match(sysInfo!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('23.4R2-S5');
    });

    it('should extract Junos version from configuration API', () => {
      const patterns = getVersionPatterns('juniper');
      const cfgInfo = patterns.find((p) => p.path === '/api/v1/configuration/system/information');
      expect(cfgInfo).toBeDefined();
      const match = '"version": "24.2R2-S3"'.match(cfgInfo!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('24.2R2-S3');
    });
  });

  describe('SonicWall version extraction', () => {
    it('should extract SMA version from header', () => {
      const patterns = getVersionPatterns('sonicwall');
      const header = patterns.find((p) => p.type === 'header');
      expect(header).toBeDefined();
      const match = 'SMA/12.4.3'.match(header!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('12.4.3');
    });

    it('should extract firmware version from body', () => {
      const patterns = getVersionPatterns('sonicwall');
      const body = patterns.find((p) => p.type === 'body');
      expect(body).toBeDefined();
      const match = '10.2.1.9-57sv'.match(body!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('10.2.1.9');
    });
  });

  describe('Zyxel version extraction', () => {
    it('should extract ZLD version', () => {
      const patterns = getVersionPatterns('zyxel');
      const zld = patterns.find((p) => p.path === '/zld_product_spec.js');
      expect(zld).toBeDefined();
      const match = 'ZLD V5.37'.match(zld!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('5.37');
    });
  });

  describe('Sophos version extraction', () => {
    it('should extract SFOS firmware version', () => {
      const patterns = getVersionPatterns('sophos');
      expect(patterns.length).toBeGreaterThanOrEqual(1);
      const body = patterns.find((p) => p.type === 'body');
      expect(body).toBeDefined();
      const match = 'SFOS Version v20.0.1'.match(body!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('20.0.1');
    });
  });

  describe('Check Point version extraction', () => {
    it('should extract version from login page', () => {
      const patterns = getVersionPatterns('checkpoint');
      expect(patterns.length).toBeGreaterThanOrEqual(1);
      const login = patterns.find((p) => p.path === '/sslvpn/Login/Login');
      expect(login).toBeDefined();
      const match = 'Check Point Mobile Access R81.20'.match(login!.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('81.20');
    });
  });

  describe('WatchGuard version extraction', () => {
    it('should extract Fireware version', () => {
      const patterns = getVersionPatterns('watchguard');
      expect(patterns.length).toBeGreaterThanOrEqual(1);
      const p = patterns[0];
      const match = 'Fireware XTM v12.10.4'.match(p.versionExtract!);
      expect(match).toBeTruthy();
      expect(match![1]).toBe('12.10.4');
    });
  });

  describe('total versionExtract count', () => {
    it('should have at least 14 versionExtract patterns across all tier2 vendors', () => {
      let total = 0;
      for (const fp of tier2enterpriseFingerprints) {
        total += fp.patterns.filter((p) => p.versionExtract).length;
      }
      expect(total).toBeGreaterThanOrEqual(14);
    });
  });
});
