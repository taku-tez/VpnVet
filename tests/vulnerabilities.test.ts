/**
 * Vulnerability Database Tests
 */

import {
  vulnerabilities,
  getVulnerabilitiesByVendor,
  getCriticalVulnerabilities,
  getKevVulnerabilities,
} from '../src/vulnerabilities.js';
import { isVersionAffected } from '../src/utils.js';
import { fingerprints } from '../src/fingerprints/index.js';

describe('Vulnerabilities', () => {
  describe('vulnerability database', () => {
    it('should have vulnerabilities', () => {
      expect(vulnerabilities.length).toBeGreaterThan(0);
    });

    it('should have at least 25 CVEs', () => {
      expect(vulnerabilities.length).toBeGreaterThanOrEqual(25);
    });

    it('should have valid vulnerability structure', () => {
      for (const vuln of vulnerabilities) {
        expect(vuln.cve).toMatch(/^CVE-\d{4}-\d+$/);
        expect(['critical', 'high', 'medium', 'low']).toContain(vuln.severity);
        expect(vuln.description).toBeDefined();
        expect(Array.isArray(vuln.affected)).toBe(true);
        expect(vuln.affected.length).toBeGreaterThan(0);
        expect(Array.isArray(vuln.references)).toBe(true);
        expect(typeof vuln.exploitAvailable).toBe('boolean');
        expect(typeof vuln.cisaKev).toBe('boolean');
      }
    });

    it('should have CVSS scores for critical/high vulnerabilities', () => {
      const criticalHigh = vulnerabilities.filter(
        v => v.severity === 'critical' || v.severity === 'high'
      );
      
      for (const vuln of criticalHigh) {
        expect(vuln.cvss).toBeDefined();
        expect(vuln.cvss).toBeGreaterThanOrEqual(7.0);
      }
    });
  });

  describe('CISA KEV vulnerabilities', () => {
    it('should have CISA KEV entries', () => {
      const kev = getKevVulnerabilities();
      expect(kev.length).toBeGreaterThan(0);
    });

    it('should include major VPN CVEs in KEV', () => {
      const kevCves = getKevVulnerabilities().map(v => v.cve);
      
      // These are well-known actively exploited VPN vulnerabilities
      expect(kevCves).toContain('CVE-2018-13379'); // FortiGate path traversal
      expect(kevCves).toContain('CVE-2019-11510'); // Pulse Secure file read
      expect(kevCves).toContain('CVE-2019-19781'); // Citrix Shitrix
      expect(kevCves).toContain('CVE-2024-21762'); // FortiOS RCE
      expect(kevCves).toContain('CVE-2024-3400');  // PAN-OS RCE
      
      // New vendor CVEs
      expect(kevCves).toContain('CVE-2022-1388');  // F5 BIG-IP
      expect(kevCves).toContain('CVE-2022-30525'); // Zyxel
      expect(kevCves).toContain('CVE-2022-3236');  // Sophos
      expect(kevCves).toContain('CVE-2023-2868');  // Barracuda
    });
  });

  describe('getVulnerabilitiesByVendor', () => {
    it('should return Fortinet vulnerabilities', () => {
      const fortinet = getVulnerabilitiesByVendor('fortinet');
      expect(fortinet.length).toBeGreaterThan(0);
      
      for (const vuln of fortinet) {
        expect(vuln.affected.some(a => a.vendor === 'fortinet')).toBe(true);
      }
    });

    it('should return Palo Alto vulnerabilities', () => {
      const paloalto = getVulnerabilitiesByVendor('paloalto');
      expect(paloalto.length).toBeGreaterThan(0);
    });

    it('should return Ivanti/Pulse vulnerabilities', () => {
      const ivanti = getVulnerabilitiesByVendor('ivanti');
      const pulse = getVulnerabilitiesByVendor('pulse');
      
      // Ivanti and Pulse should have overlapping vulnerabilities
      expect(ivanti.length).toBeGreaterThan(0);
      expect(pulse.length).toBeGreaterThan(0);
    });

    it('should return Citrix vulnerabilities', () => {
      const citrix = getVulnerabilitiesByVendor('citrix');
      expect(citrix.length).toBeGreaterThan(0);
      
      // Should include Citrix Bleed
      expect(citrix.some(v => v.cve === 'CVE-2023-4966')).toBe(true);
    });

    it('should return empty array for unknown vendor', () => {
      const unknown = getVulnerabilitiesByVendor('unknown');
      expect(unknown).toEqual([]);
    });
  });

  describe('getCriticalVulnerabilities', () => {
    it('should return only critical vulnerabilities', () => {
      const critical = getCriticalVulnerabilities();
      
      expect(critical.length).toBeGreaterThan(0);
      for (const vuln of critical) {
        expect(vuln.severity).toBe('critical');
      }
    });

    it('should have high CVSS scores', () => {
      const critical = getCriticalVulnerabilities();
      
      for (const vuln of critical) {
        // Critical severity typically has CVSS >= 8.0
        expect(vuln.cvss).toBeGreaterThanOrEqual(8.0);
      }
    });
  });

  describe('no duplicate CVE-IDs', () => {
    it('should not have the same CVE-ID more than once', () => {
      const seen = new Set<string>();
      const duplicates: string[] = [];
      for (const v of vulnerabilities) {
        if (seen.has(v.cve)) duplicates.push(v.cve);
        seen.add(v.cve);
      }
      expect(duplicates).toEqual([]);
    });
  });

  describe('cross-reference integrity with fingerprints', () => {
    it('affected vendor+product should exist in fingerprints', () => {
      const fpKeys = new Set(fingerprints.map(f => `${f.vendor}:${f.product}`));
      const missing: string[] = [];
      for (const v of vulnerabilities) {
        for (const a of v.affected) {
          const key = `${a.vendor}:${a.product}`;
          if (!fpKeys.has(key)) missing.push(`${v.cve} -> ${key}`);
        }
      }
      expect(missing).toEqual([]);
    });
  });

  describe('fingerprint vendors without CVE coverage', () => {
    it('should identify vendors with fingerprints but no CVEs (coverage warning candidates)', () => {
      const vulnVendors = new Set(
        vulnerabilities.flatMap(v => v.affected.map(a => a.vendor))
      );
      const fpVendors = new Set(fingerprints.map(f => f.vendor));
      const noCveVendors = [...fpVendors].filter(v => !vulnVendors.has(v)).sort();

      // These vendors have fingerprints but no CVEs — expected for cloud/ZTNA/niche vendors
      // If a new vendor gets CVEs added, remove it from this list
      const expectedNoCve = [
        'ahnlab', 'cloudflare', 'dptech', 'endian', 'h3c', 'hillstone',
        'kerio', 'lancom', 'meraki', 'netmotion', 'nsfocus', 'openvpn',
        'opnsense', 'ruijie', 'secui', 'stormshield', 'topsec', 'ubiquiti',
        'untangle', 'venustech', 'zscaler',
      ].sort();

      expect(noCveVendors).toEqual(expectedNoCve);
    });
  });

  describe('references URL validity', () => {
    it('all references should start with http:// or https://', () => {
      const invalid: string[] = [];
      for (const v of vulnerabilities) {
        for (const ref of v.references) {
          if (!/^https?:\/\//.test(ref)) {
            invalid.push(`${v.cve}: ${ref}`);
          }
        }
      }
      expect(invalid).toEqual([]);
    });
  });

  describe('required fields strict check', () => {
    it('every vulnerability should have non-empty description', () => {
      for (const v of vulnerabilities) {
        expect(v.description.length).toBeGreaterThan(0);
      }
    });

    it('every affected entry should have vendor and product', () => {
      for (const v of vulnerabilities) {
        for (const a of v.affected) {
          expect(a.vendor.length).toBeGreaterThan(0);
          expect(a.product.length).toBeGreaterThan(0);
        }
      }
    });

    it('every vulnerability should have at least one reference', () => {
      for (const v of vulnerabilities) {
        expect(v.references.length).toBeGreaterThan(0);
      }
    });
  });

  describe('KEV critical CVE fixed set', () => {
    it('should contain major known-exploited VPN CVEs', () => {
      const allCves = vulnerabilities.map(v => v.cve);
      const requiredCves = [
        'CVE-2024-21762',  // FortiOS RCE
        'CVE-2023-46805',  // Ivanti Connect Secure auth bypass
        'CVE-2024-3400',   // PAN-OS command injection
        'CVE-2023-4966',   // Citrix Bleed
        'CVE-2019-11510',  // Pulse Secure file read
        'CVE-2018-13379',  // FortiGate path traversal
        'CVE-2019-19781',  // Citrix Shitrix
        'CVE-2022-42475',  // FortiOS heap overflow
        'CVE-2023-27997',  // FortiOS heap buffer overflow
      ];
      for (const cve of requiredCves) {
        expect(allCves).toContain(cve);
      }
    });
  });

  describe('specific CVE details', () => {
    it('CVE-2024-3400 should be max severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2024-3400');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(10.0);
      expect(cve?.severity).toBe('critical');
      expect(cve?.cisaKev).toBe(true);
    });

    it('CVE-2023-4966 (Citrix Bleed) should be critical', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2023-4966');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('critical');
      expect(cve?.cisaKev).toBe(true);
    });

    it('isVersionAffected returns false when no version constraints defined', () => {
      expect(isVersionAffected('1.0.0', {})).toBe(false);
    });

    it('CVE-2022-42475 (FortiOS heap overflow) should have affected versions', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2022-42475');
      expect(cve).toBeDefined();
      expect(cve?.affected.length).toBeGreaterThan(0);
      
      // Should have version ranges
      const hasVersionRange = cve?.affected.some(
        a => a.versionStart && a.versionEnd
      );
      expect(hasVersionRange).toBe(true);
    });
  });
});
