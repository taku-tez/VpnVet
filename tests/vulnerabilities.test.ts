/**
 * Vulnerability Database Tests
 */

import {
  vulnerabilities,
  getVulnerabilitiesByVendor,
  getCriticalVulnerabilities,
  getKevVulnerabilities,
} from '../src/vulnerabilities.js';

describe('Vulnerabilities', () => {
  describe('vulnerability database', () => {
    it('should have vulnerabilities', () => {
      expect(vulnerabilities.length).toBeGreaterThan(0);
    });

    it('should have at least 15 CVEs', () => {
      expect(vulnerabilities.length).toBeGreaterThanOrEqual(15);
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
