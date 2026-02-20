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
      expect(kevCves).toContain('CVE-2025-20333'); // Cisco ASA RCE
      expect(kevCves).toContain('CVE-2025-20362'); // Cisco ASA/FTD reload
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

  describe('February 2026 CVE additions', () => {
    it('should include CVE-2026-22153 FortiOS auth bypass', () => {
      const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-22153');
      expect(vuln).toBeDefined();
      expect(vuln!.severity).toBe('high');
      expect(vuln!.affected.some(a => a.vendor === 'fortinet')).toBe(true);
    });

    it('should include CVE-2026-21643 FortiClientEMS SQLi RCE', () => {
      const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-21643');
      expect(vuln).toBeDefined();
      expect(vuln!.severity).toBe('critical');
      expect(vuln!.cvss).toBeGreaterThanOrEqual(9.0);
    });

    it('should include CVE-2026-0229 PAN-OS ADNS DoS', () => {
      const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-0229');
      expect(vuln).toBeDefined();
      expect(vuln!.severity).toBe('high');
      expect(vuln!.affected.some(a => a.vendor === 'paloalto')).toBe(true);
    });
  });

  describe('cross-reference integrity with fingerprints', () => {
    // Products that intentionally lack fingerprints (management-plane only, not VPN endpoints)
    const KNOWN_NO_FINGERPRINT = new Set([
      'fortinet:FortiManager',
      'fortinet:FortiSIEM',    // Management-plane product, not a VPN endpoint
      'fortinet:FortiWeb',     // WAF product, not a VPN endpoint
      'fortinet:FortiProxy',   // Proxy product, not a VPN endpoint
      'ivanti:EPMM',           // Mobile device management, not a VPN endpoint
      'cisco:ASA',   // ASA is the firewall; VPN endpoint detected as AnyConnect
      'cisco:FTD',   // FTD is threat defense; VPN endpoint detected as AnyConnect
      // BeyondTrust PRA shares login UI with Remote Support; single fingerprint covers both
      'beyondtrust:Privileged Remote Access',
    ]);

    it('affected vendor+product should exist in fingerprints (or be in known exceptions)', () => {
      const fpKeys = new Set(fingerprints.map(f => `${f.vendor}:${f.product}`));
      const missing: string[] = [];
      for (const v of vulnerabilities) {
        for (const a of v.affected) {
          const key = `${a.vendor}:${a.product}`;
          if (!fpKeys.has(key) && !KNOWN_NO_FINGERPRINT.has(key)) {
            missing.push(`${v.cve} -> ${key}`);
          }
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
        'kerio', 'lancom', 'meraki',
        // mobileiron fingerprints detect Ivanti EPMM on the network; EPMM CVEs are filed
        // under vendor:'ivanti' per NVD taxonomy, so mobileiron has no direct CVE mapping here
        'mobileiron',
        'netmotion', 'nsfocus',
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

    it('CVE-2024-47575 (FortiJump) should target FortiManager, not FortiGate', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2024-47575');
      expect(cve).toBeDefined();
      expect(cve?.description).toContain('FortiManager');
      for (const a of cve!.affected) {
        expect(a.product).toBe('FortiManager');
      }
      expect(cve?.affected.some(a => a.product === 'FortiGate')).toBe(false);
    });

    it('CVE-2025-59718 (Fortinet SSO bypass) should be critical with CISA KEV', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-59718');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(9.8);
      expect(cve?.severity).toBe('critical');
      expect(cve?.cisaKev).toBe(true);
      expect(cve?.exploitAvailable).toBe(true);
    });

    it('CVE-2025-59719 (FortiWeb SSO bypass) should be critical', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-59719');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(9.8);
      expect(cve?.severity).toBe('critical');
    });

    it('CVE-2025-64155 (FortiSIEM command injection) should be critical with KEV and target FortiSIEM', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-64155');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(9.8);
      expect(cve?.severity).toBe('critical');
      expect(cve?.cisaKev).toBe(true);
      expect(cve?.exploitAvailable).toBe(true);
      expect(cve?.affected.every(a => a.product === 'FortiSIEM')).toBe(true);
      expect(cve?.affected.some(a => a.product === 'FortiGate')).toBe(false);
    });

    it('CVE-2026-0227 (PAN-OS GlobalProtect DoS) should be high with PoC', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-0227');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(7.7);
      expect(cve?.severity).toBe('high');
      expect(cve?.exploitAvailable).toBe(true);
    });

    it('CVE-2025-11730 (Zyxel DDNS command injection) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-11730');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(7.2);
      expect(cve?.severity).toBe('high');
    });

    it('CVE-2025-8078 (Zyxel post-auth command injection) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-8078');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(7.2);
      expect(cve?.severity).toBe('high');
      expect(cve?.affected[0]?.versionStart).toBe('4.32');
      expect(cve?.affected[0]?.versionEnd).toBe('5.40');
    });

    it('CVE-2025-25249 (FortiOS CAPWAP RCE) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-25249');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(8.1);
      expect(cve?.severity).toBe('high');
      expect(cve?.cisaKev).toBe(false);
    });

    it('CVE-2025-32756 (Fortinet buffer overflow) should be critical with exploit', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-32756');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(9.8);
      expect(cve?.exploitAvailable).toBe(true);
      expect(cve?.cisaKev).toBe(true);
    });

    it('CVE-2025-40599 (SonicWall SMA 100 OVERSTEP) should be critical', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-40599');
      expect(cve).toBeDefined();
      expect(cve?.cvss).toBe(9.8);
      expect(cve?.severity).toBe('critical');
      expect(cve?.exploitAvailable).toBe(true);
    });

    it('CVE-2025-40602 (SonicWall SMA 1000 privesc) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-40602');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('high');
      expect(cve?.exploitAvailable).toBe(true);
    });

    it('CVE-2025-9133 (Zyxel missing authorization) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-9133');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('high');
      expect(cve?.cvss).toBe(7.2);
      expect(cve?.affected.some(a => a.vendor === 'zyxel')).toBe(true);
    });

    it('CVE-2026-21914 (Juniper SRX GTP DoS) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-21914');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('high');
      expect(cve?.cvss).toBe(7.5);
      expect(cve?.affected.some(a => a.vendor === 'juniper')).toBe(true);
    });

    it('CVE-2026-21906 (Juniper SRX IPsec/GRE DoS) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-21906');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('high');
      expect(cve?.cvss).toBe(7.5);
      expect(cve?.affected.some(a => a.vendor === 'juniper')).toBe(true);
    });

    it('CVE-2026-1281 (Ivanti EPMM pre-auth RCE) should be critical with CISA KEV', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-1281');
      expect(cve).toBeDefined();
      expect(cve!.severity).toBe('critical');
      expect(cve!.cvss).toBe(9.8);
      expect(cve!.cisaKev).toBe(true);
      expect(cve!.exploitAvailable).toBe(true);
    });

    it('CVE-2026-1340 (Ivanti EPMM code injection) should be critical', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-1340');
      expect(cve).toBeDefined();
      expect(cve!.severity).toBe('critical');
      expect(cve!.cvss).toBe(9.8);
      expect(cve!.exploitAvailable).toBe(true);
    });

    it('CVE-2026-1498 (WatchGuard Firebox LDAP injection) should be high', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-1498');
      expect(cve).toBeDefined();
      expect(cve!.severity).toBe('high');
      expect(cve!.cvss).toBe(7.0);
      expect(cve!.affected.some(a => a.vendor === 'watchguard')).toBe(true);
    });

    it('CVE-2026-21917 (Juniper SRX Web-Filtering DoS) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-21917');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('high');
      expect(cve?.cvss).toBe(7.5);
      expect(cve?.affected.some(a => a.vendor === 'juniper')).toBe(true);
    });

    it('CVE-2026-21918 (Juniper SRX/MX flowd Double Free DoS) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-21918');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('high');
      expect(cve?.cvss).toBe(7.5);
      expect(cve?.affected.some(a => a.vendor === 'juniper')).toBe(true);
    });

    it('CVE-2026-21905 (Juniper SRX SIP ALG DoS) should be high severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-21905');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('high');
      expect(cve?.cvss).toBe(7.5);
      expect(cve?.affected.some(a => a.vendor === 'juniper')).toBe(true);
    });

    it('CVE-2026-25815 (FortiOS Default Cryptographic Key) should be low severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2026-25815');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('low');
      expect(cve?.cvss).toBe(3.2);
      expect(cve?.affected.some(a => a.vendor === 'fortinet')).toBe(true);
    });

    it('CVE-2025-15497 (OpenVPN Epoch Key DoS) should be medium severity', () => {
      const cve = vulnerabilities.find(v => v.cve === 'CVE-2025-15497');
      expect(cve).toBeDefined();
      expect(cve?.severity).toBe('medium');
      expect(cve?.cvss).toBe(6.5);
      expect(cve?.affected.some(a => a.vendor === 'openvpn')).toBe(true);
    });

    it('Pulse/Ivanti CVEs should be accessible via both vendor names', () => {
      const ivantiCves = vulnerabilities.filter(v =>
        v.affected.some(a => a.vendor === 'ivanti')
      );
      expect(ivantiCves.length).toBeGreaterThan(0);
      const pulseCves = vulnerabilities.filter(v =>
        v.affected.some(a => a.vendor === 'pulse')
      );
      expect(pulseCves.length).toBeGreaterThan(0);
    });
  });
});

describe('description vs affected.product consistency', () => {
  /**
   * Map of product keywords found in descriptions to expected affected.product values.
   * FortiGate and FortiOS are treated as the same product.
   */
  const PRODUCT_KEYWORD_MAP: Record<string, { vendor: string; products: string[] }> = {
    'FortiSIEM': { vendor: 'fortinet', products: ['FortiSIEM'] },
    'FortiWeb': { vendor: 'fortinet', products: ['FortiWeb'] },
    'FortiManager': { vendor: 'fortinet', products: ['FortiManager'] },
    'FortiProxy': { vendor: 'fortinet', products: ['FortiProxy'] },
    'FortiAnalyzer': { vendor: 'fortinet', products: ['FortiManager'] }, // Grouped with FortiManager
    // FortiOS/FortiGate are equivalent — no check needed
  };

  it('description product keywords should match affected.product', () => {
    const mismatches: string[] = [];

    for (const vuln of vulnerabilities) {
      for (const [keyword, expected] of Object.entries(PRODUCT_KEYWORD_MAP)) {
        if (vuln.description.includes(keyword)) {
          // Check that at least one affected entry has the expected product
          const hasMatchingProduct = vuln.affected.some(
            a => a.vendor === expected.vendor && expected.products.includes(a.product)
          );
          if (!hasMatchingProduct) {
            mismatches.push(
              `${vuln.cve}: description mentions "${keyword}" but affected has [${vuln.affected.map(a => a.product).join(', ')}]`
            );
          }
        }
      }
    }

    expect(mismatches).toEqual([]);
  });

  it('Ivanti EPMM CVEs should not be listed as Connect Secure', () => {
    const epmmCves = vulnerabilities.filter(v =>
      v.description.includes('EPMM') || v.description.includes('Endpoint Manager Mobile')
    );
    for (const vuln of epmmCves) {
      expect(vuln.affected.some(a => a.product === 'Connect Secure')).toBe(false);
      expect(vuln.affected.some(a => a.product === 'EPMM')).toBe(true);
    }
  });
});

describe('Ransomware tagging', () => {
  const ransomwareCves = vulnerabilities.filter(v => v.knownRansomware);

  it('should have ransomware-tagged CVEs', () => {
    expect(ransomwareCves.length).toBeGreaterThan(20);
  });

  it('all ransomware-tagged CVEs should also be CISA KEV', () => {
    for (const v of ransomwareCves) {
      expect(v.cisaKev).toBe(true);
    }
  });

  it('should tag known ransomware CVEs', () => {
    const knownRansomwareCves = [
      'CVE-2024-21762', // FortiOS - Akira, LockBit
      'CVE-2019-11510', // Pulse Secure - REvil
      'CVE-2023-4966',  // Citrix Bleed - LockBit
      'CVE-2024-40766', // SonicWall - Akira
      'CVE-2023-20269', // Cisco ASA - Akira, LockBit
    ];
    for (const cve of knownRansomwareCves) {
      const vuln = vulnerabilities.find(v => v.cve === cve);
      expect(vuln).toBeDefined();
      expect(vuln!.knownRansomware).toBe(true);
    }
  });
});

describe('February 2026 CVE additions', () => {
  it('should include CVE-2025-15467 OpenSSL CMS RCE', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-15467');
    expect(vuln).toBeDefined();
    expect(vuln!.severity).toBe('critical');
    expect(vuln!.cvss).toBe(9.8);
    expect(vuln!.exploitAvailable).toBe(true);
    expect(vuln!.affected.length).toBeGreaterThanOrEqual(3);
  });

  it('should include CVE-2026-22548 F5 BIG-IP WAF DoS', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-22548');
    expect(vuln).toBeDefined();
    expect(vuln!.severity).toBe('medium');
    expect(vuln!.cvss).toBe(5.9);
  });

  it('CVE-2025-15467 should affect multiple vendors', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-15467')!;
    const vendors = vuln.affected.map(a => a.vendor);
    expect(vendors).toContain('fortinet');
    expect(vendors).toContain('paloalto');
    expect(vendors).toContain('openvpn');
  });
});

describe('Ivanti EPMM exploit chain CVE-2025-4427/4428', () => {
  it('should include CVE-2025-4427 Ivanti EPMM auth bypass', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-4427');
    expect(vuln).toBeDefined();
    expect(vuln!.severity).toBe('medium');
    expect(vuln!.cvss).toBe(5.3);
    expect(vuln!.exploitAvailable).toBe(true);
    expect(vuln!.cisaKev).toBe(true);
    expect(vuln!.affected.some(a => a.vendor === 'ivanti')).toBe(true);
    expect(vuln!.affected.some(a => a.product === 'EPMM')).toBe(true);
  });

  it('should include CVE-2025-4428 Ivanti EPMM SSTI RCE', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-4428');
    expect(vuln).toBeDefined();
    expect(vuln!.severity).toBe('high');
    expect(vuln!.cvss).toBe(7.2);
    expect(vuln!.exploitAvailable).toBe(true);
    expect(vuln!.cisaKev).toBe(true);
    expect(vuln!.affected.some(a => a.vendor === 'ivanti')).toBe(true);
  });

  it('CVE-2025-4427/4428 should have valid references', () => {
    for (const cve of ['CVE-2025-4427', 'CVE-2025-4428']) {
      const vuln = vulnerabilities.find(v => v.cve === cve);
      expect(vuln).toBeDefined();
      expect(vuln!.references.length).toBeGreaterThanOrEqual(2);
      for (const ref of vuln!.references) {
        expect(ref).toMatch(/^https?:\/\//);
      }
    }
  });

  it('CVE-2025-4428 version range should be ≤ 12.5.0.0', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-4428');
    expect(vuln).toBeDefined();
    const affected = vuln!.affected[0];
    expect(affected.versionEnd).toBe('12.5.0.0');
  });
});

describe('WatchGuard CVE-2025-9242 - KEV Nov 2025 OOB write', () => {
  it('should include CVE-2025-9242 in vulnerabilities database', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-9242');
    expect(vuln).toBeDefined();
    expect(vuln!.severity).toBe('critical');
    expect(vuln!.cvss).toBe(9.3);
    expect(vuln!.exploitAvailable).toBe(true);
    expect(vuln!.cisaKev).toBe(true);
  });

  it('CVE-2025-9242 should affect watchguard vendor', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-9242');
    expect(vuln).toBeDefined();
    expect(vuln!.affected.some(a => a.vendor === 'watchguard')).toBe(true);
  });

  it('CVE-2025-9242 affected version end should be 12.11.3', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-9242');
    const entry = vuln!.affected.find(a => a.vendor === 'watchguard');
    expect(entry).toBeDefined();
    expect(entry!.versionEnd).toBe('12.11.3');
  });

  it('CVE-2025-9242 should reference watchguard advisory wgsa-2025-00015', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-9242');
    expect(vuln).toBeDefined();
    const hasAdvisory = vuln!.references.some(r => r.includes('wgsa-2025-00015'));
    expect(hasAdvisory).toBe(true);
  });

  it('should have both CVE-2025-9242 (Nov) and CVE-2025-14733 (Dec) for WatchGuard IKEv2', () => {
    const wg9242 = vulnerabilities.find(v => v.cve === 'CVE-2025-9242');
    const wg14733 = vulnerabilities.find(v => v.cve === 'CVE-2025-14733');
    expect(wg9242).toBeDefined();
    expect(wg14733).toBeDefined();
    // Both should be critical WatchGuard IKEv2 vulnerabilities
    expect(wg9242!.cvss).toBe(9.3);
    expect(wg14733!.cvss).toBe(9.3);
  });
});

describe('PAN-OS CVE-2025-0108 management web interface auth bypass', () => {
  it('should include CVE-2025-0108 in vulnerabilities database', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-0108');
    expect(vuln).toBeDefined();
    expect(vuln!.severity).toBe('high');
    expect(vuln!.cvss).toBe(8.8);
    expect(vuln!.exploitAvailable).toBe(true);
  });

  it('CVE-2025-0108 should affect paloalto vendor', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-0108');
    expect(vuln).toBeDefined();
    expect(vuln!.affected.some(a => a.vendor === 'paloalto')).toBe(true);
  });

  it('CVE-2025-0108 should cover multiple PAN-OS version ranges', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-0108');
    expect(vuln).toBeDefined();
    // Should cover at least 4 version ranges
    expect(vuln!.affected.length).toBeGreaterThanOrEqual(4);
  });

  it('CVE-2025-0108 description should mention management web interface and exploit chain', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-0108');
    expect(vuln).toBeDefined();
    expect(vuln!.description.toLowerCase()).toMatch(/management|auth.*bypass|bypass.*auth/);
    expect(vuln!.description).toMatch(/CVE-2024-9474/);
  });

  it('CVE-2025-0108 references should include Palo Alto security advisory', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2025-0108');
    expect(vuln).toBeDefined();
    const hasPaloAltoAdvisory = vuln!.references.some(r =>
      r.includes('security.paloaltonetworks.com')
    );
    expect(hasPaloAltoAdvisory).toBe(true);
  });
});

describe('BeyondTrust CVE-2026-1731 pre-auth RCE', () => {
  it('should include CVE-2026-1731 in vulnerabilities database', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-1731');
    expect(vuln).toBeDefined();
    expect(vuln!.severity).toBe('critical');
    expect(vuln!.cvss).toBe(9.8);
    expect(vuln!.exploitAvailable).toBe(true);
    expect(vuln!.cisaKev).toBe(true);
  });

  it('CVE-2026-1731 should affect beyondtrust vendor', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-1731');
    expect(vuln).toBeDefined();
    expect(vuln!.affected.some(a => a.vendor === 'beyondtrust')).toBe(true);
  });

  it('CVE-2026-1731 should cover both Remote Support and PRA products', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-1731');
    expect(vuln).toBeDefined();
    const products = vuln!.affected.map(a => a.product);
    expect(products).toContain('Remote Support');
    expect(products).toContain('Privileged Remote Access');
  });

  it('CVE-2026-1731 RS version boundary: ≤ 25.3.1', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-1731');
    const rsEntry = vuln!.affected.find(a => a.product === 'Remote Support');
    expect(rsEntry).toBeDefined();
    expect(rsEntry!.versionEnd).toBe('25.3.1');
  });

  it('CVE-2026-1731 PRA version boundary: ≤ 24.3.4', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-1731');
    const praEntry = vuln!.affected.find(a => a.product === 'Privileged Remote Access');
    expect(praEntry).toBeDefined();
    expect(praEntry!.versionEnd).toBe('24.3.4');
  });

  it('CVE-2026-1731 should have valid references', () => {
    const vuln = vulnerabilities.find(v => v.cve === 'CVE-2026-1731');
    expect(vuln).toBeDefined();
    expect(vuln!.references.length).toBeGreaterThanOrEqual(2);
    for (const ref of vuln!.references) {
      expect(ref).toMatch(/^https?:\/\//);
    }
  });
});
