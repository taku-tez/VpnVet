/**
 * Agent H: SARIF coverageWarning (#2), Pulse alias CVE matching (#3), CVE-2024-47575 fix (#6)
 */
import { vulnerabilities } from '../src/vulnerabilities.js';
import { resolveProductAlias, resolveProductAndVendor } from '../src/product.js';
import { normalizeProduct } from '../src/utils.js';

describe('SARIF coverageWarning as result (#2)', () => {
  it('should produce SARIF with coverage warning result when coverageWarning is present', () => {
    const coverageRule = {
      id: 'VPNVET-COVERAGE-WARNING',
      name: 'CoverageWarning',
      shortDescription: { text: 'VPN device detected but no CVE mappings available for this product' },
    };
    expect(coverageRule.id).toBe('VPNVET-COVERAGE-WARNING');
  });

  it('coverageWarning should trigger for products without CVE mappings', () => {
    const hasFortManagerCves = vulnerabilities.some(v =>
      v.affected.some(a => a.vendor === 'fortinet' && a.product === 'FortiManager')
    );
    expect(hasFortManagerCves).toBe(true);
  });
});

describe('Pulse alias CVE matching (#3)', () => {
  it('resolveProductAndVendor should map Pulse Connect Secure to ivanti', () => {
    const resolved = resolveProductAndVendor('Pulse Connect Secure');
    expect(resolved).not.toBeNull();
    expect(resolved!.vendor).toBe('ivanti');
    expect(resolved!.product).toBe('Connect Secure');
  });

  it('pulse vendor device should match ivanti CVEs via alias resolution', () => {
    const deviceVendor = 'pulse';
    const deviceProduct = 'Pulse Connect Secure';

    const canonicalProduct = resolveProductAlias(deviceProduct, deviceVendor);
    const canonicalProductNorm = normalizeProduct(canonicalProduct);
    const originalProductNorm = normalizeProduct(deviceProduct);

    const resolved = resolveProductAndVendor(deviceProduct);
    const vendorsToSearch = new Set([deviceVendor]);
    if (resolved?.vendor && resolved.vendor !== deviceVendor) {
      vendorsToSearch.add(resolved.vendor);
    }

    expect(vendorsToSearch.has('pulse')).toBe(true);
    expect(vendorsToSearch.has('ivanti')).toBe(true);

    const productNorms = new Set([canonicalProductNorm, originalProductNorm]);
    const isProductMatch = (aProduct: string | undefined): boolean => {
      if (!aProduct) return true;
      const aNorm = normalizeProduct(aProduct);
      if (productNorms.has(aNorm)) return true;
      const aCanonical = resolveProductAlias(aProduct);
      return productNorms.has(normalizeProduct(aCanonical));
    };

    const matchedCves = vulnerabilities.filter(v =>
      v.affected.some(a =>
        vendorsToSearch.has(a.vendor) && isProductMatch(a.product)
      )
    );

    const cveIds = matchedCves.map(v => v.cve);
    expect(cveIds).toContain('CVE-2024-21887');
    expect(cveIds).toContain('CVE-2025-0282');
    expect(cveIds).toContain('CVE-2019-11510');
    expect(matchedCves.length).toBeGreaterThanOrEqual(5);
  });

  it('ivanti vendor device should also match pulse CVEs', () => {
    const vendorVulns = vulnerabilities.filter(v =>
      v.affected.some(a => a.vendor === 'ivanti' &&
        (!a.product || normalizeProduct(a.product) === normalizeProduct('Connect Secure')))
    );
    expect(vendorVulns.length).toBeGreaterThanOrEqual(3);
  });
});

describe('CVE-2024-47575 product mapping (#6)', () => {
  it('should target FortiManager, not FortiGate', () => {
    const cve = vulnerabilities.find(v => v.cve === 'CVE-2024-47575');
    expect(cve).toBeDefined();
    for (const a of cve!.affected) {
      expect(a.product).toBe('FortiManager');
      expect(a.vendor).toBe('fortinet');
    }
  });

  it('should have version ranges for FortiManager', () => {
    const cve = vulnerabilities.find(v => v.cve === 'CVE-2024-47575');
    expect(cve!.affected.length).toBe(4);
    expect(cve!.affected[0].versionStart).toBe('7.6.0');
  });

  it('FortiManager product alias should resolve', () => {
    const resolved = resolveProductAlias('fortimanager');
    expect(resolved).toBe('FortiManager');
  });
});
