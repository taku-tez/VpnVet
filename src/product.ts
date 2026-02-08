/**
 * Product alias resolution — maps legacy/rebranded product names to canonical names.
 *
 * VPN vendors frequently rebrand or acquire products. This module ensures that
 * a user scanning "Pulse Connect Secure" gets the same CVE hits as "Ivanti Connect Secure".
 */

export interface ProductAlias {
  vendor: string;
  canonical: string;
}

/**
 * Product alias dictionary.
 * Key: normalised alias (lowercase, trimmed).
 * Value: { vendor, canonical product name }.
 *
 * The canonical name MUST match what vulnerabilities.ts uses in `affected.product`.
 */
export const PRODUCT_ALIASES: Record<string, ProductAlias> = {
  // Ivanti ← Pulse Secure rebrand (2021)
  'pulse connect secure': { vendor: 'ivanti', canonical: 'Connect Secure' },
  'pulse secure': { vendor: 'ivanti', canonical: 'Connect Secure' },
  'ivanti pulse connect secure': { vendor: 'ivanti', canonical: 'Connect Secure' },

  // Citrix Gateway ← NetScaler Gateway rebrand (2018)
  'netscaler gateway': { vendor: 'citrix', canonical: 'Citrix Gateway' },
  'netscaler adc': { vendor: 'citrix', canonical: 'Citrix Gateway' },
  'citrix netscaler': { vendor: 'citrix', canonical: 'Citrix Gateway' },
  'citrix adc': { vendor: 'citrix', canonical: 'Citrix Gateway' },

  // FortiGate product name variations
  'fortios': { vendor: 'fortinet', canonical: 'FortiGate' },
  'fortigate ssl vpn': { vendor: 'fortinet', canonical: 'FortiGate' },
  'forti ssl vpn': { vendor: 'fortinet', canonical: 'FortiGate' },

  // FortiManager product name variations
  'fortimanager': { vendor: 'fortinet', canonical: 'FortiManager' },
  'forti manager': { vendor: 'fortinet', canonical: 'FortiManager' },

  // FortiSIEM product name variations
  'fortisiem': { vendor: 'fortinet', canonical: 'FortiSIEM' },
  'forti siem': { vendor: 'fortinet', canonical: 'FortiSIEM' },

  // FortiWeb product name variations
  'fortiweb': { vendor: 'fortinet', canonical: 'FortiWeb' },
  'forti web': { vendor: 'fortinet', canonical: 'FortiWeb' },

  // FortiProxy product name variations
  'fortiproxy': { vendor: 'fortinet', canonical: 'FortiProxy' },
  'forti proxy': { vendor: 'fortinet', canonical: 'FortiProxy' },

  // Ivanti EPMM (MobileIron legacy)
  'ivanti epmm': { vendor: 'ivanti', canonical: 'EPMM' },
  'ivanti endpoint manager mobile': { vendor: 'ivanti', canonical: 'EPMM' },
  'mobileiron core': { vendor: 'ivanti', canonical: 'EPMM' },

  // Palo Alto product name variations
  'pan-os': { vendor: 'paloalto', canonical: 'GlobalProtect' },
  'panos': { vendor: 'paloalto', canonical: 'GlobalProtect' },

  // Cisco product name variations
  'cisco asa': { vendor: 'cisco', canonical: 'AnyConnect' },
  'cisco ftd': { vendor: 'cisco', canonical: 'AnyConnect' },
  'adaptive security appliance': { vendor: 'cisco', canonical: 'AnyConnect' },

  // SonicWall SMA variations
  'sonicwall sma 100': { vendor: 'sonicwall', canonical: 'SMA' },
  'sonicwall sma 1000': { vendor: 'sonicwall', canonical: 'SMA' },

  // F5 product variations
  'big-ip': { vendor: 'f5', canonical: 'BIG-IP APM' },
  'big-ip apm': { vendor: 'f5', canonical: 'BIG-IP APM' },
  'bigip': { vendor: 'f5', canonical: 'BIG-IP APM' },
  'f5 big-ip': { vendor: 'f5', canonical: 'BIG-IP APM' },

  // Sophos rebrand
  'cyberoam': { vendor: 'sophos', canonical: 'XG Firewall' },
  'sophos firewall': { vendor: 'sophos', canonical: 'XG Firewall' },
  'sophos xg': { vendor: 'sophos', canonical: 'XG Firewall' },
};

/**
 * Resolve a product name to its canonical form.
 *
 * @param product - User/detection-supplied product name
 * @param vendor  - Optional vendor hint (unused today, reserved for future disambiguation)
 * @returns The canonical product name, or the original if no alias matches.
 */
export function resolveProductAlias(product: string, _vendor?: string): string {
  const key = product.toLowerCase().trim().replace(/\s+/g, ' ');
  const alias = PRODUCT_ALIASES[key];
  return alias ? alias.canonical : product;
}

/**
 * Resolve both vendor and product from a product alias.
 * Useful when the alias implies a vendor change (e.g. Pulse → Ivanti).
 *
 * @returns { vendor, product } with canonical values, or null if no alias matches.
 */
export function resolveProductAndVendor(product: string): { vendor: string; product: string } | null {
  const key = product.toLowerCase().trim().replace(/\s+/g, ' ');
  const alias = PRODUCT_ALIASES[key];
  return alias ? { vendor: alias.vendor, product: alias.canonical } : null;
}
