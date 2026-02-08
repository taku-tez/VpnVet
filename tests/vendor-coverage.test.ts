/**
 * Vendor Coverage Test
 * 
 * Ensures every value in the VpnVendor union type has a corresponding
 * fingerprint implementation in getAllVendors().
 * 
 * If this test fails, either:
 * 1. Add fingerprints for the missing vendor, or
 * 2. Remove the vendor from VpnVendor type in src/types.ts
 */

// Uses Jest globals
import { getAllVendors } from '../src/fingerprints/index.js';

// Mirror of VpnVendor union type — keep in sync with src/types.ts
const VPN_VENDOR_VALUES: string[] = [
  // Tier 1 Enterprise
  'fortinet', 'paloalto', 'cisco', 'checkpoint', 'f5', 'juniper',
  // SSL VPN Specialists
  'pulse', 'ivanti', 'citrix', 'array', 'sonicwall',
  // UTM / NGFW
  'sophos', 'watchguard', 'barracuda', 'zyxel', 'stormshield',
  'lancom', 'kerio', 'untangle', 'endian',
  // SMB / SOHO
  'draytek', 'mikrotik', 'ubiquiti', 'pfsense', 'opnsense',
  'netgear', 'tplink',
  // Asia / China
  'huawei', 'h3c', 'hillstone', 'sangfor', 'ruijie',
  'nsfocus', 'venustech', 'topsec', 'dptech',
  // Korea
  'ahnlab', 'secui',
  // Open Source
  'openvpn',
  // Enterprise Mobility
  'netmotion',
  // Cloud / ZTNA
  'zscaler', 'cloudflare',
  // Other
  'aruba', 'meraki',
];

describe('Vendor Coverage', () => {
  const implementedVendors = new Set(getAllVendors());

  it('every VpnVendor value has a fingerprint implementation', () => {
    const missing = VPN_VENDOR_VALUES.filter(v => !implementedVendors.has(v));
    if (missing.length > 0) fail(`Missing fingerprints for: ${missing.join(', ')}`);
    expect(missing).toEqual([]);
  });

  it('every fingerprint vendor is in VpnVendor type', () => {
    const vendorSet = new Set(VPN_VENDOR_VALUES);
    const extra = getAllVendors().filter(v => !vendorSet.has(v));
    if (extra.length > 0) fail(`Fingerprints exist but not in VpnVendor: ${extra.join(', ')}`);
    expect(extra).toEqual([]);
  });

  it('no duplicate vendors in fingerprints', () => {
    const vendors = getAllVendors();
    expect(vendors.length).toBe(new Set(vendors).size);
  });
});
