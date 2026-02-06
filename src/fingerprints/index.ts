/**
 * VPN Device Fingerprints Database
 * 
 * Split into categories for maintainability:
 * - tier1-enterprise: Fortinet, Palo Alto, Cisco, Pulse/Ivanti, Citrix (16 KEV)
 * - tier2-enterprise: SonicWall, Check Point, F5, Juniper, etc. (10 KEV)
 * - asia: Sangfor, Huawei, H3C, and regional vendors
 * - smb-soho: DrayTek, MikroTik, pfSense, and small business solutions
 * - cloud-ztna: Meraki, Aruba, Zscaler, Cloudflare
 */

import type { Fingerprint } from '../types.js';
import { tier1enterpriseFingerprints } from './tier1-enterprise.js';
import { tier2enterpriseFingerprints } from './tier2-enterprise.js';
import { asiaFingerprints } from './asia.js';
import { smbsohoFingerprints } from './smb-soho.js';
import { cloudztnaFingerprints } from './cloud-ztna.js';

export const fingerprints: Fingerprint[] = [
  ...tier1enterpriseFingerprints,
  ...tier2enterpriseFingerprints,
  ...asiaFingerprints,
  ...smbsohoFingerprints,
  ...cloudztnaFingerprints,
];

export function getFingerprintsByVendor(vendor: string): Fingerprint[] {
  return fingerprints.filter(f => f.vendor === vendor);
}

export function getAllVendors(): string[] {
  return [...new Set(fingerprints.map(f => f.vendor))];
}

// Re-export category fingerprints for direct access
export {
  tier1enterpriseFingerprints,
  tier2enterpriseFingerprints,
  asiaFingerprints,
  smbsohoFingerprints,
  cloudztnaFingerprints,
};
