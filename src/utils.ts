/**
 * VpnVet Utility Functions
 */

import type { Vulnerability, VpnVendor } from './types.js';

// ============================================================
// Logging (xxVet unified pattern)
// ============================================================

let verbose = false;

export function setVerbose(v: boolean): void {
  verbose = v;
}

export function logProgress(message: string): void {
  if (verbose) {
    console.error(`[vpnvet] ${message}`);
  }
}

export function logError(message: string): void {
  console.error(`[vpnvet] ERROR: ${message}`);
}

export function logInfo(message: string): void {
  console.error(`[vpnvet] ${message}`);
}

/**
 * Normalize a target URL
 */
export function normalizeUrl(target: string): string {
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    return `https://${target}`;
  }
  return target;
}

/**
 * Parse a version segment into numeric and string parts.
 * e.g. "49sv" -> [{type:'num', val:49}, {type:'str', val:'sv'}]
 *      "d"    -> [{type:'str', val:'d'}]
 *      "13"   -> [{type:'num', val:13}]
 */
function parseSegmentParts(seg: string): Array<{ type: 'num' | 'str'; numVal: number; strVal: string }> {
  const parts: Array<{ type: 'num' | 'str'; numVal: number; strVal: string }> = [];
  const tokens = seg.match(/\d+|[a-zA-Z]+/g);
  if (!tokens) return [{ type: 'str', numVal: 0, strVal: seg }];
  for (const t of tokens) {
    if (/^\d+$/.test(t)) {
      parts.push({ type: 'num', numVal: parseInt(t, 10), strVal: t });
    } else {
      parts.push({ type: 'str', numVal: 0, strVal: t.toLowerCase() });
    }
  }
  return parts;
}

/**
 * Compare semantic versions
 * Returns: -1 if a < b, 0 if equal, 1 if a > b
 * 
 * Handles VPN-specific version formats like:
 * - 13.1-49.14 (nested/hyphenated)
 * - 10.2.0.5-d-29sv (alpha suffixes)
 * - R81.20 (letter prefixes)
 */
export function compareVersions(a: string, b: string): number {
  // Split on . and - but keep both as delimiters
  const segmentsA = a.split(/[.\-]/);
  const segmentsB = b.split(/[.\-]/);
  
  const maxLen = Math.max(segmentsA.length, segmentsB.length);
  
  for (let i = 0; i < maxLen; i++) {
    const segA = segmentsA[i] || '';
    const segB = segmentsB[i] || '';
    
    const partsA = segA ? parseSegmentParts(segA) : [];
    const partsB = segB ? parseSegmentParts(segB) : [];
    
    const maxParts = Math.max(partsA.length, partsB.length);
    
    for (let j = 0; j < maxParts; j++) {
      const pA = partsA[j];
      const pB = partsB[j];
      
      // Missing part: segment with fewer sub-parts is "less"
      if (!pA && pB) return -1;
      if (pA && !pB) return 1;
      if (!pA || !pB) continue;
      
      // Both numeric
      if (pA.type === 'num' && pB.type === 'num') {
        if (pA.numVal < pB.numVal) return -1;
        if (pA.numVal > pB.numVal) return 1;
      }
      // Both string
      else if (pA.type === 'str' && pB.type === 'str') {
        if (pA.strVal < pB.strVal) return -1;
        if (pA.strVal > pB.strVal) return 1;
      }
      // num vs str: numbers sort before strings
      else {
        return pA.type === 'num' ? -1 : 1;
      }
    }
  }
  
  return 0;
}

/**
 * Check if a version is within affected range
 */
/**
 * Check if a version is within affected range.
 * Returns true if version matches, false if not, undefined if no version constraints defined.
 */
export function isVersionAffected(
  version: string,
  affected: { versionStart?: string; versionEnd?: string; versionExact?: string }
): boolean {
  if (affected.versionExact) {
    return version === affected.versionExact;
  }

  if (affected.versionStart && affected.versionEnd) {
    return compareVersions(version, affected.versionStart) >= 0 &&
           compareVersions(version, affected.versionEnd) <= 0;
  }

  return false;
}

/**
 * Check if an affected entry has any version constraints defined.
 */
export function hasVersionConstraints(
  affected: { versionStart?: string; versionEnd?: string; versionExact?: string }
): boolean {
  return !!(affected.versionStart || affected.versionEnd || affected.versionExact);
}

/**
 * Get severity numeric value for sorting
 */
export function getSeverityWeight(severity: string): number {
  const weights: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };
  return weights[severity] ?? 4;
}

/**
 * Get confidence numeric value for sorting
 */
export function getConfidenceWeight(confidence: string): number {
  const weights: Record<string, number> = {
    confirmed: 0,
    likely: 1,
    potential: 2,
  };
  return weights[confidence] ?? 3;
}

/**
 * Format vendor name for display
 */
export function formatVendorName(vendor: VpnVendor): string {
  const names: Partial<Record<VpnVendor, string>> = {
    fortinet: 'Fortinet',
    paloalto: 'Palo Alto',
    cisco: 'Cisco',
    checkpoint: 'Check Point',
    f5: 'F5 Networks',
    juniper: 'Juniper',
    pulse: 'Pulse Secure',
    ivanti: 'Ivanti',
    citrix: 'Citrix',
    array: 'Array Networks',
    sonicwall: 'SonicWall',
    sophos: 'Sophos',
    watchguard: 'WatchGuard',
    barracuda: 'Barracuda',
    zyxel: 'Zyxel',
    stormshield: 'Stormshield',
    lancom: 'LANCOM',
    kerio: 'Kerio',
    untangle: 'Untangle',
    endian: 'Endian',
    draytek: 'DrayTek',
    mikrotik: 'MikroTik',
    ubiquiti: 'Ubiquiti',
    pfsense: 'pfSense',
    opnsense: 'OPNsense',
    netgear: 'NETGEAR',
    tplink: 'TP-Link',
    huawei: 'Huawei',
    h3c: 'H3C',
    hillstone: 'Hillstone',
    sangfor: 'Sangfor',
    ruijie: 'Ruijie',
    nsfocus: 'NSFOCUS',
    venustech: 'Venustech',
    topsec: 'TopSec',
    dptech: 'DPtech',
    ahnlab: 'AhnLab',
    secui: 'SECUI',
    openvpn: 'OpenVPN',
    wireguard: 'WireGuard',
    netmotion: 'NetMotion',
    mobileiron: 'MobileIron',
    zscaler: 'Zscaler',
    cloudflare: 'Cloudflare',
    netskope: 'Netskope',
    cato: 'Cato Networks',
    aruba: 'Aruba',
    meraki: 'Meraki',
  };
  
  return names[vendor] || vendor;
}

/**
 * Calculate confidence percentage from score
 */
export function calculateConfidence(score: number, maxScore: number): number {
  return Math.min(100, Math.round((score / maxScore) * 100));
}

/**
 * Check if vulnerability is high priority (critical + KEV + exploit)
 */
export function isHighPriority(vuln: Vulnerability): boolean {
  return vuln.severity === 'critical' && vuln.cisaKev && vuln.exploitAvailable;
}
