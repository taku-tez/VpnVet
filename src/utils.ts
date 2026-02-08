/**
 * VpnVet Utility Functions
 */

import * as crypto from 'node:crypto';
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
 * Normalize a target URI for SARIF output.
 * Handles scheme detection, URL validation, and SHA-256 hashing for invalid targets.
 */
export function normalizeTargetUri(target: string): { uri: string; originalTarget?: string } {
  const trimmed = target.trim();
  // Already has a scheme
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    try {
      new URL(trimmed);
      return { uri: trimmed };
    } catch {
      const hash = crypto.createHash('sha256').update(trimmed).digest('hex').slice(0, 12);
      return { uri: `https://invalid-target-${hash}`, originalTarget: trimmed };
    }
  }
  // No scheme – prepend https://
  const candidate = `https://${trimmed}`;
  try {
    new URL(candidate);
    return { uri: candidate };
  } catch {
    const hash = crypto.createHash('sha256').update(trimmed).digest('hex').slice(0, 12);
    return { uri: `https://invalid-target-${hash}`, originalTarget: trimmed };
  }
}

/**
 * Normalize a target URL.
 * Trims whitespace, rejects empty strings, prepends https:// if no scheme,
 * and validates via the URL constructor.
 */
export function normalizeUrl(target: string): string {
  const trimmed = target.trim();
  if (!trimmed) {
    throw new Error('Invalid URL: empty target');
  }

  const withScheme = (!trimmed.startsWith('http://') && !trimmed.startsWith('https://'))
    ? `https://${trimmed}`
    : trimmed;

  // Validate via URL constructor — throws on malformed URLs
  try {
    new URL(withScheme);
  } catch {
    throw new Error(`Invalid URL: "${target}"`);
  }

  return withScheme;
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
 * Normalize a product name for comparison.
 * Lowercases, trims, and collapses whitespace.
 */
export function normalizeProduct(product: string): string {
  return product.toLowerCase().trim().replace(/\s+/g, ' ');
}

/**
 * Compare semantic versions
 * Returns: -1 if a < b, 0 if equal, 1 if a > b
 * 
 * Handles VPN-specific version formats like:
 * - 13.1-49.14 (nested/hyphenated)
 * - 10.2.0.5-d-29sv (alpha suffixes)
 * - R81.20 (letter prefixes)
 * 
 * Trailing zeros are treated as equal: 13.1 == 13.1.0 == 13.1.0.0
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
      
      // Missing part: treat as zero for trailing-zero equivalence
      if (!pA && pB) {
        // pA is missing — if pB is numeric zero, they're equal; otherwise pA < pB
        if (pB.type === 'num' && pB.numVal === 0) continue;
        return -1;
      }
      if (pA && !pB) {
        // pB is missing — if pA is numeric zero, they're equal; otherwise pA > pB
        if (pA.type === 'num' && pA.numVal === 0) continue;
        return 1;
      }
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
 * Returns boolean: true if version matches the affected range, false otherwise (including when no version constraints are defined).
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

  // Partial bounds: only start means "version >= start"
  if (affected.versionStart) {
    return compareVersions(version, affected.versionStart) >= 0;
  }

  // Partial bounds: only end means "version <= end"
  if (affected.versionEnd) {
    return compareVersions(version, affected.versionEnd) <= 0;
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

// ============================================================
// MurmurHash3 (32-bit) — Shodan-compatible favicon hashing
// ============================================================

/**
 * MurmurHash3 32-bit implementation (pure TypeScript, no dependencies).
 * Operates on a Buffer and returns a signed 32-bit integer.
 */
export function murmurhash3_32(data: Buffer, seed: number = 0): number {
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const len = data.length;
  let h1 = seed;
  const nblocks = len >>> 2;

  // Body
  for (let i = 0; i < nblocks; i++) {
    let k1 = data.readUInt32LE(i * 4);
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = Math.imul(h1, 5) + 0xe6546b64;
  }

  // Tail
  const tail = nblocks * 4;
  let k1 = 0;
  switch (len & 3) {
    case 3: k1 ^= data[tail + 2] << 16; // fallthrough
    case 2: k1 ^= data[tail + 1] << 8;  // fallthrough
    case 1:
      k1 ^= data[tail];
      k1 = Math.imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
  }

  // Finalization
  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  // Return as signed 32-bit integer (Shodan convention)
  return h1 | 0;
}

/**
 * Compute Shodan-compatible favicon hash.
 * Shodan method: base64-encode the raw favicon bytes, then mmh3_32 the base64 string.
 */
export function faviconHash(faviconBody: Buffer): number {
  const b64 = faviconBody.toString('base64');
  return murmurhash3_32(Buffer.from(b64, 'utf8'));
}
