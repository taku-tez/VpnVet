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
 * Compare semantic versions
 * Returns: -1 if a < b, 0 if equal, 1 if a > b
 */
export function compareVersions(a: string, b: string): number {
  const partsA = a.split(/[.\-]/).map(p => parseInt(p, 10) || 0);
  const partsB = b.split(/[.\-]/).map(p => parseInt(p, 10) || 0);
  
  const maxLen = Math.max(partsA.length, partsB.length);
  
  for (let i = 0; i < maxLen; i++) {
    const numA = partsA[i] || 0;
    const numB = partsB[i] || 0;
    
    if (numA < numB) return -1;
    if (numA > numB) return 1;
  }
  
  return 0;
}

/**
 * Check if a version is within affected range
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
