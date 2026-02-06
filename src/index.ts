/**
 * VpnVet - VPN Device Detection & Vulnerability Scanner
 * 
 * @packageDocumentation
 */

export { VpnScanner, scan, scanMultiple } from './scanner.js';
export { fingerprints, getFingerprintsByVendor, getAllVendors } from './fingerprints/index.js';
export { vulnerabilities, getVulnerabilitiesByVendor, getCriticalVulnerabilities, getKevVulnerabilities } from './vulnerabilities.js';
export type {
  VpnDevice,
  VpnVendor,
  DetectionMethod,
  Vulnerability,
  AffectedVersion,
  ScanResult,
  ScanOptions,
  VulnerabilityMatch,
  Fingerprint,
  FingerprintPattern,
  ReportOptions,
} from './types.js';
