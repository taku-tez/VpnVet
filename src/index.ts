/**
 * VpnVet - VPN Device Detection & Vulnerability Scanner
 * 
 * @packageDocumentation
 */

// Core scanner
export { VpnScanner, scan, scanMultiple } from './scanner.js';

// Fingerprints database
export { fingerprints, getFingerprintsByVendor, getAllVendors } from './fingerprints/index.js';

// Vulnerability database
export { 
  vulnerabilities, 
  getVulnerabilitiesByVendor, 
  getCriticalVulnerabilities, 
  getKevVulnerabilities 
} from './vulnerabilities.js';

// Utilities
export {
  normalizeUrl,
  compareVersions,
  isVersionAffected,
  formatVendorName,
  calculateConfidence,
  isHighPriority,
  murmurhash3_32,
  faviconHash,
} from './utils.js';

// Vendor normalization
export { resolveVendor, VENDOR_ALIASES } from './vendor.js';

// Types
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
