/**
 * VpnVet - VPN Device Detection & Vulnerability Scanner
 * 
 * @packageDocumentation
 */

// Core scanner
export { VpnScanner, scan, scanMultiple, classifyError, errorKindLabel } from './scanner.js';

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

// Product alias resolution
export { resolveProductAlias, resolveProductAndVendor, PRODUCT_ALIASES } from './product.js';

// JARM fingerprinting
export { scanJarm, computeJarmHash, lookupJarmHash, KNOWN_JARM_HASHES } from './jarm.js';

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
  ScanError,
  ScanErrorKind,
} from './types.js';
