/**
 * VpnVet Types
 */

export interface VpnDevice {
  vendor: VpnVendor;
  product: string;
  version?: string;
  confidence: number; // 0-100
  detectionMethod: DetectionMethod[];
  endpoints: string[];
}

export type VpnVendor =
  // Tier 1 Enterprise
  | 'fortinet'
  | 'paloalto'
  | 'cisco'
  | 'checkpoint'
  | 'f5'
  | 'juniper'
  // SSL VPN Specialists
  | 'pulse'
  | 'ivanti'
  | 'citrix'
  | 'array'
  | 'sonicwall'
  // UTM / NGFW
  | 'sophos'
  | 'watchguard'
  | 'barracuda'
  | 'zyxel'
  | 'stormshield'
  | 'lancom'
  | 'kerio'
  | 'untangle'
  | 'endian'
  // SMB / SOHO
  | 'draytek'
  | 'mikrotik'
  | 'ubiquiti'
  | 'pfsense'
  | 'opnsense'
  | 'netgear'
  | 'tplink'
  // Asia / China
  | 'huawei'
  | 'h3c'
  | 'hillstone'
  | 'sangfor'
  | 'ruijie'
  | 'nsfocus'
  | 'venustech'
  | 'topsec'
  | 'dptech'
  // Korea
  | 'ahnlab'
  | 'secui'
  // Open Source
  | 'openvpn'
  | 'wireguard'
  // Enterprise Mobility
  | 'netmotion'
  | 'mobileiron'
  // Cloud / ZTNA (also detectable when self-hosted)
  | 'zscaler'
  | 'cloudflare'
  | 'netskope'
  | 'cato'
  // Other
  | 'aruba'
  | 'meraki'
  | 'unknown';

export type DetectionMethod =
  | 'endpoint'
  | 'header'
  | 'certificate'
  | 'banner'
  | 'favicon'
  | 'html';

export interface Vulnerability {
  cve: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss?: number;
  description: string;
  affected: AffectedVersion[];
  references: string[];
  exploitAvailable: boolean;
  cisaKev: boolean; // CISA Known Exploited Vulnerabilities
  knownRansomware?: boolean; // Known to be used in ransomware campaigns
}

/**
 * Affected version range for a vulnerability.
 *
 * Comparison rules (evaluated in order):
 * 1. versionExact set        → version === versionExact
 * 2. versionStart & versionEnd → versionStart <= version <= versionEnd
 * 3. versionStart only       → version >= versionStart  (no upper bound)
 * 4. versionEnd only         → version <= versionEnd    (no lower bound)
 * 5. None set                → no version constraint (isVersionAffected returns false)
 */
export interface AffectedVersion {
  vendor: VpnVendor;
  product: string;
  versionStart?: string;
  versionEnd?: string;
  versionExact?: string;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  device?: VpnDevice;
  vulnerabilities: VulnerabilityMatch[];
  coverageWarning?: string;
  errors: string[];
  scanErrors?: ScanError[];
}

export interface VulnerabilityMatch {
  vulnerability: Vulnerability;
  confidence: 'confirmed' | 'likely' | 'potential';
  evidence: string;
}

/** Classified error kinds for scan failures */
export type ScanErrorKind = 'timeout' | 'dns' | 'tls' | 'reset' | 'refused' | 'http-status' | 'invalid-url' | 'ssrf-blocked' | 'pattern-error' | 'unknown';

export interface ScanError {
  kind: ScanErrorKind;
  message: string;
  url?: string;
  statusCode?: number;
}

export interface ScanOptions {
  timeout?: number;
  ports?: number[];
  skipVersionDetection?: boolean;
  skipVulnCheck?: boolean;
  userAgent?: string;
  followRedirects?: boolean;
  headers?: Record<string, string>;
  fast?: boolean; // Stop on first match
  vendor?: VpnVendor | string; // Test specific vendor only (VpnVendor recommended)
  allowCrossHostRedirects?: boolean; // Allow redirects to different hosts (default: false)
  concurrency?: number; // Max concurrent scans in scanMultiple (default: 5)
  adaptiveConcurrency?: boolean; // Reduce concurrency on high failure rate (default: false)
  maxRetries?: number; // Max retries per target (default: 0)
  insecureTls?: boolean; // Skip TLS certificate verification (default: true for scanner use)
}

export interface Fingerprint {
  vendor: VpnVendor;
  product: string;
  patterns: FingerprintPattern[];
}

export interface FingerprintPattern {
  type: 'endpoint' | 'header' | 'body' | 'certificate' | 'favicon';
  path?: string;
  method?: 'GET' | 'HEAD' | 'POST';
  /**
   * For favicon type: can be pipe-separated mmh3 hash values (e.g. '945408572|-76600061')
   * for Shodan-compatible hash matching, or a regex pattern for legacy body matching.
   */
  match: string | RegExp;
  weight: number; // 1-10, used for confidence calculation
  versionExtract?: RegExp;
  /** Allowed HTTP status codes. Defaults to 2xx (200-299) when omitted. */
  status?: number[];
}

export interface ReportOptions {
  format: 'json' | 'sarif' | 'csv' | 'table';
  output?: string;
  includeEvidence?: boolean;
  minSeverity?: 'critical' | 'high' | 'medium' | 'low';
}
