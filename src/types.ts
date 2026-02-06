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
  | 'fortinet'
  | 'paloalto'
  | 'cisco'
  | 'pulse'
  | 'sonicwall'
  | 'checkpoint'
  | 'citrix'
  | 'ivanti'
  | 'openvpn'
  | 'wireguard'
  | 'f5'
  | 'juniper'
  | 'zyxel'
  | 'sophos'
  | 'watchguard'
  | 'barracuda'
  | 'sangfor'
  | 'array'
  | 'netmotion'
  | 'hillstone'
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
}

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
  errors: string[];
}

export interface VulnerabilityMatch {
  vulnerability: Vulnerability;
  confidence: 'confirmed' | 'likely' | 'potential';
  evidence: string;
}

export interface ScanOptions {
  timeout?: number;
  ports?: number[];
  skipVersionDetection?: boolean;
  skipVulnCheck?: boolean;
  userAgent?: string;
  followRedirects?: boolean;
  headers?: Record<string, string>;
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
  match: string | RegExp;
  weight: number; // 1-10, used for confidence calculation
  versionExtract?: RegExp;
}

export interface ReportOptions {
  format: 'json' | 'sarif' | 'csv' | 'table';
  output?: string;
  includeEvidence?: boolean;
  minSeverity?: 'critical' | 'high' | 'medium' | 'low';
}
