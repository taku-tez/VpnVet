/**
 * VpnVet Scanner
 * 
 * Detects VPN devices and checks for known vulnerabilities.
 */

import * as https from 'node:https';
import * as http from 'node:http';
import * as tls from 'node:tls';
import * as net from 'node:net';
import * as dns from 'node:dns/promises';
import { URL } from 'node:url';
import { fingerprints, getAllVendors } from './fingerprints/index.js';
import { vulnerabilities } from './vulnerabilities.js';
import { resolveVendor } from './vendor.js';
import { resolveProductAlias, resolveProductAndVendor } from './product.js';
import {
  normalizeUrl,
  normalizeProduct,
  isVersionAffected,
  hasVersionConstraints,
  getSeverityWeight,
  getConfidenceWeight,
  faviconHash,
} from './utils.js';
import type {
  ScanResult,
  ScanError,
  ScanOptions,
  ScanErrorKind,
  VpnDevice,
  Fingerprint,
  FingerprintPattern,
  VulnerabilityMatch,
  DetectionMethod,
} from './types.js';

const DEFAULT_OPTIONS: Required<ScanOptions> = {
  timeout: 10000,
  ports: [443, 10443, 8443, 4433],
  skipVersionDetection: false,
  skipVulnCheck: false,
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  followRedirects: true,
  headers: {},
  fast: false,
  vendor: '',
  allowCrossHostRedirects: false,
  concurrency: 5,
  adaptiveConcurrency: false,
  maxRetries: 0,
};

/**
 * Classify a network/request error into a ScanErrorKind.
 */
export function classifyError(err: unknown): ScanErrorKind {
  if (!(err instanceof Error)) return 'unknown';
  const msg = err.message.toLowerCase();
  const code = (err as NodeJS.ErrnoException).code?.toLowerCase() ?? '';

  if (code === 'etimedout' || code === 'esockettimedout' || msg.includes('timeout')) return 'timeout';
  if (code === 'enotfound' || code === 'eai_again' || msg.includes('getaddrinfo')) return 'dns';
  if (code === 'econnreset' || msg.includes('socket hang up')) return 'reset';
  if (code === 'econnrefused') return 'refused';
  if (msg.includes('tls') || msg.includes('ssl') || msg.includes('certificate') ||
      code === 'err_tls_cert_altname_invalid' || code === 'unable_to_verify_leaf_signature') return 'tls';
  if (msg.includes('invalid url')) return 'invalid-url';
  return 'unknown';
}

/** Human-readable label for a ScanErrorKind */
export function errorKindLabel(kind: ScanErrorKind): string {
  const labels: Record<ScanErrorKind, string> = {
    'timeout': 'Connection timed out',
    'dns': 'DNS resolution failed',
    'tls': 'TLS/SSL error',
    'reset': 'Connection reset',
    'refused': 'Connection refused',
    'http-status': 'HTTP error',
    'invalid-url': 'Invalid URL',
    'ssrf-blocked': 'Blocked (internal address)',
    'unknown': 'Unknown error',
  };
  return labels[kind];
}

interface HttpResponse {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
}

export class VpnScanner {
  private options: Required<ScanOptions>;

  constructor(options: ScanOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };

    // Normalize vendor via shared resolver (#3)
    if (this.options.vendor) {
      const resolved = resolveVendor(this.options.vendor, getAllVendors());
      if (!resolved) {
        throw new Error(`Unknown vendor: "${this.options.vendor}". Known vendors: ${getAllVendors().join(', ')}`);
      }
      this.options.vendor = resolved;
    }

    // Validate and normalize concurrency (#3)
    const c = this.options.concurrency;
    if (c == null || !Number.isFinite(c) || !Number.isInteger(c) || c <= 0) {
      this.options.concurrency = DEFAULT_OPTIONS.concurrency;
    } else if (c > 100) {
      this.options.concurrency = 100;
    }
  }

  async scan(target: string): Promise<ScanResult> {
    const result: ScanResult = {
      target,
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
      scanErrors: [],
    };

    try {
      // Normalize target URL
      let baseUrl: string;
      try {
        baseUrl = normalizeUrl(target);
      } catch (e) {
        const msg = e instanceof Error ? e.message : `Invalid URL: "${target}"`;
        result.errors.push(msg);
        const kind = classifyError(e);
        result.scanErrors!.push({ kind: kind === 'unknown' ? 'invalid-url' : kind, message: msg });
        return result;
      }
      
      // Try to detect VPN device
      const device = await this.detectDevice(baseUrl, result);
      
      if (device) {
        result.device = device;
        
        // Check for vulnerabilities if device detected
        if (!this.options.skipVulnCheck) {
          result.vulnerabilities = await this.checkVulnerabilities(device, baseUrl);

          // Check if any CVE definitions exist for this vendor/product
          // Resolve product alias so that legacy names (e.g. "Pulse Connect Secure")
          // match canonical CVE entries (e.g. "Connect Secure" under ivanti).
          const canonicalProduct = resolveProductAlias(device.product, device.vendor);
          const deviceProductNorm = normalizeProduct(canonicalProduct);
          const resolvedPV = resolveProductAndVendor(device.product);
          const coverageVendors = new Set<string>([device.vendor]);
          if (resolvedPV?.vendor && resolvedPV.vendor !== device.vendor) {
            coverageVendors.add(resolvedPV.vendor);
          }
          const hasCveMappings = vulnerabilities.some(v =>
            v.affected.some(a => {
              if (!coverageVendors.has(a.vendor)) return false;
              if (!a.product) return true; // no product constraint = matches all for this vendor
              const aNorm = normalizeProduct(a.product);
              if (aNorm === deviceProductNorm) return true;
              // Also resolve CVE-side product alias (e.g. "Pulse Connect Secure" → "Connect Secure")
              const aCanonical = resolveProductAlias(a.product);
              return normalizeProduct(aCanonical) === deviceProductNorm;
            })
          );
          if (!hasCveMappings) {
            result.coverageWarning = `No CVE mappings currently available for ${device.vendor} ${device.product}. Detection coverage and vulnerability coverage are independent — a detected product with zero CVEs does not imply it is secure.`;
          }
        }
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      result.errors.push(msg);
      const kind = classifyError(error);
      result.scanErrors!.push({ kind, message: msg });
    }

    // Remove scanErrors if empty to keep output clean
    if (result.scanErrors && result.scanErrors.length === 0) {
      delete result.scanErrors;
    }

    return result;
  }

  async scanMultiple(targets: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = new Array(targets.length);
    const initialConcurrency = Math.max(1, this.options.concurrency || 5);
    const adaptive = this.options.adaptiveConcurrency ?? false;
    const maxRetries = Math.max(0, this.options.maxRetries ?? 0);
    let activeConcurrency = initialConcurrency;
    let nextIndex = 0;

    // Semaphore: track how many slots are currently in-flight
    let inFlight = 0;
    let doneCount = 0;

    // Adaptive tracking
    let failureCount = 0;

    const scanWithRetry = async (target: string): Promise<ScanResult> => {
      let lastResult: ScanResult | undefined;
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        lastResult = await this.scan(target);
        if (lastResult.device || lastResult.errors.length === 0) {
          return lastResult;
        }
      }
      return lastResult!;
    };

    if (targets.length === 0) return results;

    return new Promise<ScanResult[]>((resolve) => {
      const tryDispatch = () => {
        // Launch tasks up to the current activeConcurrency limit
        while (inFlight < activeConcurrency && nextIndex < targets.length) {
          const i = nextIndex++;
          inFlight++;

          scanWithRetry(targets[i]).catch((err) => {
            // If scan throws (instead of returning errors), wrap it
            return {
              target: targets[i],
              timestamp: new Date().toISOString(),
              vulnerabilities: [],
              errors: [err instanceof Error ? err.message : String(err)],
              scanErrors: [{ kind: classifyError(err), message: err instanceof Error ? err.message : String(err) }],
            } as ScanResult;
          }).then((result) => {
            results[i] = result;
            inFlight--;
            doneCount++;

            // Adaptive concurrency adjustment
            if (adaptive) {
              if (result.errors.length > 0 && !result.device) {
                failureCount++;
              }
              // Evaluate failure rate every 5 completions
              if (doneCount % 5 === 0 && doneCount >= 5) {
                const failRate = failureCount / doneCount;
                if (failRate > 0.5 && activeConcurrency > 1) {
                  activeConcurrency = Math.max(1, Math.floor(activeConcurrency / 2));
                }
              }
            }

            // Check if all done
            if (doneCount === targets.length) {
              resolve(results);
            } else {
              // Dispatch more work (respects potentially lowered activeConcurrency)
              tryDispatch();
            }
          });
        }
      };

      tryDispatch();
    });
  }

  private async detectDevice(baseUrl: string, scanResult?: ScanResult): Promise<VpnDevice | undefined> {
    // Determine URLs to try based on ports option
    const urlsToTry = this.buildPortUrls(baseUrl);

    for (const url of urlsToTry) {
      const result = await this.detectDeviceForUrl(url, scanResult);
      if (result) return result;
    }

    return undefined;
  }

  private buildPortUrls(baseUrl: string): string[] {
    const parsedUrl = new URL(baseUrl);

    // If explicit port in URL, only use that
    if (parsedUrl.port) {
      return [baseUrl];
    }

    // Otherwise, try each port from options
    const urls: string[] = [];
    for (const port of this.options.ports) {
      const isDefaultPort = (parsedUrl.protocol === 'https:' && port === 443) ||
                            (parsedUrl.protocol === 'http:' && port === 80);
      if (isDefaultPort) {
        urls.push(baseUrl);
      } else {
        const u = new URL(baseUrl);
        u.port = String(port);
        urls.push(u.toString().replace(/\/$/, ''));
      }
    }

    // Deduplicate while preserving order
    return [...new Set(urls)];
  }

  private async detectDeviceForUrl(baseUrl: string, scanResult?: ScanResult): Promise<VpnDevice | undefined> {
    // SSRF: block private/internal targets at the detection level
    const parsedBase = new URL(baseUrl);
    if (!(await VpnScanner.isHostSafe(parsedBase.hostname))) {
      const msg = `SSRF blocked: ${parsedBase.hostname} resolves to internal/unsafe address`;
      if (scanResult) {
        scanResult.errors.push(msg);
        scanResult.scanErrors ??= [];
        scanResult.scanErrors.push({ kind: 'ssrf-blocked', message: msg, url: baseUrl });
      }
      return undefined;
    }

    const scores: Map<string, { fingerprint: Fingerprint; score: number; methods: DetectionMethod[]; endpoints: string[]; version?: string }> = new Map();

    // Filter fingerprints if vendor specified
    let fingerprintsToTest = fingerprints;
    if (this.options.vendor) {
      fingerprintsToTest = fingerprints.filter(f => f.vendor === this.options.vendor);
    }

    // Test each fingerprint
    for (const fingerprint of fingerprintsToTest) {
      let totalScore = 0;
      const methods: DetectionMethod[] = [];
      const endpoints: string[] = [];
      let detectedVersion: string | undefined;

      for (const pattern of fingerprint.patterns) {
        const matched = await this.testPattern(baseUrl, pattern, scanResult);
        
        if (matched.success) {
          totalScore += pattern.weight;
          
          // Track version if detected
          if (matched.version && !detectedVersion) {
            detectedVersion = matched.version;
          }
          
          // Track detection methods
          if (pattern.type === 'endpoint') {
            methods.push('endpoint');
            if (pattern.path) endpoints.push(pattern.path);
          } else if (pattern.type === 'header') {
            methods.push('header');
          } else if (pattern.type === 'body') {
            methods.push('html');
          } else if (pattern.type === 'certificate') {
            methods.push('certificate');
          } else if (pattern.type === 'favicon') {
            methods.push('favicon');
          }
        }
      }

      if (totalScore > 0) {
        const key = `${fingerprint.vendor}:${fingerprint.product}`;
        const existing = scores.get(key);
        
        if (!existing || existing.score < totalScore) {
          scores.set(key, {
            fingerprint,
            score: totalScore,
            methods: [...new Set(methods)],
            endpoints: [...new Set(endpoints)],
            version: detectedVersion,
          });
        }

        // Fast mode: return immediately on first strong match
        if (this.options.fast && totalScore >= 10) {
          const maxPossibleScore = fingerprint.patterns.reduce((sum, p) => sum + p.weight, 0);
          const confidence = Math.min(100, Math.round((totalScore / maxPossibleScore) * 100));
          
          return {
            vendor: fingerprint.vendor,
            product: fingerprint.product,
            version: detectedVersion,
            confidence,
            detectionMethod: [...new Set(methods)],
            endpoints: [...new Set(endpoints)],
          };
        }
      }
    }

    // Find highest scoring match
    let bestMatch: { fingerprint: Fingerprint; score: number; methods: DetectionMethod[]; endpoints: string[]; version?: string } | undefined;
    
    for (const match of scores.values()) {
      if (!bestMatch || match.score > bestMatch.score) {
        bestMatch = match;
      }
    }

    if (bestMatch && bestMatch.score >= 5) {
      // `unknown` fallback criteria:
      // - Score < 5: No detection returned (undefined). The score threshold of 5
      //   prevents low-confidence noise. A single weight-3 body match alone won't trigger.
      // - Score >= 5 but < 10: Low confidence detection. Usually from generic patterns
      //   (e.g., certificate + one body match). May warrant manual verification.
      // - Score >= 10: Reliable detection. Typically requires multiple independent
      //   signals (header + endpoint, or header + body).
      // If no vendor fingerprint scores >= 5, the result is `undefined` (no device detected).
      // The scanner never returns vendor='unknown'; absence of a result IS the unknown case.
      // Calculate confidence (0-100)
      const maxPossibleScore = bestMatch.fingerprint.patterns.reduce((sum, p) => sum + p.weight, 0);
      const confidence = Math.min(100, Math.round((bestMatch.score / maxPossibleScore) * 100));

      return {
        vendor: bestMatch.fingerprint.vendor,
        product: bestMatch.fingerprint.product,
        version: bestMatch.version,
        confidence,
        detectionMethod: bestMatch.methods,
        endpoints: bestMatch.endpoints,
      };
    }

    return undefined;
  }

  private async testPattern(
    baseUrl: string,
    pattern: FingerprintPattern,
    scanResult?: ScanResult
  ): Promise<{ success: boolean; version?: string }> {
    try {
      if (pattern.type === 'endpoint' || pattern.type === 'body') {
        const url = pattern.path ? `${baseUrl}${pattern.path}` : baseUrl;
        const response = await this.httpRequest(url, pattern.method || 'GET');
        
        if (!response) return { success: false };

        // Record HTTP error statuses (4xx/5xx) for diagnostics
        if (response.statusCode >= 400 && scanResult) {
          scanResult.scanErrors ??= [];
          // Avoid duplicate entries for the same URL+status
          const alreadyRecorded = scanResult.scanErrors.some(
            e => e.kind === 'http-status' && e.url === url && e.statusCode === response.statusCode
          );
          if (!alreadyRecorded) {
            scanResult.scanErrors.push({
              kind: 'http-status',
              message: `HTTP ${response.statusCode} from ${url}`,
              url,
              statusCode: response.statusCode,
            });
          }
        }

        // Status code validation
        if (pattern.status) {
          if (!pattern.status.includes(response.statusCode)) return { success: false };
        } else {
          if (response.statusCode < 200 || response.statusCode >= 300) return { success: false };
        }

        const matchPattern = typeof pattern.match === 'string' 
          ? new RegExp(pattern.match, 'i')
          : pattern.match;

        if (matchPattern.test(response.body)) {
          let version: string | undefined;
          
          if (pattern.versionExtract && !this.options.skipVersionDetection) {
            const versionMatch = response.body.match(pattern.versionExtract);
            if (versionMatch?.[1]) {
              version = versionMatch[1];
            }
          }
          
          return { success: true, version };
        }
      } else if (pattern.type === 'header') {
        // Try HEAD first; fall back to GET if HEAD returns null or 405/501
        let response = await this.httpRequest(baseUrl, 'HEAD');
        if (!response || response.statusCode === 405 || response.statusCode === 501) {
          response = await this.httpRequest(baseUrl, 'GET');
        }
        
        if (!response) return { success: false };

        if (this.matchHeaders(response.headers, pattern.match)) {
          return { success: true };
        }
      } else if (pattern.type === 'favicon') {
        const faviconPath = pattern.path || '/favicon.ico';
        const url = `${baseUrl}${faviconPath}`;

        const matchStr = typeof pattern.match === 'string' ? pattern.match : null;
        // If match looks like hash values (digits, optional minus, pipe-separated), use hash comparison
        const isHashMatch = matchStr && /^-?\d+(\|-?\d+)*$/.test(matchStr);

        if (isHashMatch) {
          // Binary fetch for hash comparison
          const binaryResult = await this.httpRequestBinary(url);
          if (!binaryResult) return { success: false };

          // Validate HTTP status (must be 2xx)
          if (binaryResult.statusCode < 200 || binaryResult.statusCode >= 300) {
            return { success: false };
          }

          // Validate Content-Type (must be image/* or application/octet-stream)
          const ct = binaryResult.contentType.toLowerCase().split(';')[0].trim();
          if (ct && !ct.startsWith('image/') && ct !== 'application/octet-stream') {
            return { success: false };
          }

          // Validate size (16 bytes to 1MB)
          const buf = binaryResult.buffer;
          if (buf.length < 16 || buf.length > 1_048_576) {
            return { success: false };
          }

          const hash = faviconHash(buf);
          const hashes = matchStr.split('|').map(Number);
          if (hashes.includes(hash)) {
            return { success: true };
          }
        } else {
          // Legacy regex match on body text
          const response = await this.httpRequest(url, 'GET');
          if (!response) return { success: false };

          const matchPattern2 = typeof pattern.match === 'string'
            ? new RegExp(pattern.match, 'i')
            : pattern.match;

          if (matchPattern2.test(response.body)) {
            let version: string | undefined;
            if (pattern.versionExtract && !this.options.skipVersionDetection) {
              const versionMatch = response.body.match(pattern.versionExtract);
              if (versionMatch?.[1]) {
                version = versionMatch[1];
              }
            }
            return { success: true, version };
          }
        }
      } else if (pattern.type === 'certificate') {
        const certInfo = await this.getCertificateInfo(baseUrl);
        
        if (certInfo) {
          const matchPattern = typeof pattern.match === 'string'
            ? new RegExp(pattern.match, 'i')
            : pattern.match;

          if (matchPattern.test(certInfo)) {
            return { success: true };
          }
        }
      }
    } catch {
      // Ignore errors during pattern testing
    }

    return { success: false };
  }

  /**
   * Check if response headers match a pattern (string or RegExp).
   */
  private matchHeaders(headers: Record<string, string | string[]>, match: string | RegExp): boolean {
    const headerStr = Object.entries(headers)
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
      .join('\n')
      .toLowerCase();

    const regex = typeof match === 'string' ? new RegExp(match, 'i') : match;
    return regex.test(headerStr);
  }

  /**
   * Check if a hostname is safe to connect to (not internal/special-use).
   * Resolves FQDNs via DNS. Returns false on DNS failure (fail-closed).
   * @deprecated Use resolveSafeAddresses() for DNS-rebinding-resistant requests.
   */
  private static async isHostSafe(hostname: string): Promise<boolean> {
    const addrs = await VpnScanner.resolveSafeAddresses(hostname);
    return addrs.length > 0;
  }

  /**
   * Resolve hostname to IP addresses, returning only safe (non-internal) ones.
   * Returns an empty array if the host is unsafe or DNS fails (fail-closed).
   * The caller should use these resolved IPs directly to prevent DNS rebinding.
   */
  static async resolveSafeAddresses(hostname: string): Promise<string[]> {
    if (net.isIP(hostname)) {
      return VpnScanner.isUnsafeIP(hostname) ? [] : [hostname];
    }
    try {
      const addresses = await dns.lookup(hostname, { all: true });
      // If ANY address is unsafe, reject the entire hostname (fail-closed)
      if (addresses.some(({ address }) => VpnScanner.isUnsafeIP(address))) {
        return [];
      }
      return addresses.map(({ address }) => address);
    } catch {
      return []; // DNS failure → fail-closed
    }
  }

  /**
   * Check if an IP address is unsafe (internal, special-use, or reserved).
   *
   * Fail-closed blocked ranges (IPv4):
   *   - 0.0.0.0/8        — "This" network (RFC1122)
   *   - 10.0.0.0/8       — Private-Use (RFC1918)
   *   - 100.64.0.0/10    — Shared Address / CGN (RFC6598)
   *   - 127.0.0.0/8      — Loopback (RFC1122)
   *   - 169.254.0.0/16   — Link-Local (RFC3927)
   *   - 172.16.0.0/12    — Private-Use (RFC1918)
   *   - 192.0.0.0/24     — IETF Protocol Assignments (RFC6890)
   *   - 192.0.2.0/24     — TEST-NET-1 / Documentation (RFC5737)
   *   - 192.88.99.0/24   — 6to4 Relay Anycast (RFC7526, deprecated)
   *   - 192.168.0.0/16   — Private-Use (RFC1918)
   *   - 198.18.0.0/15    — Benchmarking (RFC2544)
   *   - 198.51.100.0/24  — TEST-NET-2 / Documentation (RFC5737)
   *   - 203.0.113.0/24   — TEST-NET-3 / Documentation (RFC5737)
   *   - 224.0.0.0/4      — Multicast (RFC3171)
   *   - 240.0.0.0/4+     — Reserved / Future Use + Broadcast
   *
   * Fail-closed blocked ranges (IPv6):
   *   - ::1               — Loopback
   *   - ::                — Unspecified
   *   - fc00::/7          — Unique Local Address (ULA)
   *   - fe80::/10         — Link-Local
   *   - ff00::/8          — Multicast (RFC4291)
   *   - 2001:db8::/32     — Documentation (RFC3849)
   *   - ::ffff:0:0/96    — IPv4-mapped (delegated to IPv4 check)
   */
  static isUnsafeIP(ip: string): boolean {
    // Normalize and extract IPv4-mapped IPv6 (::ffff:x.x.x.x or 0:0:0:0:0:ffff:x.x.x.x)
    const normalized = ip.toLowerCase().trim();

    // Extract embedded IPv4 from IPv4-mapped IPv6 addresses
    const v4Mapped = VpnScanner.extractIPv4Mapped(normalized);
    if (v4Mapped) {
      return VpnScanner.isUnsafeIP(v4Mapped);
    }

    if (net.isIPv4(ip)) {
      const parts = ip.split('.').map(Number);
      return (
        parts[0] === 0 ||                                           // 0.0.0.0/8 (this network)
        parts[0] === 10 ||                                          // 10.0.0.0/8
        (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) || // 100.64.0.0/10 (CGN / RFC6598)
        parts[0] === 127 ||                                         // 127.0.0.0/8
        (parts[0] === 169 && parts[1] === 254) ||                  // 169.254.0.0/16 (link-local)
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||  // 172.16.0.0/12
        (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) ||  // 192.0.0.0/24 (IETF Protocol Assignments)
        (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) ||  // 192.0.2.0/24 (TEST-NET-1 / RFC5737)
        (parts[0] === 192 && parts[1] === 88 && parts[2] === 99) ||// 192.88.99.0/24 (6to4 Relay Anycast)
        (parts[0] === 192 && parts[1] === 168) ||                  // 192.168.0.0/16
        (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) || // 198.18.0.0/15 (benchmarking)
        (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) || // 198.51.100.0/24 (TEST-NET-2 / RFC5737)
        (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) || // 203.0.113.0/24 (TEST-NET-3 / RFC5737)
        parts[0] >= 224                                             // 224.0.0.0/4 (multicast) + 240+ (reserved)
      );
    }
    if (net.isIPv6(ip)) {
      const expanded = VpnScanner.expandIPv6(normalized);
      const first16 = parseInt(expanded.slice(0, 4), 16);
      return (
        expanded === '0000:0000:0000:0000:0000:0000:0000:0001' ||   // ::1 loopback
        expanded === '0000:0000:0000:0000:0000:0000:0000:0000' ||   // :: unspecified
        (first16 >= 0xfc00 && first16 <= 0xfdff) ||                 // fc00::/7 (ULA)
        (first16 >= 0xfe80 && first16 <= 0xfebf) ||                 // fe80::/10 (link-local)
        (first16 >= 0xff00) ||                                       // ff00::/8 (multicast)
        (first16 === 0x2001 && parseInt(expanded.slice(5, 9), 16) === 0x0db8) // 2001:db8::/32 (documentation)
      );
    }
    return false;
  }

  /**
   * Extract embedded IPv4 from IPv4-mapped IPv6 addresses.
   * Handles dotted form (::ffff:1.2.3.4) and hex form (::ffff:c0a8:0101).
   */
  private static extractIPv4Mapped(ip: string): string | null {
    // Dotted form: ::ffff:1.2.3.4 or 0:0:0:0:0:ffff:1.2.3.4
    const dottedMatch = ip.match(/::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i) ||
                        ip.match(/^0{0,4}(?::0{0,4}){4}:ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
    if (dottedMatch && net.isIPv4(dottedMatch[1])) {
      return dottedMatch[1];
    }

    // Hex form: ::ffff:c0a8:0101 or 0:0:0:0:0:ffff:c0a8:0101
    const hexMatch = ip.match(/::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i) ||
                     ip.match(/^0{0,4}(?::0{0,4}){4}:ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
    if (hexMatch) {
      const hi = parseInt(hexMatch[1], 16);
      const lo = parseInt(hexMatch[2], 16);
      if (hi > 0xffff || lo > 0xffff) return null;
      const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      if (net.isIPv4(v4)) {
        return v4;
      }
    }

    return null;
  }

  /**
   * Expand an IPv6 address to its full 8-group form (e.g., "::1" → "0000:0000:...0001").
   */
  static expandIPv6(ip: string): string {
    // Remove zone ID if present
    const noZone = ip.split('%')[0].toLowerCase();
    let halves = noZone.split('::');
    if (halves.length > 2) return '0000:0000:0000:0000:0000:0000:0000:0000'; // invalid

    let groups: string[];
    if (halves.length === 2) {
      const left = halves[0] ? halves[0].split(':') : [];
      const right = halves[1] ? halves[1].split(':') : [];
      const missing = 8 - left.length - right.length;
      groups = [...left, ...Array(missing).fill('0'), ...right];
    } else {
      groups = noZone.split(':');
    }

    return groups.map(g => g.padStart(4, '0')).slice(0, 8).join(':');
  }

  /**
   * Core request logic shared by text and binary fetches.
   * Handles SSRF-safe DNS resolution, redirect tracking, cross-host control,
   * and loop detection. The `singleFetch` callback performs the actual I/O.
   */
  private async httpRequestCore<T extends { statusCode: number; headers: Record<string, string | string[]> }>(
    url: string,
    singleFetch: (currentUrl: string, pinnedAddresses: string[]) => Promise<T | null>,
  ): Promise<T | null> {
    const maxRedirects = this.options.followRedirects ? 5 : 0;
    const visited = new Set<string>();
    let currentUrl = url;
    const originalHost = new URL(url).hostname;

    // SSRF: resolve and pin DNS for initial target
    let pinnedAddresses = await VpnScanner.resolveSafeAddresses(originalHost);
    if (pinnedAddresses.length === 0) return null;

    for (let i = 0; i <= maxRedirects; i++) {
      if (visited.has(currentUrl)) return null; // Loop detected
      visited.add(currentUrl);

      // Try with fallback across pinned addresses (up to 3 attempts)
      let response: T | null = null;
      const maxAttempts = Math.min(pinnedAddresses.length, 3);
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        response = await singleFetch(currentUrl, pinnedAddresses.slice(attempt));
        if (response) break;
      }
      if (!response) return null;

      // Follow redirect?
      const isRedirect = response.statusCode >= 300 && response.statusCode < 400;
      if (isRedirect && i < maxRedirects) {
        const location = response.headers['location'];
        const locationStr = Array.isArray(location) ? location[0] : location;
        if (locationStr) {
          // Resolve relative/absolute URL
          const redirectUrl = new URL(locationStr, currentUrl);
          const redirectHost = redirectUrl.hostname;

          // Block cross-host redirects unless explicitly allowed (check first)
          if (redirectHost !== originalHost && !this.options.allowCrossHostRedirects) {
            return null;
          }

          // Re-resolve and pin DNS for redirect target
          pinnedAddresses = await VpnScanner.resolveSafeAddresses(redirectHost);
          if (pinnedAddresses.length === 0) return null;

          currentUrl = redirectUrl.toString();
          continue;
        }
      }

      return response;
    }

    return null;
  }

  private async httpRequest(
    url: string,
    method: string = 'GET'
  ): Promise<HttpResponse | null> {
    return this.httpRequestCore<HttpResponse>(
      url,
      (currentUrl, pinnedAddresses) => this.httpRequestSingle(currentUrl, method, pinnedAddresses),
    );
  }

  /**
   * Build a pinned DNS lookup function that returns pre-resolved addresses.
   * Supports fallback: rotates through candidates on repeated calls,
   * respecting family hints when available.
   * Prevents DNS rebinding by ensuring the connection uses the same IPs
   * that were validated during the safety check.
   */
  private static buildPinnedLookup(pinnedAddresses: string[]): (
    hostname: string,
    options: any,
    callback: (err: Error | null, address: string, family: number) => void
  ) => void {
    let callIndex = 0;
    return (_hostname, options, callback) => {
      // Filter by family hint if provided
      const familyHint = options?.family;
      const candidates = familyHint
        ? pinnedAddresses.filter(a => (net.isIPv4(a) ? 4 : 6) === familyHint)
        : pinnedAddresses;
      const pool = candidates.length > 0 ? candidates : pinnedAddresses;

      if (pool.length === 0) {
        callback(new Error('No pinned addresses available'), '', 0);
        return;
      }

      const addr = pool[callIndex % pool.length];
      callIndex++;
      const family = net.isIPv4(addr) ? 4 : 6;
      callback(null, addr, family);
    };
  }

  private async httpRequestSingle(
    url: string,
    method: string = 'GET',
    pinnedAddresses?: string[]
  ): Promise<HttpResponse | null> {
    return new Promise((resolve) => {
      try {
        const parsedUrl = new URL(url);
        const isHttps = parsedUrl.protocol === 'https:';
        const lib = isHttps ? https : http;

        const options: Record<string, any> = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (isHttps ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method,
          headers: {
            'User-Agent': this.options.userAgent,
            Accept: 'text/html,application/xhtml+xml,*/*',
            ...this.options.headers,
          },
          timeout: this.options.timeout,
          rejectUnauthorized: false, // Accept self-signed certs (common for VPN devices)
        };

        // Pin DNS resolution to prevent rebinding attacks
        if (pinnedAddresses && pinnedAddresses.length > 0) {
          options.lookup = VpnScanner.buildPinnedLookup(pinnedAddresses);
          // Set servername for TLS/SNI (must be the original hostname, not the IP)
          if (isHttps && !net.isIP(parsedUrl.hostname)) {
            options.servername = parsedUrl.hostname;
          }
        }

        const req = lib.request(options, (res) => {
          let body = '';
          
          res.setEncoding('utf8');
          res.on('data', (chunk) => {
            body += chunk;
            // Limit body size
            if (body.length > 100000) {
              req.destroy();
            }
          });
          
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode || 0,
              headers: res.headers as Record<string, string | string[]>,
              body,
            });
          });
        });

        req.on('error', () => resolve(null));
        req.on('timeout', () => {
          req.destroy();
          resolve(null);
        });

        req.end();
      } catch {
        resolve(null);
      }
    });
  }

  /**
   * Fetch a URL and return the raw response body as a Buffer (binary-safe).
   * Used for favicon hash computation.
   */
  private async httpRequestBinary(url: string): Promise<{ buffer: Buffer; statusCode: number; contentType: string } | null> {
    const result = await this.httpRequestCore<{ statusCode: number; headers: Record<string, string | string[]>; body: Buffer }>(
      url,
      (currentUrl, pinnedAddresses) => this.httpRequestBinarySingle(currentUrl, pinnedAddresses),
    );
    if (!result) return null;

    const contentTypeRaw = result.headers['content-type'];
    const contentType = (Array.isArray(contentTypeRaw) ? contentTypeRaw[0] : contentTypeRaw) || '';
    return { buffer: result.body, statusCode: result.statusCode, contentType };
  }

  private async httpRequestBinarySingle(
    url: string,
    pinnedAddresses?: string[]
  ): Promise<{ statusCode: number; headers: Record<string, string | string[]>; body: Buffer } | null> {
    return new Promise((resolve) => {
      try {
        const parsedUrl = new URL(url);
        const isHttps = parsedUrl.protocol === 'https:';
        const lib = isHttps ? https : http;

        const options: Record<string, any> = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (isHttps ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method: 'GET',
          headers: {
            'User-Agent': this.options.userAgent,
            Accept: '*/*',
            ...this.options.headers,
          },
          timeout: this.options.timeout,
          rejectUnauthorized: false,
        };

        // Pin DNS resolution to prevent rebinding attacks
        if (pinnedAddresses && pinnedAddresses.length > 0) {
          options.lookup = VpnScanner.buildPinnedLookup(pinnedAddresses);
          if (isHttps && !net.isIP(parsedUrl.hostname)) {
            options.servername = parsedUrl.hostname;
          }
        }

        const req = lib.request(options, (res) => {
          const chunks: Buffer[] = [];
          let totalLen = 0;

          res.on('data', (chunk: Buffer) => {
            totalLen += chunk.length;
            if (totalLen > 1_000_000) {
              req.destroy();
              return;
            }
            chunks.push(chunk);
          });

          res.on('end', () => {
            resolve({
              statusCode: res.statusCode || 0,
              headers: res.headers as Record<string, string | string[]>,
              body: Buffer.concat(chunks),
            });
          });
        });

        req.on('error', () => resolve(null));
        req.on('timeout', () => {
          req.destroy();
          resolve(null);
        });

        req.end();
      } catch {
        resolve(null);
      }
    });
  }

  private async getCertificateInfo(url: string): Promise<string | null> {
    const parsedUrl = new URL(url);

    if (parsedUrl.protocol !== 'https:') {
      return null;
    }

    const hostname = parsedUrl.hostname;
    const port = Number(parsedUrl.port) || 443;

    // Resolve safe addresses to prevent DNS rebinding
    const safeAddresses = await VpnScanner.resolveSafeAddresses(hostname);
    if (safeAddresses.length === 0) {
      return null;
    }

    // Try each pinned IP with fallback
    for (const ip of safeAddresses) {
      const result = await this.getCertificateInfoSingle(ip, port, hostname);
      if (result !== null) return result;
    }

    return null;
  }

  private getCertificateInfoSingle(ip: string, port: number, hostname: string): Promise<string | null> {
    return new Promise((resolve) => {
      try {
        const tlsOptions: tls.ConnectionOptions = {
          host: ip,
          port,
          rejectUnauthorized: false,
          timeout: this.options.timeout,
        };

        // Set SNI servername to original hostname (skip for IP-literal targets)
        if (!net.isIP(hostname)) {
          tlsOptions.servername = hostname;
        }

        const socket = tls.connect(
          tlsOptions,
          () => {
            const cert = socket.getPeerCertificate();
            socket.end();

            if (cert) {
              const info = [
                cert.subject?.CN,
                cert.subject?.O,
                cert.issuer?.CN,
                cert.issuer?.O,
              ]
                .filter(Boolean)
                .join(' ');
              
              resolve(info);
            } else {
              resolve(null);
            }
          }
        );

        socket.on('error', () => resolve(null));
        socket.on('timeout', () => {
          socket.destroy();
          resolve(null);
        });
      } catch {
        resolve(null);
      }
    });
  }

  private async checkVulnerabilities(
    device: VpnDevice,
    _baseUrl: string
  ): Promise<VulnerabilityMatch[]> {
    const matches: VulnerabilityMatch[] = [];

    // Resolve product alias before matching (e.g. "Pulse Connect Secure" → "Connect Secure")
    const canonicalProduct = resolveProductAlias(device.product, device.vendor);
    const canonicalProductNorm = normalizeProduct(canonicalProduct);
    // Also keep original product norm for matching CVE entries that use legacy names
    const originalProductNorm = normalizeProduct(device.product);

    // Resolve vendor alias via product mapping (e.g. pulse → ivanti)
    const resolved = resolveProductAndVendor(device.product);
    const effectiveVendor = resolved?.vendor;

    // Build set of vendors to search: device.vendor + effectiveVendor (if different)
    const vendorsToSearch = new Set<string>([device.vendor]);
    if (effectiveVendor && effectiveVendor !== device.vendor) {
      vendorsToSearch.add(effectiveVendor);
    }

    // Build set of product names to match (canonical + original + CVE-side alias resolution)
    const productNorms = new Set([canonicalProductNorm, originalProductNorm]);

    // Helper: check if a CVE affected entry's product matches our device
    const isProductMatch = (aProduct: string | undefined): boolean => {
      if (!aProduct) return true; // no product constraint = matches all for this vendor
      const aNorm = normalizeProduct(aProduct);
      if (productNorms.has(aNorm)) return true;
      // Also resolve the CVE's product through alias (e.g. CVE says "Pulse Connect Secure" → "Connect Secure")
      const aCanonical = resolveProductAlias(aProduct);
      return productNorms.has(normalizeProduct(aCanonical));
    };

    // Get vulnerabilities for all matching vendors
    const vendorVulns = vulnerabilities.filter(v =>
      v.affected.some(a => vendorsToSearch.has(a.vendor))
    );

    for (const vuln of vendorVulns) {
      // Check if product matches across all vendor aliases
      const productMatch = vuln.affected.some(
        a => vendorsToSearch.has(a.vendor) && isProductMatch(a.product)
      );

      if (productMatch) {
        // Without version info, we can only say "potential"
        // With version info, we can be more confident
        let confidence: 'confirmed' | 'likely' | 'potential' = 'potential';
        let evidence = `Device detected as ${device.vendor} ${device.product}`;

        if (device.version && !this.options.skipVersionDetection) {
          // Check if any affected entry for this vendor has version constraints
          const matchingAffected = vuln.affected.filter(
            a => vendorsToSearch.has(a.vendor) && isProductMatch(a.product)
          );
          
          const affectedWithVersion = matchingAffected.find(
            a => hasVersionConstraints(a) && isVersionAffected(device.version!, a)
          );
          
          // Check if there are entries WITHOUT version constraints (vendor/product only)
          const hasNoVersionEntries = matchingAffected.some(a => !hasVersionConstraints(a));

          if (affectedWithVersion) {
            confidence = 'confirmed';
            evidence = `Version ${device.version} is in affected range`;
          } else if (hasNoVersionEntries) {
            // CVE has no version range defined - keep as potential (or likely if KEV)
            confidence = vuln.cisaKev ? 'likely' : 'potential';
            evidence += '. No version range defined for this CVE.';
            if (vuln.cisaKev) {
              evidence += ' This CVE is in CISA Known Exploited Vulnerabilities catalog.';
            }
          } else {
            // Version detected but not in any affected range - skip
            continue;
          }
        } else {
          // No version info or skipVersionDetection - mark as potential if CISA KEV
          if (vuln.cisaKev) {
            confidence = 'likely';
            evidence += '. This CVE is in CISA Known Exploited Vulnerabilities catalog.';
          }
        }

        matches.push({
          vulnerability: vuln,
          confidence,
          evidence,
        });
      }
    }

    // Sort by severity and confidence
    return matches.sort((a, b) => {
      const severityDiff = getSeverityWeight(a.vulnerability.severity) - getSeverityWeight(b.vulnerability.severity);
      if (severityDiff !== 0) return severityDiff;
      
      return getConfidenceWeight(a.confidence) - getConfidenceWeight(b.confidence);
    });
  }

}

export async function scan(target: string, options?: ScanOptions): Promise<ScanResult> {
  const scanner = new VpnScanner(options);
  return scanner.scan(target);
}

export async function scanMultiple(targets: string[], options?: ScanOptions): Promise<ScanResult[]> {
  const scanner = new VpnScanner(options);
  return scanner.scanMultiple(targets);
}
