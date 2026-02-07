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
import { fingerprints } from './fingerprints/index.js';
import { vulnerabilities } from './vulnerabilities.js';
import {
  normalizeUrl,
  normalizeProduct,
  compareVersions,
  isVersionAffected,
  hasVersionConstraints,
  getSeverityWeight,
  getConfidenceWeight,
  faviconHash,
} from './utils.js';
import type {
  ScanResult,
  ScanOptions,
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
};

interface HttpResponse {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
}

export class VpnScanner {
  private options: Required<ScanOptions>;

  constructor(options: ScanOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };

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
    };

    try {
      // Normalize target URL
      const baseUrl = normalizeUrl(target);
      
      // Try to detect VPN device
      const device = await this.detectDevice(baseUrl);
      
      if (device) {
        result.device = device;
        
        // Check for vulnerabilities if device detected
        if (!this.options.skipVulnCheck) {
          result.vulnerabilities = await this.checkVulnerabilities(device, baseUrl);

          // Check if any CVE definitions exist for this vendor/product
          const deviceProductNorm = normalizeProduct(device.product);
          const hasCveMappings = vulnerabilities.some(v =>
            v.affected.some(a =>
              a.vendor === device.vendor &&
              (!a.product || normalizeProduct(a.product) === deviceProductNorm)
            )
          );
          if (!hasCveMappings) {
            result.coverageWarning = `No CVE mappings currently available for ${device.vendor} ${device.product}. Detection coverage and vulnerability coverage are independent — a detected product with zero CVEs does not imply it is secure.`;
          }
        }
      }
    } catch (error) {
      result.errors.push(error instanceof Error ? error.message : String(error));
    }

    return result;
  }

  async scanMultiple(targets: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = new Array(targets.length);
    const concurrency = Math.max(1, this.options.concurrency || 5);
    let index = 0;

    const worker = async () => {
      while (index < targets.length) {
        const i = index++;
        results[i] = await this.scan(targets[i]);
      }
    };

    await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, () => worker()));
    return results;
  }

  private async detectDevice(baseUrl: string): Promise<VpnDevice | undefined> {
    // Determine URLs to try based on ports option
    const urlsToTry = this.buildPortUrls(baseUrl);

    for (const url of urlsToTry) {
      const result = await this.detectDeviceForUrl(url);
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

  private async detectDeviceForUrl(baseUrl: string): Promise<VpnDevice | undefined> {
    // SSRF: block private/internal targets at the detection level
    const parsedBase = new URL(baseUrl);
    if (!(await VpnScanner.isHostSafe(parsedBase.hostname))) {
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
        const matched = await this.testPattern(baseUrl, pattern);
        
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
    pattern: FingerprintPattern
  ): Promise<{ success: boolean; version?: string }> {
    try {
      if (pattern.type === 'endpoint' || pattern.type === 'body') {
        const url = pattern.path ? `${baseUrl}${pattern.path}` : baseUrl;
        const response = await this.httpRequest(url, pattern.method || 'GET');
        
        if (!response) return { success: false };

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
   * Covers RFC1918, RFC5737, RFC6598 (CGN), loopback, link-local,
   * benchmarking, multicast, and IPv4-mapped IPv6 addresses.
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
        (parts[0] === 192 && parts[1] === 168) ||                  // 192.168.0.0/16
        (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) || // 198.18.0.0/15 (benchmarking)
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
        (first16 >= 0xfe80 && first16 <= 0xfebf)                    // fe80::/10 (link-local)
      );
    }
    return false;
  }

  /**
   * Extract embedded IPv4 from IPv4-mapped IPv6 addresses.
   * Handles ::ffff:x.x.x.x and 0:0:0:0:0:ffff:x.x.x.x forms.
   */
  private static extractIPv4Mapped(ip: string): string | null {
    // Dotted form: ::ffff:1.2.3.4 or 0:0:0:0:0:ffff:1.2.3.4
    const dottedMatch = ip.match(/::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i) ||
                        ip.match(/^0{0,4}(?::0{0,4}){4}:ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
    if (dottedMatch && net.isIPv4(dottedMatch[1])) {
      return dottedMatch[1];
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

  /** @deprecated Use isUnsafeIP instead */
  private static isPrivateIP(ip: string): boolean {
    return VpnScanner.isUnsafeIP(ip);
  }

  private async httpRequest(
    url: string,
    method: string = 'GET'
  ): Promise<HttpResponse | null> {
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
      let response: HttpResponse | null = null;
      const maxAttempts = Math.min(pinnedAddresses.length, 3);
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        // buildPinnedLookup rotates through addresses on each call
        response = await this.httpRequestSingle(currentUrl, method, pinnedAddresses.slice(attempt));
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

  /**
   * Build a pinned DNS lookup function that returns pre-resolved addresses.
   * Prevents DNS rebinding by ensuring the connection uses the same IPs
   * that were validated during the safety check.
   */
  /**
   * Build a pinned DNS lookup function that returns pre-resolved addresses.
   * Supports fallback: rotates through candidates on repeated calls,
   * respecting family hints when available.
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
    const maxRedirects = this.options.followRedirects ? 5 : 0;
    const visited = new Set<string>();
    let currentUrl = url;
    const originalHost = new URL(url).hostname;

    // SSRF: resolve and pin DNS for initial target
    let pinnedAddresses = await VpnScanner.resolveSafeAddresses(originalHost);
    if (pinnedAddresses.length === 0) return null;

    for (let i = 0; i <= maxRedirects; i++) {
      if (visited.has(currentUrl)) return null;
      visited.add(currentUrl);

      // Try with fallback across pinned addresses (up to 3 attempts)
      let result: { statusCode: number; headers: Record<string, string | string[]>; body: Buffer } | null = null;
      const maxAttempts = Math.min(pinnedAddresses.length, 3);
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        result = await this.httpRequestBinarySingle(currentUrl, pinnedAddresses.slice(attempt));
        if (result) break;
      }
      if (!result) return null;

      const isRedirect = result.statusCode >= 300 && result.statusCode < 400;
      if (isRedirect && i < maxRedirects) {
        const location = result.headers['location'];
        const locationStr = Array.isArray(location) ? location[0] : location;
        if (locationStr) {
          const redirectUrl = new URL(locationStr, currentUrl);
          const redirectHost = redirectUrl.hostname;

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

      const contentTypeRaw = result.headers['content-type'];
      const contentType = (Array.isArray(contentTypeRaw) ? contentTypeRaw[0] : contentTypeRaw) || '';

      return { buffer: result.body, statusCode: result.statusCode, contentType };
    }

    return null;
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

    // Get vulnerabilities for this vendor
    const vendorVulns = vulnerabilities.filter(v =>
      v.affected.some(a => a.vendor === device.vendor)
    );

    for (const vuln of vendorVulns) {
      // Check if product matches
      const productMatch = vuln.affected.some(
        a => a.vendor === device.vendor && 
            (a.product === device.product || !a.product)
      );

      if (productMatch) {
        // Without version info, we can only say "potential"
        // With version info, we can be more confident
        let confidence: 'confirmed' | 'likely' | 'potential' = 'potential';
        let evidence = `Device detected as ${device.vendor} ${device.product}`;

        if (device.version && !this.options.skipVersionDetection) {
          // Check if any affected entry for this vendor has version constraints
          const matchingAffected = vuln.affected.filter(
            a => a.vendor === device.vendor && (a.product === device.product || !a.product)
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
