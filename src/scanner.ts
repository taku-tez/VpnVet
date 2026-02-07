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
  compareVersions,
  isVersionAffected,
  hasVersionConstraints,
  getSeverityWeight,
  getConfidenceWeight,
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
        }
      }
    } catch (error) {
      result.errors.push(error instanceof Error ? error.message : String(error));
    }

    return result;
  }

  async scanMultiple(targets: string[]): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    
    for (const target of targets) {
      const result = await this.scan(target);
      results.push(result);
    }
    
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
        const response = await this.httpRequest(baseUrl, 'HEAD');
        
        if (!response) return { success: false };

        const matchPattern = typeof pattern.match === 'string'
          ? pattern.match.toLowerCase()
          : pattern.match;

        const headerStr = Object.entries(response.headers)
          .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
          .join('\n')
          .toLowerCase();

        if (typeof matchPattern === 'string') {
          if (headerStr.includes(matchPattern)) {
            return { success: true };
          }
        } else if (matchPattern.test(headerStr)) {
          return { success: true };
        }
      } else if (pattern.type === 'favicon') {
        const faviconPath = pattern.path || '/favicon.ico';
        const url = `${baseUrl}${faviconPath}`;
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

  private static isPrivateIP(hostname: string): boolean {
    // Check if hostname resolves to a private/internal IP
    if (net.isIPv4(hostname)) {
      const parts = hostname.split('.').map(Number);
      return (
        parts[0] === 10 ||                                          // 10.0.0.0/8
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || // 172.16.0.0/12
        (parts[0] === 192 && parts[1] === 168) ||                  // 192.168.0.0/16
        parts[0] === 127 ||                                         // 127.0.0.0/8
        (parts[0] === 169 && parts[1] === 254)                     // 169.254.0.0/16
      );
    }
    if (net.isIPv6(hostname)) {
      const normalized = hostname.toLowerCase();
      return (
        normalized === '::1' ||
        normalized.startsWith('fc') ||
        normalized.startsWith('fd') ||
        normalized.startsWith('fe80')
      );
    }
    return false;
  }

  private async httpRequest(
    url: string,
    method: string = 'GET'
  ): Promise<HttpResponse | null> {
    const maxRedirects = this.options.followRedirects ? 5 : 0;
    const visited = new Set<string>();
    let currentUrl = url;
    const originalHost = new URL(url).hostname;

    for (let i = 0; i <= maxRedirects; i++) {
      if (visited.has(currentUrl)) return null; // Loop detected
      visited.add(currentUrl);

      const response = await this.httpRequestSingle(currentUrl, method);
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

          // Always block redirects to private/internal IPs
          if (VpnScanner.isPrivateIP(redirectHost)) {
            return null;
          }

          // If redirectHost is a hostname (not an IP), resolve it and check
          if (!net.isIP(redirectHost)) {
            try {
              const { address } = await dns.lookup(redirectHost);
              if (VpnScanner.isPrivateIP(address)) {
                return null;
              }
            } catch {
              // DNS resolution failed — block to be safe
              return null;
            }
          }

          currentUrl = redirectUrl.toString();
          continue;
        }
      }

      return response;
    }

    return null;
  }

  private async httpRequestSingle(
    url: string,
    method: string = 'GET'
  ): Promise<HttpResponse | null> {
    return new Promise((resolve) => {
      try {
        const parsedUrl = new URL(url);
        const isHttps = parsedUrl.protocol === 'https:';
        const lib = isHttps ? https : http;

        const options = {
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

  private async getCertificateInfo(url: string): Promise<string | null> {
    return new Promise((resolve) => {
      try {
        const parsedUrl = new URL(url);
        
        if (parsedUrl.protocol !== 'https:') {
          resolve(null);
          return;
        }

        const tlsOptions: tls.ConnectionOptions = {
          host: parsedUrl.hostname,
          port: Number(parsedUrl.port) || 443,
          rejectUnauthorized: false,
          timeout: this.options.timeout,
        };

        // Set SNI servername for virtual host environments (skip for IP addresses)
        if (!net.isIP(parsedUrl.hostname)) {
          tlsOptions.servername = parsedUrl.hostname;
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
