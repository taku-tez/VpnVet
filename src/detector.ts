/**
 * VPN Device Detection Logic
 *
 * Fingerprint matching, scoring, and device identification.
 */

import { URL } from 'node:url';
import { fingerprints } from './fingerprints/index.js';
import { faviconHash } from './utils.js';
import {
  isHostSafe,
  httpRequest,
  httpRequestBinary,
  getCertificateInfo,
} from './http-client.js';
import type { HttpClientOptions, HttpRequestError } from './http-client.js';
import type {
  ScanResult,
  ScanError,
  ScanErrorKind,
  VpnDevice,
  Fingerprint,
  FingerprintPattern,
  DetectionMethod,
} from './types.js';

// ---------------------------------------------------------------------------
// Port URL construction
// ---------------------------------------------------------------------------

export function buildPortUrls(baseUrl: string, ports: number[]): string[] {
  const parsedUrl = new URL(baseUrl);

  if (parsedUrl.port) {
    return [baseUrl];
  }

  const urls: string[] = [];
  for (const port of ports) {
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

  return [...new Set(urls)];
}

// ---------------------------------------------------------------------------
// Header matching
// ---------------------------------------------------------------------------

export function matchHeaders(headers: Record<string, string | string[]>, match: string | RegExp): boolean {
  const headerStr = Object.entries(headers)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
    .join('\n')
    .toLowerCase();

  const regex = typeof match === 'string' ? new RegExp(match, 'i') : match;
  return regex.test(headerStr);
}

// ---------------------------------------------------------------------------
// Dedup scan error helper
// ---------------------------------------------------------------------------

/**
 * Add a scan error with dedup by (kind, url, statusCode).
 */
export function addScanError(
  scanResult: ScanResult,
  entry: ScanError,
): void {
  scanResult.scanErrors ??= [];
  const isDuplicate = scanResult.scanErrors.some(
    e => e.kind === entry.kind && e.url === entry.url && e.statusCode === entry.statusCode,
  );
  if (!isDuplicate) {
    scanResult.scanErrors.push(entry);
  }
}

/**
 * Record an HTTP request error (network failure) into scanErrors.
 */
function recordHttpError(
  scanResult: ScanResult | undefined,
  url: string,
  error: HttpRequestError | undefined,
): void {
  if (!scanResult || !error) return;
  addScanError(scanResult, { kind: error.kind, message: error.message, url });
}

/**
 * Record an HTTP status error (4xx/5xx) into scanErrors.
 */
function recordHttpStatus(
  scanResult: ScanResult | undefined,
  url: string,
  statusCode: number,
): void {
  if (!scanResult || statusCode < 400) return;
  addScanError(scanResult, {
    kind: 'http-status',
    message: `HTTP ${statusCode} from ${url}`,
    url,
    statusCode,
  });
}

// ---------------------------------------------------------------------------
// Pattern testing
// ---------------------------------------------------------------------------

export async function testPattern(
  baseUrl: string,
  pattern: FingerprintPattern,
  httpOpts: HttpClientOptions,
  skipVersionDetection: boolean,
  scanResult?: ScanResult,
): Promise<{ success: boolean; version?: string }> {
  try {
    if (pattern.type === 'endpoint' || pattern.type === 'body') {
      const baseOrigin = new URL(baseUrl).origin;
      const url = pattern.path ? `${baseOrigin}${pattern.path}` : baseUrl;
      const result = await httpRequest(url, pattern.method || 'GET', httpOpts);

      if (!result.data) {
        recordHttpError(scanResult, url, result.error);
        return { success: false };
      }

      const response = result.data;
      recordHttpStatus(scanResult, url, response.statusCode);

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
        if (pattern.versionExtract && !skipVersionDetection) {
          const versionMatch = response.body.match(pattern.versionExtract);
          if (versionMatch?.[1]) {
            version = versionMatch[1];
          }
        }
        return { success: true, version };
      }
    } else if (pattern.type === 'header') {
      const url = baseUrl;
      let result = await httpRequest(url, 'HEAD', httpOpts);
      if (!result.data || result.data.statusCode === 405 || result.data.statusCode === 501) {
        result = await httpRequest(url, 'GET', httpOpts);
      }

      if (!result.data) {
        recordHttpError(scanResult, url, result.error);
        return { success: false };
      }

      const response = result.data;
      recordHttpStatus(scanResult, url, response.statusCode);

      if (pattern.status) {
        if (!pattern.status.includes(response.statusCode)) return { success: false };
      } else {
        if (response.statusCode < 200 || response.statusCode >= 300) return { success: false };
      }

      if (matchHeaders(response.headers, pattern.match)) {
        return { success: true };
      }
    } else if (pattern.type === 'favicon') {
      const faviconPath = pattern.path || '/favicon.ico';
      const url = `${new URL(baseUrl).origin}${faviconPath}`;

      const matchStr = typeof pattern.match === 'string' ? pattern.match : null;
      const isHashMatch = matchStr && /^-?\d+(\|-?\d+)*$/.test(matchStr);

      if (isHashMatch) {
        const binResult = await httpRequestBinary(url, httpOpts);
        if (!binResult.data) {
          recordHttpError(scanResult, url, binResult.error);
          return { success: false };
        }

        const binaryResult = binResult.data;
        recordHttpStatus(scanResult, url, binaryResult.statusCode);

        if (binaryResult.statusCode < 200 || binaryResult.statusCode >= 300) return { success: false };

        const ct = binaryResult.contentType.toLowerCase().split(';')[0].trim();
        if (ct && !ct.startsWith('image/') && ct !== 'application/octet-stream') return { success: false };

        const buf = binaryResult.buffer;
        if (buf.length < 16 || buf.length > 1_048_576) return { success: false };

        const hash = faviconHash(buf);
        const hashes = matchStr.split('|').map(Number);
        if (hashes.includes(hash)) {
          return { success: true };
        }
      } else {
        const result = await httpRequest(url, 'GET', httpOpts);
        if (!result.data) {
          recordHttpError(scanResult, url, result.error);
          return { success: false };
        }

        const response = result.data;
        recordHttpStatus(scanResult, url, response.statusCode);

        if (pattern.status) {
          if (!pattern.status.includes(response.statusCode)) return { success: false };
        } else {
          if (response.statusCode < 200 || response.statusCode >= 300) return { success: false };
        }

        const matchPattern2 = typeof pattern.match === 'string'
          ? new RegExp(pattern.match, 'i')
          : pattern.match;

        if (matchPattern2.test(response.body)) {
          let version: string | undefined;
          if (pattern.versionExtract && !skipVersionDetection) {
            const versionMatch = response.body.match(pattern.versionExtract);
            if (versionMatch?.[1]) {
              version = versionMatch[1];
            }
          }
          return { success: true, version };
        }
      }
    } else if (pattern.type === 'certificate') {
      const url = baseUrl;
      const certResult = await getCertificateInfo(url, httpOpts.timeout);

      if (!certResult.data) {
        recordHttpError(scanResult, url, certResult.error);
        return { success: false };
      }

      const matchPattern = typeof pattern.match === 'string'
        ? new RegExp(pattern.match, 'i')
        : pattern.match;

      if (matchPattern.test(certResult.data)) {
        return { success: true };
      }
    }
  } catch (err) {
    if (scanResult) {
      const kind: ScanErrorKind = 'pattern-error';
      const message = err instanceof Error ? err.message : String(err);
      const url = pattern.path ? `${new URL(baseUrl).origin}${pattern.path}` : baseUrl;
      addScanError(scanResult, { kind, message, url });
    }
  }

  return { success: false };
}

// ---------------------------------------------------------------------------
// Device detection
// ---------------------------------------------------------------------------

export interface DetectOptions {
  ports: number[];
  vendor: string;
  fast: boolean;
  skipVersionDetection: boolean;
  httpOpts: HttpClientOptions;
}

export async function detectDevice(
  baseUrl: string,
  opts: DetectOptions,
  scanResult?: ScanResult,
): Promise<VpnDevice | undefined> {
  const urlsToTry = buildPortUrls(baseUrl, opts.ports);

  const parsedBase = new URL(baseUrl);
  if (!(await isHostSafe(parsedBase.hostname))) {
    const msg = `SSRF blocked: ${parsedBase.hostname} resolves to internal/unsafe address`;
    if (scanResult) {
      scanResult.errors.push(msg);
      addScanError(scanResult, { kind: 'ssrf-blocked', message: msg, url: baseUrl });
    }
    return undefined;
  }

  for (const url of urlsToTry) {
    const result = await detectDeviceForUrl(url, opts, scanResult);
    if (result) return result;
  }

  return undefined;
}

export async function detectDeviceForUrl(
  baseUrl: string,
  opts: DetectOptions,
  scanResult?: ScanResult,
): Promise<VpnDevice | undefined> {
  const parsedBase = new URL(baseUrl);
  if (!(await isHostSafe(parsedBase.hostname))) {
    const msg = `SSRF blocked: ${parsedBase.hostname} resolves to internal/unsafe address`;
    if (scanResult) {
      const alreadyBlocked = scanResult.scanErrors?.some(
        e => e.kind === 'ssrf-blocked' && e.message?.includes(parsedBase.hostname)
      );
      if (!alreadyBlocked) {
        scanResult.errors.push(msg);
        addScanError(scanResult, { kind: 'ssrf-blocked', message: msg, url: baseUrl });
      }
    }
    return undefined;
  }

  const scores: Map<string, { fingerprint: Fingerprint; score: number; methods: DetectionMethod[]; endpoints: string[]; version?: string }> = new Map();

  let fingerprintsToTest = fingerprints;
  if (opts.vendor) {
    fingerprintsToTest = fingerprints.filter(f => f.vendor === opts.vendor);
  }

  for (const fingerprint of fingerprintsToTest) {
    let totalScore = 0;
    const methods: DetectionMethod[] = [];
    const endpoints: string[] = [];
    let detectedVersion: string | undefined;

    for (const pattern of fingerprint.patterns) {
      const matched = await testPattern(baseUrl, pattern, opts.httpOpts, opts.skipVersionDetection, scanResult);

      if (matched.success) {
        totalScore += pattern.weight;

        if (matched.version && !detectedVersion) {
          detectedVersion = matched.version;
        }

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

      if (opts.fast && totalScore >= 10) {
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

  let bestMatch: { fingerprint: Fingerprint; score: number; methods: DetectionMethod[]; endpoints: string[]; version?: string } | undefined;

  for (const match of scores.values()) {
    if (!bestMatch || match.score > bestMatch.score) {
      bestMatch = match;
    }
  }

  if (bestMatch && bestMatch.score >= 5) {
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
