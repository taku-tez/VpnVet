/**
 * HTTP Client with SSRF protection
 *
 * Provides DNS-pinned HTTP requests (text & binary) and TLS certificate retrieval.
 */

import * as https from 'node:https';
import * as http from 'node:http';
import * as tls from 'node:tls';
import * as net from 'node:net';
import * as dns from 'node:dns/promises';
import { URL } from 'node:url';
import type { ScanErrorKind } from './types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: string;
}

export interface BinaryResponse {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: Buffer;
}

export interface BinaryResult {
  buffer: Buffer;
  statusCode: number;
  contentType: string;
}

/** Enriched result carrying optional error info when data is null */
export interface HttpRequestError {
  kind: ScanErrorKind;
  message: string;
}

export interface HttpResult<T> {
  data: T | null;
  error?: HttpRequestError;
}

// ---------------------------------------------------------------------------
// Error classification (shared with scanner.ts)
// ---------------------------------------------------------------------------

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

export interface HttpClientOptions {
  timeout: number;
  userAgent: string;
  headers: Record<string, string>;
  followRedirects: boolean;
  allowCrossHostRedirects: boolean;
  insecureTls?: boolean;
}

// ---------------------------------------------------------------------------
// SSRF – IP safety checks
// ---------------------------------------------------------------------------

/**
 * Check if an IP address is unsafe (internal, special-use, or reserved).
 */
export function isUnsafeIP(ip: string): boolean {
  const normalized = ip.toLowerCase().trim();

  const v4Mapped = extractIPv4Mapped(normalized);
  if (v4Mapped) {
    return isUnsafeIP(v4Mapped);
  }

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    return (
      parts[0] === 0 ||
      parts[0] === 10 ||
      (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) ||
      parts[0] === 127 ||
      (parts[0] === 169 && parts[1] === 254) ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) ||
      (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) ||
      (parts[0] === 192 && parts[1] === 88 && parts[2] === 99) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) ||
      (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) ||
      (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) ||
      parts[0] >= 224
    );
  }
  if (net.isIPv6(ip)) {
    const expanded = expandIPv6(normalized);
    const first16 = parseInt(expanded.slice(0, 4), 16);
    return (
      expanded === '0000:0000:0000:0000:0000:0000:0000:0001' ||
      expanded === '0000:0000:0000:0000:0000:0000:0000:0000' ||
      (first16 >= 0xfc00 && first16 <= 0xfdff) ||
      (first16 >= 0xfe80 && first16 <= 0xfebf) ||
      (first16 >= 0xff00) ||
      (first16 === 0x2001 && parseInt(expanded.slice(5, 9), 16) === 0x0db8)
    );
  }
  return false;
}

/**
 * Extract embedded IPv4 from IPv4-mapped IPv6 addresses.
 */
export function extractIPv4Mapped(ip: string): string | null {
  const dottedMatch = ip.match(/::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i) ||
                      ip.match(/^0{0,4}(?::0{0,4}){4}:ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (dottedMatch && net.isIPv4(dottedMatch[1])) {
    return dottedMatch[1];
  }

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
 * Expand an IPv6 address to its full 8-group form.
 */
export function expandIPv6(ip: string): string {
  const noZone = ip.split('%')[0].toLowerCase();
  let halves = noZone.split('::');
  if (halves.length > 2) return '0000:0000:0000:0000:0000:0000:0000:0000';

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
 * Check if a hostname is safe to connect to (not internal/special-use).
 * @deprecated Use resolveSafeAddresses() for DNS-rebinding-resistant requests.
 */
export async function isHostSafe(hostname: string): Promise<boolean> {
  const addrs = await resolveSafeAddresses(hostname);
  return addrs.length > 0;
}

/**
 * Resolve hostname to IP addresses, returning only safe (non-internal) ones.
 * Returns an empty array if the host is unsafe or DNS fails (fail-closed).
 */
export async function resolveSafeAddresses(hostname: string): Promise<string[]> {
  if (net.isIP(hostname)) {
    return isUnsafeIP(hostname) ? [] : [hostname];
  }
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    if (addresses.some(({ address }) => isUnsafeIP(address))) {
      return [];
    }
    return addresses.map(({ address }) => address);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Pinned DNS lookup
// ---------------------------------------------------------------------------

/**
 * Build a pinned DNS lookup function that returns pre-resolved addresses.
 */
export function buildPinnedLookup(pinnedAddresses: string[]): (
  hostname: string,
  options: { family?: number } | number,
  callback: (err: Error | null, address: string, family: number) => void
) => void {
  let callIndex = 0;
  return (_hostname, options, callback) => {
    const familyHint = typeof options === 'object' ? options?.family : options;
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

// ---------------------------------------------------------------------------
// HTTP requests
// ---------------------------------------------------------------------------

/**
 * Core request logic with SSRF-safe DNS, redirect following, and loop detection.
 */
export async function httpRequestCore<T extends { statusCode: number; headers: Record<string, string | string[]> }>(
  url: string,
  opts: HttpClientOptions,
  singleFetch: (currentUrl: string, pinnedAddresses: string[]) => Promise<HttpResult<T>>,
): Promise<HttpResult<T>> {
  const maxRedirects = opts.followRedirects ? 5 : 0;
  const visited = new Set<string>();
  let currentUrl = url;
  const originalHost = new URL(url).hostname;

  let pinnedAddresses = await resolveSafeAddresses(originalHost);
  if (pinnedAddresses.length === 0) return { data: null, error: { kind: 'dns', message: `DNS resolution failed or unsafe: ${originalHost}` } };

  let lastError: HttpRequestError | undefined;

  for (let i = 0; i <= maxRedirects; i++) {
    if (visited.has(currentUrl)) return { data: null, error: lastError };
    visited.add(currentUrl);

    let result: HttpResult<T> = { data: null };
    const maxAttempts = Math.min(pinnedAddresses.length, 3);
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      result = await singleFetch(currentUrl, pinnedAddresses.slice(attempt));
      if (result.data) break;
    }
    if (!result.data) {
      lastError = result.error;
      return { data: null, error: lastError };
    }

    const response = result.data;
    const isRedirect = response.statusCode >= 300 && response.statusCode < 400;
    if (isRedirect && i < maxRedirects) {
      const location = response.headers['location'];
      const locationStr = Array.isArray(location) ? location[0] : location;
      if (locationStr) {
        const redirectUrl = new URL(locationStr, currentUrl);
        const redirectHost = redirectUrl.hostname;

        if (redirectHost !== originalHost && !opts.allowCrossHostRedirects) {
          return { data: null };
        }

        pinnedAddresses = await resolveSafeAddresses(redirectHost);
        if (pinnedAddresses.length === 0) return { data: null, error: { kind: 'dns', message: `DNS resolution failed or unsafe: ${redirectHost}` } };

        currentUrl = redirectUrl.toString();
        continue;
      }
    }

    return { data: response };
  }

  return { data: null, error: lastError };
}

export async function httpRequest(
  url: string,
  method: string,
  opts: HttpClientOptions,
): Promise<HttpResult<HttpResponse>> {
  return httpRequestCore<HttpResponse>(
    url,
    opts,
    (currentUrl, pinnedAddresses) => httpRequestSingle(currentUrl, method, opts, pinnedAddresses),
  );
}

export async function httpRequestSingle(
  url: string,
  method: string,
  opts: HttpClientOptions,
  pinnedAddresses?: string[],
): Promise<HttpResult<HttpResponse>> {
  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const lib = isHttps ? https : http;

      const requestOptions: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers: {
          'User-Agent': opts.userAgent,
          Accept: 'text/html,application/xhtml+xml,*/*',
          ...opts.headers,
        },
        timeout: opts.timeout,
        rejectUnauthorized: opts.insecureTls === false ? true : false,
      };

      if (pinnedAddresses && pinnedAddresses.length > 0) {
        requestOptions.lookup = buildPinnedLookup(pinnedAddresses) as https.RequestOptions['lookup'];
        if (isHttps && !net.isIP(parsedUrl.hostname)) {
          (requestOptions as https.RequestOptions).servername = parsedUrl.hostname;
        }
      }

      const req = lib.request(requestOptions, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
          if (body.length > 100000) {
            req.destroy();
          }
        });
        res.on('end', () => {
          resolve({
            data: {
              statusCode: res.statusCode || 0,
              headers: res.headers as Record<string, string | string[]>,
              body,
            },
          });
        });
      });

      req.on('error', (err) => resolve({ data: null, error: { kind: classifyError(err), message: err.message } }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ data: null, error: { kind: 'timeout', message: 'Request timed out' } });
      });

      req.end();
    } catch (err) {
      resolve({ data: null, error: { kind: classifyError(err), message: err instanceof Error ? err.message : String(err) } });
    }
  });
}

export async function httpRequestBinary(
  url: string,
  opts: HttpClientOptions,
): Promise<HttpResult<BinaryResult>> {
  const result = await httpRequestCore<BinaryResponse>(
    url,
    opts,
    (currentUrl, pinnedAddresses) => httpRequestBinarySingle(currentUrl, opts, pinnedAddresses),
  );
  if (!result.data) return { data: null, error: result.error };

  const contentTypeRaw = result.data.headers['content-type'];
  const contentType = (Array.isArray(contentTypeRaw) ? contentTypeRaw[0] : contentTypeRaw) || '';
  return { data: { buffer: result.data.body, statusCode: result.data.statusCode, contentType } };
}

export async function httpRequestBinarySingle(
  url: string,
  opts: HttpClientOptions,
  pinnedAddresses?: string[],
): Promise<HttpResult<BinaryResponse>> {
  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';
      const lib = isHttps ? https : http;

      const requestOptions: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        headers: {
          'User-Agent': opts.userAgent,
          Accept: '*/*',
          ...opts.headers,
        },
        timeout: opts.timeout,
        rejectUnauthorized: opts.insecureTls === false ? true : false,
      };

      if (pinnedAddresses && pinnedAddresses.length > 0) {
        requestOptions.lookup = buildPinnedLookup(pinnedAddresses) as https.RequestOptions['lookup'];
        if (isHttps && !net.isIP(parsedUrl.hostname)) {
          (requestOptions as https.RequestOptions).servername = parsedUrl.hostname;
        }
      }

      const req = lib.request(requestOptions, (res) => {
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
            data: {
              statusCode: res.statusCode || 0,
              headers: res.headers as Record<string, string | string[]>,
              body: Buffer.concat(chunks),
            },
          });
        });
      });

      req.on('error', (err) => resolve({ data: null, error: { kind: classifyError(err), message: err.message } }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ data: null, error: { kind: 'timeout', message: 'Request timed out' } });
      });

      req.end();
    } catch (err) {
      resolve({ data: null, error: { kind: classifyError(err), message: err instanceof Error ? err.message : String(err) } });
    }
  });
}

// ---------------------------------------------------------------------------
// TLS Certificate
// ---------------------------------------------------------------------------

export async function getCertificateInfo(
  url: string,
  timeout: number,
): Promise<HttpResult<string>> {
  const parsedUrl = new URL(url);
  if (parsedUrl.protocol !== 'https:') return { data: null };

  const hostname = parsedUrl.hostname;
  const port = Number(parsedUrl.port) || 443;

  const safeAddresses = await resolveSafeAddresses(hostname);
  if (safeAddresses.length === 0) return { data: null, error: { kind: 'dns', message: `DNS resolution failed or unsafe: ${hostname}` } };

  let lastError: HttpRequestError | undefined;
  for (const ip of safeAddresses) {
    const result = await getCertificateInfoSingle(ip, port, hostname, timeout);
    if (result.data !== null) return result;
    lastError = result.error;
  }

  return { data: null, error: lastError };
}

export function getCertificateInfoSingle(
  ip: string,
  port: number,
  hostname: string,
  timeout: number,
): Promise<HttpResult<string>> {
  return new Promise((resolve) => {
    try {
      const tlsOptions: tls.ConnectionOptions = {
        host: ip,
        port,
        rejectUnauthorized: false,
        timeout,
      };

      if (!net.isIP(hostname)) {
        tlsOptions.servername = hostname;
      }

      const socket = tls.connect(tlsOptions, () => {
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
          resolve({ data: info });
        } else {
          resolve({ data: null });
        }
      });

      socket.on('error', (err) => resolve({ data: null, error: { kind: classifyError(err), message: err.message } }));
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ data: null, error: { kind: 'timeout', message: `TLS connection to ${hostname} timed out` } });
      });
    } catch (err) {
      resolve({ data: null, error: { kind: classifyError(err), message: err instanceof Error ? err.message : String(err) } });
    }
  });
}
