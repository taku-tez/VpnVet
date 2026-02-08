/**
 * VpnVet Scanner — Orchestration layer
 *
 * Delegates HTTP I/O to http-client.ts and detection to detector.ts.
 */

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
} from './utils.js';
import {
  isUnsafeIP,
  extractIPv4Mapped,
  expandIPv6,
  isHostSafe,
  resolveSafeAddresses,
  buildPinnedLookup,
} from './http-client.js';
import type { HttpClientOptions } from './http-client.js';
import { detectDevice } from './detector.js';
import type {
  ScanResult,
  ScanOptions,
  ScanErrorKind,
  VpnDevice,
  VulnerabilityMatch,
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
    'pattern-error': 'Pattern test error',
    'unknown': 'Unknown error',
  };
  return labels[kind];
}

/** Error kinds that represent transient failures worth retrying */
const RETRYABLE_KINDS: ReadonlySet<ScanErrorKind> = new Set([
  'timeout', 'reset', 'refused', 'dns',
]);

/** Check if a ScanResult contains only retryable (transient) errors */
function isRetryable(result: ScanResult): boolean {
  if (!result.scanErrors || result.scanErrors.length === 0) return true;
  return result.scanErrors.every(e => RETRYABLE_KINDS.has(e.kind));
}

export class VpnScanner {
  private options: Required<ScanOptions>;

  // Expose static helpers that tests or consumers may reference via VpnScanner.*
  static isUnsafeIP = isUnsafeIP;
  static extractIPv4Mapped = extractIPv4Mapped;
  static expandIPv6 = expandIPv6;
  static isHostSafe = isHostSafe;
  static resolveSafeAddresses = resolveSafeAddresses;
  static buildPinnedLookup = buildPinnedLookup;

  constructor(options: ScanOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };

    if (this.options.vendor) {
      const resolved = resolveVendor(this.options.vendor, getAllVendors());
      if (!resolved) {
        throw new Error(`Unknown vendor: "${this.options.vendor}". Known vendors: ${getAllVendors().join(', ')}`);
      }
      this.options.vendor = resolved;
    }

    const c = this.options.concurrency;
    if (c == null || !Number.isFinite(c) || !Number.isInteger(c) || c <= 0) {
      this.options.concurrency = DEFAULT_OPTIONS.concurrency;
    } else if (c > 100) {
      this.options.concurrency = 100;
    }
  }

  /** Build HttpClientOptions from scanner options */
  private get httpOpts(): HttpClientOptions {
    return {
      timeout: this.options.timeout,
      userAgent: this.options.userAgent,
      headers: this.options.headers as Record<string, string>,
      followRedirects: this.options.followRedirects,
      allowCrossHostRedirects: this.options.allowCrossHostRedirects,
    };
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

      const device = await detectDevice(baseUrl, {
        ports: this.options.ports,
        vendor: this.options.vendor,
        fast: this.options.fast,
        skipVersionDetection: this.options.skipVersionDetection,
        httpOpts: this.httpOpts,
      }, result);

      if (device) {
        result.device = device;

        if (!this.options.skipVulnCheck) {
          result.vulnerabilities = this.checkVulnerabilities(device, baseUrl);

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
              if (!a.product) return true;
              const aNorm = normalizeProduct(a.product);
              if (aNorm === deviceProductNorm) return true;
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
    let inFlight = 0;
    let doneCount = 0;
    let failureCount = 0;

    const scanWithRetry = async (target: string): Promise<ScanResult> => {
      let lastResult: ScanResult | undefined;
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        lastResult = await this.scan(target);
        const hasScanErrors = (lastResult.scanErrors?.length ?? 0) > 0;
        if (lastResult.device || (lastResult.errors.length === 0 && !hasScanErrors)) {
          return lastResult;
        }
        if (!isRetryable(lastResult)) {
          return lastResult;
        }
      }
      return lastResult!;
    };

    if (targets.length === 0) return results;

    return new Promise<ScanResult[]>((resolve) => {
      const tryDispatch = () => {
        while (inFlight < activeConcurrency && nextIndex < targets.length) {
          const i = nextIndex++;
          inFlight++;

          scanWithRetry(targets[i]).catch((err) => {
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

            if (adaptive) {
              if (result.errors.length > 0 && !result.device) {
                failureCount++;
              }
              if (doneCount % 5 === 0 && doneCount >= 5) {
                const failRate = failureCount / doneCount;
                if (failRate > 0.5 && activeConcurrency > 1) {
                  activeConcurrency = Math.max(1, Math.floor(activeConcurrency / 2));
                }
              }
            }

            if (doneCount === targets.length) {
              resolve(results);
            } else {
              tryDispatch();
            }
          });
        }
      };

      tryDispatch();
    });
  }

  private checkVulnerabilities(
    device: VpnDevice,
    _baseUrl: string,
  ): VulnerabilityMatch[] {
    const matches: VulnerabilityMatch[] = [];

    const canonicalProduct = resolveProductAlias(device.product, device.vendor);
    const canonicalProductNorm = normalizeProduct(canonicalProduct);
    const originalProductNorm = normalizeProduct(device.product);

    const resolved = resolveProductAndVendor(device.product);
    const effectiveVendor = resolved?.vendor;

    const vendorsToSearch = new Set<string>([device.vendor]);
    if (effectiveVendor && effectiveVendor !== device.vendor) {
      vendorsToSearch.add(effectiveVendor);
    }

    const productNorms = new Set([canonicalProductNorm, originalProductNorm]);

    const isProductMatch = (aProduct: string | undefined): boolean => {
      if (!aProduct) return true;
      const aNorm = normalizeProduct(aProduct);
      if (productNorms.has(aNorm)) return true;
      const aCanonical = resolveProductAlias(aProduct);
      return productNorms.has(normalizeProduct(aCanonical));
    };

    const vendorVulns = vulnerabilities.filter(v =>
      v.affected.some(a => vendorsToSearch.has(a.vendor))
    );

    for (const vuln of vendorVulns) {
      const productMatch = vuln.affected.some(
        a => vendorsToSearch.has(a.vendor) && isProductMatch(a.product)
      );

      if (productMatch) {
        let confidence: 'confirmed' | 'likely' | 'potential' = 'potential';
        let evidence = `Device detected as ${device.vendor} ${device.product}`;

        if (device.version && !this.options.skipVersionDetection) {
          const matchingAffected = vuln.affected.filter(
            a => vendorsToSearch.has(a.vendor) && isProductMatch(a.product)
          );

          const affectedWithVersion = matchingAffected.find(
            a => hasVersionConstraints(a) && isVersionAffected(device.version!, a)
          );

          const hasNoVersionEntries = matchingAffected.some(a => !hasVersionConstraints(a));

          if (affectedWithVersion) {
            confidence = 'confirmed';
            evidence = `Version ${device.version} is in affected range`;
          } else if (hasNoVersionEntries) {
            confidence = vuln.cisaKev ? 'likely' : 'potential';
            evidence += '. No version range defined for this CVE.';
            if (vuln.cisaKev) {
              evidence += ' This CVE is in CISA Known Exploited Vulnerabilities catalog.';
            }
          } else {
            continue;
          }
        } else {
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
