/**
 * Performance tests for VpnVet scanner
 * Measures scan duration across different target counts, concurrency levels, and modes.
 */
import { VpnScanner } from '../src/scanner.js';
import type { ScanResult } from '../src/types.js';

// Helper: create a mock scanner that resolves after a fixed delay
function createMockScanner(opts: { concurrency?: number; fast?: boolean; delayMs?: number } = {}): VpnScanner {
  const { concurrency = 5, fast = false, delayMs = 5 } = opts;
  const scanner = new VpnScanner({ concurrency, fast, timeout: 1000 });

  jest.spyOn(scanner, 'scan').mockImplementation(async (target: string): Promise<ScanResult> => {
    await new Promise(r => setTimeout(r, delayMs));
    return {
      target,
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
    };
  });

  return scanner;
}

function makeTargets(n: number): string[] {
  return Array.from({ length: n }, (_, i) => `https://target-${i}.example.com`);
}

describe('Performance: target count scaling', () => {
  it.each([1, 10, 100])('scans %i targets with concurrency=5', async (count) => {
    const scanner = createMockScanner({ concurrency: 5, delayMs: 2 });
    const targets = makeTargets(count);

    const start = performance.now();
    const results = await scanner.scanMultiple(targets);
    const elapsed = performance.now() - start;

    expect(results).toHaveLength(count);

    // With concurrency=5, 100 targets @ 2ms each ≈ 40ms theoretical minimum
    // Allow generous headroom for CI
    const maxExpected = count <= 1 ? 500 : (count / 5) * 2 + 500;
    expect(elapsed).toBeLessThan(maxExpected);
  });
});

describe('Performance: concurrency comparison', () => {
  it.each([1, 5, 10])('concurrency=%i with 20 targets', async (concurrency) => {
    const delayMs = 10;
    const targetCount = 20;
    const scanner = createMockScanner({ concurrency, delayMs });
    const targets = makeTargets(targetCount);

    const start = performance.now();
    const results = await scanner.scanMultiple(targets);
    const elapsed = performance.now() - start;

    expect(results).toHaveLength(targetCount);

    // Theoretical minimum: ceil(targets / concurrency) * delayMs
    const theoreticalMin = Math.ceil(targetCount / concurrency) * delayMs;
    // Should be roughly proportional (with overhead tolerance)
    expect(elapsed).toBeGreaterThanOrEqual(theoreticalMin * 0.5);
    // Should not be wildly slower than expected
    expect(elapsed).toBeLessThan(theoreticalMin * 5 + 500);
  });

  it('higher concurrency is faster for many targets', async () => {
    const targets = makeTargets(30);
    const delayMs = 10;

    const scanner1 = createMockScanner({ concurrency: 1, delayMs });
    const scanner5 = createMockScanner({ concurrency: 5, delayMs });

    const start1 = performance.now();
    await scanner1.scanMultiple(targets);
    const elapsed1 = performance.now() - start1;

    const start5 = performance.now();
    await scanner5.scanMultiple(targets);
    const elapsed5 = performance.now() - start5;

    // concurrency=5 should be noticeably faster than concurrency=1
    expect(elapsed5).toBeLessThan(elapsed1 * 0.8);
  });
});

describe('Performance: fast mode vs full mode', () => {
  it('fast mode completes scan (mock comparison)', async () => {
    const targets = makeTargets(10);
    
    // Both use same mock delay so we just verify they complete correctly
    const scannerFast = createMockScanner({ fast: true, delayMs: 2 });
    const scannerFull = createMockScanner({ fast: false, delayMs: 2 });

    const startFast = performance.now();
    const resultsFast = await scannerFast.scanMultiple(targets);
    const elapsedFast = performance.now() - startFast;

    const startFull = performance.now();
    const resultsFull = await scannerFull.scanMultiple(targets);
    const elapsedFull = performance.now() - startFull;

    expect(resultsFast).toHaveLength(10);
    expect(resultsFull).toHaveLength(10);

    // Both should complete in reasonable time
    expect(elapsedFast).toBeLessThan(2000);
    expect(elapsedFull).toBeLessThan(2000);
  });
});

describe('Performance: bottleneck identification', () => {
  it('identifies relative cost of different scan phases', async () => {
    // Simulate different phase costs
    const phases = {
      dns: 5,
      certificate: 20,
      httpRequest: 10,
      httpRetry: 30,
    };

    const timings: Record<string, number> = {};

    for (const [phase, delayMs] of Object.entries(phases)) {
      const start = performance.now();
      // Simulate 10 sequential operations of this phase
      for (let i = 0; i < 10; i++) {
        await new Promise(r => setTimeout(r, delayMs));
      }
      timings[phase] = performance.now() - start;
    }

    // Verify relative ordering: httpRetry > certificate > httpRequest > dns
    expect(timings['httpRetry']).toBeGreaterThan(timings['certificate']);
    expect(timings['certificate']).toBeGreaterThan(timings['httpRequest']);
    expect(timings['httpRequest']).toBeGreaterThan(timings['dns']);

    // Log for manual analysis
    // eslint-disable-next-line no-console
    console.log('Phase timings (simulated 10x each):', timings);
  });
});
