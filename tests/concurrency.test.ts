import { VpnScanner } from '../src/scanner.js';

describe('scanMultiple concurrency', () => {
  it('returns results in input order regardless of completion order', async () => {
    const targets = ['target-0', 'target-1', 'target-2', 'target-3', 'target-4'];
    const scanner = new VpnScanner({ concurrency: 3, timeout: 1000 });

    // Mock scan to return results with varying delays
    const originalScan = scanner.scan.bind(scanner);
    const delays = [50, 10, 40, 5, 30]; // Different delays to shuffle completion order
    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => {
      const idx = targets.indexOf(target);
      await new Promise(r => setTimeout(r, delays[idx]));
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
      };
    });

    const results = await scanner.scanMultiple(targets);

    expect(results).toHaveLength(5);
    for (let i = 0; i < targets.length; i++) {
      expect(results[i].target).toBe(targets[i]);
    }
  });

  it('respects concurrency limit', async () => {
    const targets = Array.from({ length: 10 }, (_, i) => `target-${i}`);
    const scanner = new VpnScanner({ concurrency: 2, timeout: 1000 });

    let running = 0;
    let maxRunning = 0;

    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await new Promise(r => setTimeout(r, 20));
      running--;
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
      };
    });

    const results = await scanner.scanMultiple(targets);

    expect(results).toHaveLength(10);
    expect(maxRunning).toBeLessThanOrEqual(2);
  });

  it('handles empty targets array', async () => {
    const scanner = new VpnScanner({ concurrency: 5 });
    const results = await scanner.scanMultiple([]);
    expect(results).toHaveLength(0);
  });

  it('isolates errors per target', async () => {
    const scanner = new VpnScanner({ concurrency: 3, timeout: 1000 });

    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => {
      if (target === 'bad-target') {
        return {
          target,
          timestamp: new Date().toISOString(),
          vulnerabilities: [],
          errors: ['Connection refused'],
        };
      }
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
      };
    });

    const results = await scanner.scanMultiple(['good-1', 'bad-target', 'good-2']);

    expect(results[0].errors).toHaveLength(0);
    expect(results[1].errors).toHaveLength(1);
    expect(results[2].errors).toHaveLength(0);
  });
});

describe('adaptiveConcurrency (#1)', () => {
  it('reduces effective concurrency when failure rate exceeds 50%', async () => {
    // 20 targets, all fail — should trigger concurrency reduction after 5 completions
    const targets = Array.from({ length: 20 }, (_, i) => `fail-${i}`);
    const scanner = new VpnScanner({ concurrency: 4, adaptiveConcurrency: true, timeout: 1000 });

    let running = 0;
    let maxRunningAfter10 = 0;
    let completed = 0;

    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => {
      running++;
      await new Promise(r => setTimeout(r, 10));
      running--;
      completed++;
      // After 10 completions (2 evaluation windows), record max concurrency
      if (completed > 10) {
        maxRunningAfter10 = Math.max(maxRunningAfter10, running);
      }
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: ['Connection refused'],
      };
    });

    const results = await scanner.scanMultiple(targets);

    expect(results).toHaveLength(20);
    // After 100% failure rate, concurrency should have been halved at least once
    // Initial concurrency=4, after first eval (5 done, 100% fail) → 2, after second (10 done) → 1
    // So max running after 10 completions should be ≤ 2
    expect(maxRunningAfter10).toBeLessThanOrEqual(2);
  });

  it('reduces concurrency when scanErrors cause high failure rate', async () => {
    const targets = Array.from({ length: 20 }, (_, i) => `fail-${i}`);
    const scanner = new VpnScanner({ concurrency: 4, adaptiveConcurrency: true, timeout: 1000 });

    let running = 0;
    let maxRunningAfter10 = 0;
    let completed = 0;

    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => {
      running++;
      await new Promise(r => setTimeout(r, 10));
      running--;
      completed++;
      if (completed > 10) {
        maxRunningAfter10 = Math.max(maxRunningAfter10, running);
      }
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
        scanErrors: [{ kind: 'timeout' as const, message: 'request timed out' }],
      };
    });

    const results = await scanner.scanMultiple(targets);

    expect(results).toHaveLength(20);
    expect(maxRunningAfter10).toBeLessThanOrEqual(2);
  });

  it('does not reduce concurrency when failure rate is low', async () => {
    const targets = Array.from({ length: 15 }, (_, i) => `ok-${i}`);
    const scanner = new VpnScanner({ concurrency: 4, adaptiveConcurrency: true, timeout: 1000 });

    let running = 0;
    let maxRunning = 0;

    jest.spyOn(scanner, 'scan').mockImplementation(async (target: string) => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await new Promise(r => setTimeout(r, 10));
      running--;
      return {
        target,
        timestamp: new Date().toISOString(),
        vulnerabilities: [],
        errors: [],
        device: { vendor: 'fortinet' as any, product: 'FortiGate', confidence: 80, detectionMethod: ['endpoint'], endpoints: [] },
      };
    });

    await scanner.scanMultiple(targets);

    // Concurrency should stay at 4
    expect(maxRunning).toBeGreaterThanOrEqual(3); // Allow for timing variance
  });
});

describe('concurrency constructor validation (#3)', () => {
  it('defaults to 5 when concurrency is undefined', () => {
    const scanner = new VpnScanner({});
    expect((scanner as any).options.concurrency).toBe(5);
  });

  it('defaults to 5 when concurrency is 0', () => {
    const scanner = new VpnScanner({ concurrency: 0 });
    expect((scanner as any).options.concurrency).toBe(5);
  });

  it('defaults to 5 when concurrency is negative', () => {
    const scanner = new VpnScanner({ concurrency: -1 });
    expect((scanner as any).options.concurrency).toBe(5);
  });

  it('defaults to 5 when concurrency is non-integer', () => {
    const scanner = new VpnScanner({ concurrency: 1.5 });
    expect((scanner as any).options.concurrency).toBe(5);
  });

  it('clamps concurrency to 100 when exceeding limit', () => {
    const scanner = new VpnScanner({ concurrency: 200 });
    expect((scanner as any).options.concurrency).toBe(100);
  });

  it('accepts valid concurrency values', () => {
    const scanner = new VpnScanner({ concurrency: 10 });
    expect((scanner as any).options.concurrency).toBe(10);
  });

  it('accepts concurrency of 1', () => {
    const scanner = new VpnScanner({ concurrency: 1 });
    expect((scanner as any).options.concurrency).toBe(1);
  });
});
