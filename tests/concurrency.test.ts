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
