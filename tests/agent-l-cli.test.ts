/**
 * Agent L: CLI improvements (#1 numeric validation, #2 --targets merge, #6 SCAN_FLAGS)
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const CLI = 'npx tsx src/cli.ts';
const EXEC_OPTS = { cwd: process.cwd(), encoding: 'utf-8' as const, stdio: ['pipe', 'pipe', 'pipe'] as const };

function runCli(args: string): { status: number; stdout: string; stderr: string } {
  const result = spawnSync('npx', ['tsx', 'src/cli.ts', ...args.split(/\s+/).filter(Boolean)], {
    cwd: process.cwd(),
    encoding: 'utf-8',
    timeout: 15000,
  });
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

describe('Strict numeric validation (#1)', () => {
  describe('--timeout', () => {
    it('should reject float value like 1.5', () => {
      const r = runCli('scan example.com --timeout 1.5');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --timeout');
    });

    it('should reject trailing text like 80abc', () => {
      const r = runCli('scan example.com --timeout 80abc');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --timeout');
    });
  });

  describe('--concurrency', () => {
    it('should reject float value like 1.5', () => {
      const r = runCli('scan example.com --concurrency 1.5');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --concurrency');
    });

    it('should reject trailing text like 5abc', () => {
      const r = runCli('scan example.com --concurrency 5abc');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --concurrency');
    });

    it('should reject value over 100', () => {
      const r = runCli('scan example.com --concurrency 101');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --concurrency');
    });

    it('should reject 0', () => {
      const r = runCli('scan example.com --concurrency 0');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --concurrency');
    });
  });

  describe('--ports', () => {
    it('should reject non-numeric port like 443,abc', () => {
      const r = runCli('scan example.com --ports 443,abc');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --ports');
    });

    it('should reject empty element like 443,,80', () => {
      const r = runCli('scan example.com --ports 443,,80');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --ports');
    });

    it('should reject float port like 443.5', () => {
      const r = runCli('scan example.com --ports 443.5');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --ports');
    });

    it('should reject port 0', () => {
      const r = runCli('scan example.com --ports 0');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --ports');
    });

    it('should reject port > 65535', () => {
      const r = runCli('scan example.com --ports 70000');
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('Invalid --ports');
    });
  });
});

describe('--targets merge with positional args (#2)', () => {
  let tmpDir: string;
  let targetsFile: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vpnvet-test-'));
    targetsFile = path.join(tmpDir, 'targets.txt');
    fs.writeFileSync(targetsFile, 'file-target1.example.com\nfile-target2.example.com\n');
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should merge positional args and --targets file (not overwrite)', () => {
    // Run with positional + file targets, with a very short timeout so it finishes fast
    const r = runCli(`scan positional.example.com --targets ${targetsFile} --timeout 1000`);
    // It should attempt to scan all 3 targets (may fail on network, but check output includes all)
    const combined = r.stdout + r.stderr;
    // Should see all 3 targets mentioned
    expect(combined).toContain('[3/3]');
  });

  it('should deduplicate targets', () => {
    const dupeFile = path.join(tmpDir, 'dupes.txt');
    fs.writeFileSync(dupeFile, 'dup.example.com\ndup.example.com\n');
    const r = runCli(`scan dup.example.com --targets ${dupeFile} --timeout 1000`);
    const combined = r.stdout + r.stderr;
    expect(combined).toContain('[1/1]');
    expect(combined).not.toContain('[2/');
  });
});

describe('SCAN_FLAGS integration - unknown flag detection (#6)', () => {
  it('should reject --unknown-flag', () => {
    const r = runCli('scan example.com --unknown-flag');
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Unknown option');
  });

  it('should reject -x shorthand', () => {
    const r = runCli('scan example.com -x');
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Unknown option');
  });

  it('should reject --timout typo', () => {
    const r = runCli('scan example.com --timout 5000');
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Unknown option');
  });
});
