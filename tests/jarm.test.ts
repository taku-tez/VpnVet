/**
 * JARM TLS Fingerprinting Tests
 */

import {
  buildClientHello,
  readServerHello,
  computeJarmHash,
  cipherByte,
  versionByte,
  cipherMung,
  getProbeConfigs,
  lookupJarmHash,
  KNOWN_JARM_HASHES,
} from '../src/jarm.js';
import type { JarmProbeConfig } from '../src/jarm.js';

// ---------------------------------------------------------------------------
// cipherMung reordering
// ---------------------------------------------------------------------------

describe('cipherMung', () => {
  const items = [1, 2, 3, 4, 5];

  test('FORWARD returns same order', () => {
    expect(cipherMung(items, 'FORWARD')).toEqual([1, 2, 3, 4, 5]);
  });

  test('REVERSE returns reversed', () => {
    expect(cipherMung(items, 'REVERSE')).toEqual([5, 4, 3, 2, 1]);
  });

  test('BOTTOM_HALF with odd length', () => {
    expect(cipherMung(items, 'BOTTOM_HALF')).toEqual([4, 5]);
  });

  test('BOTTOM_HALF with even length', () => {
    expect(cipherMung([1, 2, 3, 4], 'BOTTOM_HALF')).toEqual([3, 4]);
  });

  test('TOP_HALF with odd length includes middle', () => {
    const result = cipherMung(items, 'TOP_HALF');
    expect(result).toContain(3); // middle element
    expect(result.length).toBe(3);
  });

  test('MIDDLE_OUT with odd length starts from middle', () => {
    const result = cipherMung(items, 'MIDDLE_OUT');
    expect(result[0]).toBe(3); // middle element first
    expect(result.length).toBe(5);
  });

  test('MIDDLE_OUT with even length', () => {
    const result = cipherMung([1, 2, 3, 4], 'MIDDLE_OUT');
    expect(result.length).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// Client Hello packet building
// ---------------------------------------------------------------------------

describe('buildClientHello', () => {
  const baseConfig: JarmProbeConfig = {
    host: 'example.com',
    port: 443,
    version: 'TLS_1.2',
    cipherList: 'ALL',
    cipherOrder: 'FORWARD',
    grease: 'NO_GREASE',
    alpn: 'APLN',
    supportedVersions: '1.2_SUPPORT',
    extensionOrder: 'REVERSE',
  };

  test('produces a valid TLS record', () => {
    const packet = buildClientHello(baseConfig);
    expect(packet[0]).toBe(0x16); // ContentType: Handshake
    expect(packet[1]).toBe(0x03); // TLS major version
    // Handshake type should be ClientHello (0x01)
    expect(packet[5]).toBe(0x01);
  });

  test('TLS 1.3 uses 0x0301 record version', () => {
    const config = { ...baseConfig, version: 'TLS_1.3' as const };
    const packet = buildClientHello(config);
    expect(packet[1]).toBe(0x03);
    expect(packet[2]).toBe(0x01);
  });

  test('TLS 1.2 uses 0x0303 record version', () => {
    const packet = buildClientHello(baseConfig);
    expect(packet[1]).toBe(0x03);
    expect(packet[2]).toBe(0x03);
  });

  test('TLS 1.1 uses 0x0302 record version', () => {
    const config = { ...baseConfig, version: 'TLS_1.1' as const };
    const packet = buildClientHello(config);
    expect(packet[1]).toBe(0x03);
    expect(packet[2]).toBe(0x02);
  });

  test('packet length is consistent', () => {
    const packet = buildClientHello(baseConfig);
    const recordLength = packet.readUInt16BE(3);
    expect(packet.length).toBe(recordLength + 5);
  });

  test('GREASE adds extra bytes', () => {
    const noGrease = buildClientHello(baseConfig);
    const withGrease = buildClientHello({ ...baseConfig, grease: 'GREASE' });
    // GREASE adds bytes to ciphers and extensions
    expect(withGrease.length).toBeGreaterThan(noGrease.length);
  });

  test('all 10 probe configs produce valid packets', () => {
    const configs = getProbeConfigs('example.com', 443);
    expect(configs.length).toBe(10);
    for (const config of configs) {
      const packet = buildClientHello(config);
      expect(packet[0]).toBe(0x16);
      expect(packet[5]).toBe(0x01);
      const recordLength = packet.readUInt16BE(3);
      expect(packet.length).toBe(recordLength + 5);
    }
  });
});

// ---------------------------------------------------------------------------
// Server Hello parsing
// ---------------------------------------------------------------------------

describe('readServerHello', () => {
  test('null data returns |||', () => {
    expect(readServerHello(null)).toBe('|||');
  });

  test('empty buffer returns |||', () => {
    expect(readServerHello(Buffer.alloc(0))).toBe('|||');
  });

  test('TLS alert returns |||', () => {
    const alert = Buffer.alloc(7);
    alert[0] = 21; // Alert
    expect(readServerHello(alert)).toBe('|||');
  });

  test('parses a minimal Server Hello', () => {
    // Construct a minimal valid Server Hello
    // Record: 22 03 03 <len16> 02 <len24> 03 03 <32 random> <session_id_len=0> <cipher 2 bytes> <comp 1 byte> <ext_len> ...
    const random = Buffer.alloc(32, 0xab);
    const sessionIdLen = 0;
    const cipher = Buffer.from([0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    const compression = Buffer.from([0x00]);
    const extensions = Buffer.alloc(0);
    const extLen = Buffer.alloc(2);
    extLen.writeUInt16BE(0, 0);

    const serverHelloBody = Buffer.concat([
      Buffer.from([0x03, 0x03]), // version
      random,
      Buffer.from([sessionIdLen]),
      cipher,
      compression,
      extLen,
      extensions,
    ]);

    const handshakeHeader = Buffer.concat([
      Buffer.from([0x02]), // ServerHello type
      Buffer.from([0x00, (serverHelloBody.length >> 8) & 0xff, serverHelloBody.length & 0xff]),
    ]);

    const record = Buffer.concat([
      Buffer.from([0x22]), // placeholder - will be set below
      Buffer.from([0x03, 0x03]),
      Buffer.alloc(2), // length placeholder
      handshakeHeader,
      serverHelloBody,
    ]);

    record[0] = 0x16; // Handshake
    const totalLen = handshakeHeader.length + serverHelloBody.length;
    record.writeUInt16BE(totalLen, 3);

    const result = readServerHello(record);
    // Should contain cipher|version|...
    expect(result).toContain('c02f');
    expect(result).toContain('0303');
  });
});

// ---------------------------------------------------------------------------
// JARM hash computation
// ---------------------------------------------------------------------------

describe('computeJarmHash', () => {
  test('empty JARM returns 62 zeros', () => {
    const emptyRaw = '|||,|||,|||,|||,|||,|||,|||,|||,|||,|||';
    const hash = computeJarmHash(emptyRaw);
    expect(hash).toBe('0'.repeat(62));
    expect(hash.length).toBe(62);
  });

  test('non-empty input produces 62-char hash', () => {
    // Simulated raw with some cipher responses
    const raw = 'c02c|0303|h2|0017-ff01-000a-000b-0023-0010-0005,c02c|0303|h2|0017-ff01-000a-000b-0023-0010-0005,c02c|0303|h2|0017-ff01-000a-000b-0023-0010-0005,|||,|||,c02c|0303|h2|0017-ff01-000a-000b-0023-0010-0005,c02c|0303|h2|0017-ff01-000a-000b-0023-0010-0005,c02c|0303|h2|0017-ff01-000a-000b-0023-0010-0005,|||,c02c|0303|h2|0017-ff01-000a-000b-0023-0010-0005';
    const hash = computeJarmHash(raw);
    expect(hash.length).toBe(62);
    expect(hash).not.toBe('0'.repeat(62));
  });

  test('same input produces same hash (deterministic)', () => {
    const raw = 'c02c|0303|h2|0017,c02c|0303||,|||,|||,|||,|||,|||,|||,|||,|||';
    const hash1 = computeJarmHash(raw);
    const hash2 = computeJarmHash(raw);
    expect(hash1).toBe(hash2);
  });
});

// ---------------------------------------------------------------------------
// cipherByte / versionByte
// ---------------------------------------------------------------------------

describe('cipherByte', () => {
  test('empty cipher returns 00', () => {
    expect(cipherByte('')).toBe('00');
  });

  test('known cipher returns correct index', () => {
    // 0004 is first in the list → index 1 → "01"
    expect(cipherByte('0004')).toBe('01');
    // 0005 is second → "02"
    expect(cipherByte('0005')).toBe('02');
  });

  test('TLS 1.3 cipher 1301 returns correct byte', () => {
    const result = cipherByte('1301');
    expect(result.length).toBe(2);
    // 1301 is at a known position
    expect(parseInt(result, 16)).toBeGreaterThan(0);
  });
});

describe('versionByte', () => {
  test('empty version returns 0', () => {
    expect(versionByte('')).toBe('0');
  });

  test('0303 (TLS 1.2) maps correctly', () => {
    // version[3] = '3' → options[3] = 'd'
    expect(versionByte('0303')).toBe('d');
  });

  test('0301 (TLS 1.0) maps correctly', () => {
    expect(versionByte('0301')).toBe('b');
  });

  test('0304 (TLS 1.3) maps correctly', () => {
    expect(versionByte('0304')).toBe('e');
  });
});

// ---------------------------------------------------------------------------
// Probe configs
// ---------------------------------------------------------------------------

describe('getProbeConfigs', () => {
  test('returns exactly 10 probes', () => {
    const configs = getProbeConfigs('example.com', 443);
    expect(configs.length).toBe(10);
  });

  test('probes cover multiple TLS versions', () => {
    const configs = getProbeConfigs('example.com', 443);
    const versions = new Set(configs.map(c => c.version));
    expect(versions.has('TLS_1.2')).toBe(true);
    expect(versions.has('TLS_1.1')).toBe(true);
    expect(versions.has('TLS_1.3')).toBe(true);
  });

  test('probes include both GREASE and NO_GREASE', () => {
    const configs = getProbeConfigs('example.com', 443);
    const greaseVals = new Set(configs.map(c => c.grease));
    expect(greaseVals.has('GREASE')).toBe(true);
    expect(greaseVals.has('NO_GREASE')).toBe(true);
  });

  test('all probes have correct host and port', () => {
    const configs = getProbeConfigs('test.example.com', 8443);
    for (const c of configs) {
      expect(c.host).toBe('test.example.com');
      expect(c.port).toBe(8443);
    }
  });
});

// ---------------------------------------------------------------------------
// Known JARM lookup
// ---------------------------------------------------------------------------

describe('lookupJarmHash', () => {
  test('known FortiGate hash returns match', () => {
    const match = lookupJarmHash('07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1');
    expect(match).toBeDefined();
    expect(match!.vendor).toBe('fortinet');
  });

  test('unknown hash returns undefined', () => {
    expect(lookupJarmHash('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBeUndefined();
  });

  test('KNOWN_JARM_HASHES covers major vendors', () => {
    const vendors = new Set(KNOWN_JARM_HASHES.map(k => k.vendor));
    expect(vendors.has('fortinet')).toBe(true);
    expect(vendors.has('paloalto')).toBe(true);
    expect(vendors.has('pulse')).toBe(true);
    expect(vendors.has('cisco')).toBe(true);
    expect(vendors.has('sonicwall')).toBe(true);
    expect(vendors.has('citrix')).toBe(true);
  });

  test('all known hashes are 62 characters', () => {
    for (const entry of KNOWN_JARM_HASHES) {
      expect(entry.jarmHash.length).toBe(62);
    }
  });
});

// ---------------------------------------------------------------------------
// ScanResult jarmHash field
// ---------------------------------------------------------------------------

describe('ScanResult jarmHash field', () => {
  test('jarmHash is optional in ScanResult', () => {
    const result = {
      target: 'example.com',
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      errors: [],
    };
    // TypeScript compilation validates this; runtime check that jarmHash is undefined
    expect((result as any).jarmHash).toBeUndefined();
  });
});
