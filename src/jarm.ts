/**
 * JARM - Active TLS Fingerprinting
 *
 * TypeScript implementation based on the Salesforce JARM specification.
 * https://github.com/salesforce/jarm
 *
 * Sends 10 different TLS Client Hello probes and generates a fingerprint
 * hash from the Server Hello responses.
 */

import * as net from 'node:net';
import * as crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CipherList = 'ALL' | 'NO1.3';
export type CipherOrder = 'FORWARD' | 'REVERSE' | 'BOTTOM_HALF' | 'TOP_HALF' | 'MIDDLE_OUT';
export type GreaseMode = 'GREASE' | 'NO_GREASE';
export type AlpnMode = 'APLN' | 'RARE_APLN';
export type SupportedVersionMode = '1.2_SUPPORT' | '1.3_SUPPORT' | 'NO_SUPPORT';
export type TlsVersion = 'SSLv3' | 'TLS_1' | 'TLS_1.1' | 'TLS_1.2' | 'TLS_1.3';

export interface JarmProbeConfig {
  host: string;
  port: number;
  version: TlsVersion;
  cipherList: CipherList;
  cipherOrder: CipherOrder;
  grease: GreaseMode;
  alpn: AlpnMode;
  supportedVersions: SupportedVersionMode;
  extensionOrder: CipherOrder;
}

export interface JarmResult {
  hash: string;
  raw?: string; // Pre-hash raw responses (verbose mode)
  error?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GREASE_VALUES: Buffer[] = [
  Buffer.from([0x0a, 0x0a]), Buffer.from([0x1a, 0x1a]), Buffer.from([0x2a, 0x2a]),
  Buffer.from([0x3a, 0x3a]), Buffer.from([0x4a, 0x4a]), Buffer.from([0x5a, 0x5a]),
  Buffer.from([0x6a, 0x6a]), Buffer.from([0x7a, 0x7a]), Buffer.from([0x8a, 0x8a]),
  Buffer.from([0x9a, 0x9a]), Buffer.from([0xaa, 0xaa]), Buffer.from([0xba, 0xba]),
  Buffer.from([0xca, 0xca]), Buffer.from([0xda, 0xda]), Buffer.from([0xea, 0xea]),
  Buffer.from([0xfa, 0xfa]),
];

// Cipher suites for ALL list (includes TLS 1.3)
const CIPHERS_ALL: Buffer[] = [
  Buffer.from([0x00, 0x16]), Buffer.from([0x00, 0x33]), Buffer.from([0x00, 0x67]),
  Buffer.from([0xc0, 0x9e]), Buffer.from([0xc0, 0xa2]), Buffer.from([0x00, 0x9e]),
  Buffer.from([0x00, 0x39]), Buffer.from([0x00, 0x6b]), Buffer.from([0xc0, 0x9f]),
  Buffer.from([0xc0, 0xa3]), Buffer.from([0x00, 0x9f]), Buffer.from([0x00, 0x45]),
  Buffer.from([0x00, 0xbe]), Buffer.from([0x00, 0x88]), Buffer.from([0x00, 0xc4]),
  Buffer.from([0x00, 0x9a]), Buffer.from([0xc0, 0x08]), Buffer.from([0xc0, 0x09]),
  Buffer.from([0xc0, 0x23]), Buffer.from([0xc0, 0xac]), Buffer.from([0xc0, 0xae]),
  Buffer.from([0xc0, 0x2b]), Buffer.from([0xc0, 0x0a]), Buffer.from([0xc0, 0x24]),
  Buffer.from([0xc0, 0xad]), Buffer.from([0xc0, 0xaf]), Buffer.from([0xc0, 0x2c]),
  Buffer.from([0xc0, 0x72]), Buffer.from([0xc0, 0x73]), Buffer.from([0xcc, 0xa9]),
  Buffer.from([0x13, 0x02]), Buffer.from([0x13, 0x01]), Buffer.from([0xcc, 0x14]),
  Buffer.from([0xc0, 0x07]), Buffer.from([0xc0, 0x12]), Buffer.from([0xc0, 0x13]),
  Buffer.from([0xc0, 0x27]), Buffer.from([0xc0, 0x2f]), Buffer.from([0xc0, 0x14]),
  Buffer.from([0xc0, 0x28]), Buffer.from([0xc0, 0x30]), Buffer.from([0xc0, 0x60]),
  Buffer.from([0xc0, 0x61]), Buffer.from([0xc0, 0x76]), Buffer.from([0xc0, 0x77]),
  Buffer.from([0xcc, 0xa8]), Buffer.from([0x13, 0x05]), Buffer.from([0x13, 0x04]),
  Buffer.from([0x13, 0x03]), Buffer.from([0xcc, 0x13]), Buffer.from([0xc0, 0x11]),
  Buffer.from([0x00, 0x0a]), Buffer.from([0x00, 0x2f]), Buffer.from([0x00, 0x3c]),
  Buffer.from([0xc0, 0x9c]), Buffer.from([0xc0, 0xa0]), Buffer.from([0x00, 0x9c]),
  Buffer.from([0x00, 0x35]), Buffer.from([0x00, 0x3d]), Buffer.from([0xc0, 0x9d]),
  Buffer.from([0xc0, 0xa1]), Buffer.from([0x00, 0x9d]), Buffer.from([0x00, 0x41]),
  Buffer.from([0x00, 0xba]), Buffer.from([0x00, 0x84]), Buffer.from([0x00, 0xc0]),
  Buffer.from([0x00, 0x07]), Buffer.from([0x00, 0x04]), Buffer.from([0x00, 0x05]),
];

// Cipher suites for NO1.3 list (excludes TLS 1.3 ciphers)
const CIPHERS_NO13: Buffer[] = [
  Buffer.from([0x00, 0x16]), Buffer.from([0x00, 0x33]), Buffer.from([0x00, 0x67]),
  Buffer.from([0xc0, 0x9e]), Buffer.from([0xc0, 0xa2]), Buffer.from([0x00, 0x9e]),
  Buffer.from([0x00, 0x39]), Buffer.from([0x00, 0x6b]), Buffer.from([0xc0, 0x9f]),
  Buffer.from([0xc0, 0xa3]), Buffer.from([0x00, 0x9f]), Buffer.from([0x00, 0x45]),
  Buffer.from([0x00, 0xbe]), Buffer.from([0x00, 0x88]), Buffer.from([0x00, 0xc4]),
  Buffer.from([0x00, 0x9a]), Buffer.from([0xc0, 0x08]), Buffer.from([0xc0, 0x09]),
  Buffer.from([0xc0, 0x23]), Buffer.from([0xc0, 0xac]), Buffer.from([0xc0, 0xae]),
  Buffer.from([0xc0, 0x2b]), Buffer.from([0xc0, 0x0a]), Buffer.from([0xc0, 0x24]),
  Buffer.from([0xc0, 0xad]), Buffer.from([0xc0, 0xaf]), Buffer.from([0xc0, 0x2c]),
  Buffer.from([0xc0, 0x72]), Buffer.from([0xc0, 0x73]), Buffer.from([0xcc, 0xa9]),
  Buffer.from([0xcc, 0x14]), Buffer.from([0xc0, 0x07]), Buffer.from([0xc0, 0x12]),
  Buffer.from([0xc0, 0x13]), Buffer.from([0xc0, 0x27]), Buffer.from([0xc0, 0x2f]),
  Buffer.from([0xc0, 0x14]), Buffer.from([0xc0, 0x28]), Buffer.from([0xc0, 0x30]),
  Buffer.from([0xc0, 0x60]), Buffer.from([0xc0, 0x61]), Buffer.from([0xc0, 0x76]),
  Buffer.from([0xc0, 0x77]), Buffer.from([0xcc, 0xa8]), Buffer.from([0xcc, 0x13]),
  Buffer.from([0xc0, 0x11]), Buffer.from([0x00, 0x0a]), Buffer.from([0x00, 0x2f]),
  Buffer.from([0x00, 0x3c]), Buffer.from([0xc0, 0x9c]), Buffer.from([0xc0, 0xa0]),
  Buffer.from([0x00, 0x9c]), Buffer.from([0x00, 0x35]), Buffer.from([0x00, 0x3d]),
  Buffer.from([0xc0, 0x9d]), Buffer.from([0xc0, 0xa1]), Buffer.from([0x00, 0x9d]),
  Buffer.from([0x00, 0x41]), Buffer.from([0x00, 0xba]), Buffer.from([0x00, 0x84]),
  Buffer.from([0x00, 0xc0]), Buffer.from([0x00, 0x07]), Buffer.from([0x00, 0x04]),
  Buffer.from([0x00, 0x05]),
];

// Cipher lookup table for fuzzy hash (same order as Python reference)
const CIPHER_HASH_LIST: Buffer[] = [
  Buffer.from([0x00, 0x04]), Buffer.from([0x00, 0x05]), Buffer.from([0x00, 0x07]),
  Buffer.from([0x00, 0x0a]), Buffer.from([0x00, 0x16]), Buffer.from([0x00, 0x2f]),
  Buffer.from([0x00, 0x33]), Buffer.from([0x00, 0x35]), Buffer.from([0x00, 0x39]),
  Buffer.from([0x00, 0x3c]), Buffer.from([0x00, 0x3d]), Buffer.from([0x00, 0x41]),
  Buffer.from([0x00, 0x45]), Buffer.from([0x00, 0x67]), Buffer.from([0x00, 0x6b]),
  Buffer.from([0x00, 0x84]), Buffer.from([0x00, 0x88]), Buffer.from([0x00, 0x9a]),
  Buffer.from([0x00, 0x9c]), Buffer.from([0x00, 0x9d]), Buffer.from([0x00, 0x9e]),
  Buffer.from([0x00, 0x9f]), Buffer.from([0x00, 0xba]), Buffer.from([0x00, 0xbe]),
  Buffer.from([0x00, 0xc0]), Buffer.from([0x00, 0xc4]), Buffer.from([0xc0, 0x07]),
  Buffer.from([0xc0, 0x08]), Buffer.from([0xc0, 0x09]), Buffer.from([0xc0, 0x0a]),
  Buffer.from([0xc0, 0x11]), Buffer.from([0xc0, 0x12]), Buffer.from([0xc0, 0x13]),
  Buffer.from([0xc0, 0x14]), Buffer.from([0xc0, 0x23]), Buffer.from([0xc0, 0x24]),
  Buffer.from([0xc0, 0x27]), Buffer.from([0xc0, 0x28]), Buffer.from([0xc0, 0x2b]),
  Buffer.from([0xc0, 0x2c]), Buffer.from([0xc0, 0x2f]), Buffer.from([0xc0, 0x30]),
  Buffer.from([0xc0, 0x60]), Buffer.from([0xc0, 0x61]), Buffer.from([0xc0, 0x72]),
  Buffer.from([0xc0, 0x73]), Buffer.from([0xc0, 0x76]), Buffer.from([0xc0, 0x77]),
  Buffer.from([0xc0, 0x9c]), Buffer.from([0xc0, 0x9d]), Buffer.from([0xc0, 0x9e]),
  Buffer.from([0xc0, 0x9f]), Buffer.from([0xc0, 0xa0]), Buffer.from([0xc0, 0xa1]),
  Buffer.from([0xc0, 0xa2]), Buffer.from([0xc0, 0xa3]), Buffer.from([0xc0, 0xac]),
  Buffer.from([0xc0, 0xad]), Buffer.from([0xc0, 0xae]), Buffer.from([0xc0, 0xaf]),
  Buffer.from([0xcc, 0x13]), Buffer.from([0xcc, 0x14]), Buffer.from([0xcc, 0xa8]),
  Buffer.from([0xcc, 0xa9]), Buffer.from([0x13, 0x01]), Buffer.from([0x13, 0x02]),
  Buffer.from([0x13, 0x03]), Buffer.from([0x13, 0x04]), Buffer.from([0x13, 0x05]),
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function chooseGrease(): Buffer {
  return GREASE_VALUES[Math.floor(Math.random() * GREASE_VALUES.length)];
}

/** Reorder array elements (same logic as Python cipher_mung) */
export function cipherMung<T>(ciphers: T[], order: CipherOrder): T[] {
  if (order === 'FORWARD') return [...ciphers];
  if (order === 'REVERSE') return [...ciphers].reverse();

  const len = ciphers.length;
  if (order === 'BOTTOM_HALF') {
    if (len % 2 === 1) {
      return ciphers.slice(Math.floor(len / 2) + 1);
    }
    return ciphers.slice(Math.floor(len / 2));
  }
  if (order === 'TOP_HALF') {
    const output: T[] = [];
    if (len % 2 === 1) {
      output.push(ciphers[Math.floor(len / 2)]);
    }
    output.push(...cipherMung(cipherMung(ciphers, 'REVERSE'), 'BOTTOM_HALF'));
    return output;
  }
  if (order === 'MIDDLE_OUT') {
    const middle = Math.floor(len / 2);
    const output: T[] = [];
    if (len % 2 === 1) {
      output.push(ciphers[middle]);
      for (let i = 1; i <= middle; i++) {
        output.push(ciphers[middle + i]);
        output.push(ciphers[middle - i]);
      }
    } else {
      for (let i = 1; i <= middle; i++) {
        output.push(ciphers[middle - 1 + i]);
        output.push(ciphers[middle - i]);
      }
    }
    return output;
  }
  return [...ciphers];
}

// ---------------------------------------------------------------------------
// Packet Building
// ---------------------------------------------------------------------------

function extensionServerName(host: string): Buffer {
  const hostBuf = Buffer.from(host, 'ascii');
  const buf = Buffer.alloc(9 + hostBuf.length);
  buf.writeUInt16BE(0x0000, 0); // extension type: server_name
  buf.writeUInt16BE(hostBuf.length + 5, 2); // extension length
  buf.writeUInt16BE(hostBuf.length + 3, 4); // server name list length
  buf[6] = 0x00; // host name type
  buf.writeUInt16BE(hostBuf.length, 7); // host name length
  hostBuf.copy(buf, 9);
  return buf;
}

function appLayerProtoNegotiation(config: JarmProbeConfig): Buffer {
  let alpns: Buffer[];
  if (config.alpn === 'RARE_APLN') {
    alpns = [
      Buffer.from([0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39]), // http/0.9
      Buffer.from([0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30]), // http/1.0
      Buffer.from([0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31]),             // spdy/1
      Buffer.from([0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32]),             // spdy/2
      Buffer.from([0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33]),             // spdy/3
      Buffer.from([0x03, 0x68, 0x32, 0x63]),                               // h2c
      Buffer.from([0x02, 0x68, 0x71]),                                     // hq
    ];
  } else {
    alpns = [
      Buffer.from([0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39]), // http/0.9
      Buffer.from([0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30]), // http/1.0
      Buffer.from([0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]), // http/1.1
      Buffer.from([0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x31]),             // spdy/1
      Buffer.from([0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x32]),             // spdy/2
      Buffer.from([0x06, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33]),             // spdy/3
      Buffer.from([0x02, 0x68, 0x32]),                                     // h2
      Buffer.from([0x03, 0x68, 0x32, 0x63]),                               // h2c
      Buffer.from([0x02, 0x68, 0x71]),                                     // hq
    ];
  }

  if (config.extensionOrder !== 'FORWARD') {
    alpns = cipherMung(alpns, config.extensionOrder);
  }

  const allAlpns = Buffer.concat(alpns);
  const buf = Buffer.alloc(6 + allAlpns.length);
  buf.writeUInt16BE(0x0010, 0); // extension type: ALPN
  buf.writeUInt16BE(allAlpns.length + 2, 2);
  buf.writeUInt16BE(allAlpns.length, 4);
  allAlpns.copy(buf, 6);
  return buf;
}

function keyShareExtension(grease: boolean): Buffer {
  let shareExt: Buffer;
  if (grease) {
    const g = chooseGrease();
    shareExt = Buffer.concat([g, Buffer.from([0x00, 0x01, 0x00])]);
  } else {
    shareExt = Buffer.alloc(0);
  }

  const group = Buffer.from([0x00, 0x1d]); // x25519
  const keyExchangeLen = Buffer.from([0x00, 0x20]);
  const keyData = crypto.randomBytes(32);
  shareExt = Buffer.concat([shareExt, group, keyExchangeLen, keyData]);

  const buf = Buffer.alloc(6 + shareExt.length);
  buf.writeUInt16BE(0x0033, 0); // extension type: key_share
  buf.writeUInt16BE(shareExt.length + 2, 2);
  buf.writeUInt16BE(shareExt.length, 4);
  shareExt.copy(buf, 6);
  return buf;
}

function supportedVersionsExtension(config: JarmProbeConfig, grease: boolean): Buffer {
  let tls: Buffer[];
  if (config.supportedVersions === '1.2_SUPPORT') {
    tls = [Buffer.from([0x03, 0x01]), Buffer.from([0x03, 0x02]), Buffer.from([0x03, 0x03])];
  } else {
    tls = [Buffer.from([0x03, 0x01]), Buffer.from([0x03, 0x02]), Buffer.from([0x03, 0x03]), Buffer.from([0x03, 0x04])];
  }

  if (config.extensionOrder !== 'FORWARD') {
    tls = cipherMung(tls, config.extensionOrder);
  }

  let versions: Buffer;
  if (grease) {
    versions = Buffer.concat([chooseGrease(), ...tls]);
  } else {
    versions = Buffer.concat(tls);
  }

  const buf = Buffer.alloc(5 + versions.length);
  buf.writeUInt16BE(0x002b, 0); // extension type: supported_versions
  buf.writeUInt16BE(versions.length + 1, 2);
  buf[4] = versions.length;
  versions.copy(buf, 5);
  return buf;
}

function getExtensions(config: JarmProbeConfig): Buffer {
  const parts: Buffer[] = [];
  let grease = false;

  // GREASE extension
  if (config.grease === 'GREASE') {
    const g = chooseGrease();
    parts.push(Buffer.concat([g, Buffer.from([0x00, 0x00])]));
    grease = true;
  }

  // Server name
  parts.push(extensionServerName(config.host));

  // Extended master secret
  parts.push(Buffer.from([0x00, 0x17, 0x00, 0x00]));

  // Max fragment length
  parts.push(Buffer.from([0x00, 0x01, 0x00, 0x01, 0x01]));

  // Renegotiation info
  parts.push(Buffer.from([0xff, 0x01, 0x00, 0x01, 0x00]));

  // Supported groups
  parts.push(Buffer.from([0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19]));

  // EC point formats
  parts.push(Buffer.from([0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]));

  // Session ticket
  parts.push(Buffer.from([0x00, 0x23, 0x00, 0x00]));

  // ALPN
  parts.push(appLayerProtoNegotiation(config));

  // Signature algorithms
  parts.push(Buffer.from([
    0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04,
    0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06,
    0x06, 0x01, 0x02, 0x01,
  ]));

  // Key share
  parts.push(keyShareExtension(grease));

  // PSK key exchange modes
  parts.push(Buffer.from([0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]));

  // Supported versions (conditional)
  if (config.version === 'TLS_1.3' || config.supportedVersions === '1.2_SUPPORT') {
    parts.push(supportedVersionsExtension(config, grease));
  }

  const allExtensions = Buffer.concat(parts);
  const extLenBuf = Buffer.alloc(2);
  extLenBuf.writeUInt16BE(allExtensions.length, 0);
  return Buffer.concat([extLenBuf, allExtensions]);
}

function getCiphers(config: JarmProbeConfig): Buffer {
  let list = config.cipherList === 'ALL' ? [...CIPHERS_ALL] : [...CIPHERS_NO13];

  if (config.cipherOrder !== 'FORWARD') {
    list = cipherMung(list, config.cipherOrder);
  }

  if (config.grease === 'GREASE') {
    list.unshift(chooseGrease());
  }

  return Buffer.concat(list);
}

export function buildClientHello(config: JarmProbeConfig): Buffer {
  // Record layer header
  let payload = Buffer.from([0x16]); // ContentType: Handshake

  // Record version
  let recordVersion: Buffer;
  if (config.version === 'TLS_1.3') {
    recordVersion = Buffer.from([0x03, 0x01]);
  } else if (config.version === 'SSLv3') {
    recordVersion = Buffer.from([0x03, 0x00]);
  } else if (config.version === 'TLS_1') {
    recordVersion = Buffer.from([0x03, 0x01]);
  } else if (config.version === 'TLS_1.1') {
    recordVersion = Buffer.from([0x03, 0x02]);
  } else {
    recordVersion = Buffer.from([0x03, 0x03]); // TLS 1.2
  }

  // Client hello version
  let clientHelloVersion: Buffer;
  if (config.version === 'TLS_1.3') {
    clientHelloVersion = Buffer.from([0x03, 0x03]);
  } else if (config.version === 'SSLv3') {
    clientHelloVersion = Buffer.from([0x03, 0x00]);
  } else if (config.version === 'TLS_1') {
    clientHelloVersion = Buffer.from([0x03, 0x01]);
  } else if (config.version === 'TLS_1.1') {
    clientHelloVersion = Buffer.from([0x03, 0x02]);
  } else {
    clientHelloVersion = Buffer.from([0x03, 0x03]);
  }

  // Random
  const random = crypto.randomBytes(32);

  // Session ID
  const sessionId = crypto.randomBytes(32);
  const sessionIdLength = Buffer.from([sessionId.length]);

  // Ciphers
  const cipherChoice = getCiphers(config);
  const cipherLength = Buffer.alloc(2);
  cipherLength.writeUInt16BE(cipherChoice.length, 0);

  // Compression methods
  const compressionMethods = Buffer.from([0x01, 0x00]);

  // Extensions
  const extensions = getExtensions(config);

  // Assemble client hello
  const clientHello = Buffer.concat([
    clientHelloVersion, random, sessionIdLength, sessionId,
    cipherLength, cipherChoice, compressionMethods, extensions,
  ]);

  // Handshake header
  const innerLength = Buffer.alloc(3);
  innerLength.writeUInt8(0x00, 0);
  innerLength.writeUInt16BE(clientHello.length, 1);
  const handshakeProtocol = Buffer.concat([Buffer.from([0x01]), innerLength, clientHello]);

  // Record layer length
  const outerLength = Buffer.alloc(2);
  outerLength.writeUInt16BE(handshakeProtocol.length, 0);

  payload = Buffer.concat([payload, recordVersion, outerLength, handshakeProtocol]);
  return payload;
}

// ---------------------------------------------------------------------------
// Packet Reading
// ---------------------------------------------------------------------------

export function readServerHello(data: Buffer | null): string {
  if (!data || data.length === 0) return '|||';

  try {
    // Alert
    if (data[0] === 21) return '|||';

    // Server Hello
    if (data[0] === 22 && data.length > 5 && data[5] === 2) {
      const serverHelloLength = data.readUInt16BE(3);
      const counter = data[43]; // session_id_length

      if (data.length < counter + 46) return '|||';

      const selectedCipher = data.subarray(counter + 44, counter + 46);
      const version = data.subarray(9, 11);

      let jarm = selectedCipher.toString('hex');
      jarm += '|';
      jarm += version.toString('hex');
      jarm += '|';

      // Extract extensions
      jarm += extractExtensionInfo(data, counter, serverHelloLength);

      return jarm;
    }

    return '|||';
  } catch {
    return '|||';
  }
}

function extractExtensionInfo(data: Buffer, counter: number, serverHelloLength: number): string {
  try {
    if (data.length <= counter + 47) return '|';
    if (data[counter + 47] === 11) return '|';

    if (
      (data.length > counter + 53 && data.subarray(counter + 50, counter + 53).equals(Buffer.from([0x0e, 0xac, 0x0b]))) ||
      (data.length > 85 && data.subarray(82, 85).equals(Buffer.from([0x0f, 0xf0, 0x0b])))
    ) {
      return '|';
    }

    if (counter + 42 >= serverHelloLength) return '|';

    let count = 49 + counter;
    if (data.length < counter + 49) return '|';

    const length = data.readUInt16BE(counter + 47);
    const maximum = length + (count - 1);

    const types: Buffer[] = [];
    const values: Buffer[] = [];

    while (count < maximum && count + 4 <= data.length) {
      types.push(data.subarray(count, count + 2));
      const extLength = data.readUInt16BE(count + 2);
      if (extLength === 0) {
        count += 4;
        values.push(Buffer.alloc(0));
      } else {
        if (count + 4 + extLength > data.length) break;
        values.push(data.subarray(count + 4, count + 4 + extLength));
        count += extLength + 4;
      }
    }

    let result = '';

    // ALPN
    const alpnType = Buffer.from([0x00, 0x10]);
    let alpn = '';
    for (let i = 0; i < types.length; i++) {
      if (types[i].equals(alpnType) && values[i].length > 3) {
        alpn = values[i].subarray(3).toString('ascii');
        break;
      }
    }
    result += alpn;
    result += '|';

    // Extension types
    const extList = types.map(t => t.toString('hex'));
    result += extList.join('-');

    return result;
  } catch {
    return '|';
  }
}

// ---------------------------------------------------------------------------
// JARM Hash
// ---------------------------------------------------------------------------

export function cipherByte(cipher: string): string {
  if (!cipher) return '00';

  let count = 1;
  for (const buf of CIPHER_HASH_LIST) {
    if (buf.toString('hex') === cipher) break;
    count++;
  }

  const hex = count.toString(16);
  return hex.length < 2 ? '0' + hex : hex;
}

export function versionByte(version: string): string {
  if (!version) return '0';
  const options = 'abcdef';
  const idx = parseInt(version[3], 10);
  if (isNaN(idx) || idx >= options.length) return '0';
  return options[idx];
}

export function computeJarmHash(jarmRaw: string): string {
  const emptyRaw = '|||,|||,|||,|||,|||,|||,|||,|||,|||,|||';
  if (jarmRaw === emptyRaw) return '0'.repeat(62);

  let fuzzyHash = '';
  let alpnsAndExt = '';

  const handshakes = jarmRaw.split(',');
  for (const handshake of handshakes) {
    const components = handshake.split('|');
    fuzzyHash += cipherByte(components[0] || '');
    fuzzyHash += versionByte(components[1] || '');
    alpnsAndExt += (components[2] || '');
    alpnsAndExt += (components[3] || '');
  }

  const sha256 = crypto.createHash('sha256').update(alpnsAndExt).digest('hex');
  fuzzyHash += sha256.substring(0, 32);

  return fuzzyHash;
}

// ---------------------------------------------------------------------------
// Network I/O
// ---------------------------------------------------------------------------

function sendProbe(host: string, port: number, packet: Buffer, timeoutMs: number): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const done = (result: Buffer | null) => {
      if (resolved) return;
      resolved = true;
      try { socket.destroy(); } catch { /* ignore */ }
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => done(null));
    socket.on('error', () => done(null));

    socket.connect(port, host, () => {
      socket.write(packet);
    });

    socket.on('data', (data) => {
      done(data as Buffer);
    });
  });
}

// ---------------------------------------------------------------------------
// Probe Queue Definition
// ---------------------------------------------------------------------------

export function getProbeConfigs(host: string, port: number): JarmProbeConfig[] {
  return [
    { host, port, version: 'TLS_1.2', cipherList: 'ALL', cipherOrder: 'FORWARD', grease: 'NO_GREASE', alpn: 'APLN', supportedVersions: '1.2_SUPPORT', extensionOrder: 'REVERSE' },
    { host, port, version: 'TLS_1.2', cipherList: 'ALL', cipherOrder: 'REVERSE', grease: 'NO_GREASE', alpn: 'APLN', supportedVersions: '1.2_SUPPORT', extensionOrder: 'FORWARD' },
    { host, port, version: 'TLS_1.2', cipherList: 'ALL', cipherOrder: 'TOP_HALF', grease: 'NO_GREASE', alpn: 'APLN', supportedVersions: 'NO_SUPPORT', extensionOrder: 'FORWARD' },
    { host, port, version: 'TLS_1.2', cipherList: 'ALL', cipherOrder: 'BOTTOM_HALF', grease: 'NO_GREASE', alpn: 'RARE_APLN', supportedVersions: 'NO_SUPPORT', extensionOrder: 'FORWARD' },
    { host, port, version: 'TLS_1.2', cipherList: 'ALL', cipherOrder: 'MIDDLE_OUT', grease: 'GREASE', alpn: 'RARE_APLN', supportedVersions: 'NO_SUPPORT', extensionOrder: 'REVERSE' },
    { host, port, version: 'TLS_1.1', cipherList: 'ALL', cipherOrder: 'FORWARD', grease: 'NO_GREASE', alpn: 'APLN', supportedVersions: 'NO_SUPPORT', extensionOrder: 'FORWARD' },
    { host, port, version: 'TLS_1.3', cipherList: 'ALL', cipherOrder: 'FORWARD', grease: 'NO_GREASE', alpn: 'APLN', supportedVersions: '1.3_SUPPORT', extensionOrder: 'REVERSE' },
    { host, port, version: 'TLS_1.3', cipherList: 'ALL', cipherOrder: 'REVERSE', grease: 'NO_GREASE', alpn: 'APLN', supportedVersions: '1.3_SUPPORT', extensionOrder: 'FORWARD' },
    { host, port, version: 'TLS_1.3', cipherList: 'NO1.3', cipherOrder: 'FORWARD', grease: 'NO_GREASE', alpn: 'APLN', supportedVersions: '1.3_SUPPORT', extensionOrder: 'FORWARD' },
    { host, port, version: 'TLS_1.3', cipherList: 'ALL', cipherOrder: 'MIDDLE_OUT', grease: 'GREASE', alpn: 'APLN', supportedVersions: '1.3_SUPPORT', extensionOrder: 'REVERSE' },
  ];
}

// ---------------------------------------------------------------------------
// Main scan function
// ---------------------------------------------------------------------------

export async function scanJarm(host: string, port: number = 443, timeoutMs: number = 5000): Promise<JarmResult> {
  const probes = getProbeConfigs(host, port);
  const responses: string[] = [];

  for (const probe of probes) {
    const packet = buildClientHello(probe);
    const data = await sendProbe(host, port, packet, timeoutMs);

    if (data === null) {
      // Timeout → entire JARM is empty
      return {
        hash: '0'.repeat(62),
        raw: '|||,|||,|||,|||,|||,|||,|||,|||,|||,|||',
      };
    }

    responses.push(readServerHello(data));
  }

  const raw = responses.join(',');
  const hash = computeJarmHash(raw);

  return { hash, raw };
}

// ---------------------------------------------------------------------------
// Known JARM hashes for VPN appliances
// ---------------------------------------------------------------------------

export interface KnownJarmSignature {
  vendor: string;
  product: string;
  jarmHash: string;
  description?: string;
}

/**
 * Known JARM hashes for common VPN appliances.
 * Sources: community research, Shodan, public JARM databases.
 */
export const KNOWN_JARM_HASHES: KnownJarmSignature[] = [
  // Fortinet FortiGate
  {
    vendor: 'fortinet',
    product: 'FortiGate SSL VPN',
    jarmHash: '07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1',
    description: 'FortiOS SSL VPN (common JARM)',
  },
  {
    vendor: 'fortinet',
    product: 'FortiGate SSL VPN',
    jarmHash: '07d14d16d21d21d00042d41d00041de5fb3038b23b1e3f5b306868ed4cdb31',
    description: 'FortiOS 6.x/7.x variant',
  },
  // Palo Alto GlobalProtect
  {
    vendor: 'paloalto',
    product: 'GlobalProtect',
    jarmHash: '21d19d00021d21d21c21d19d21d21da1a818a999858855444ec8681c8ebef4',
    description: 'PAN-OS GlobalProtect portal',
  },
  {
    vendor: 'paloalto',
    product: 'GlobalProtect',
    jarmHash: '21d19d00021d21d00021d19d21d21da1a818a999858855444ec8681c8ebef4',
    description: 'PAN-OS GlobalProtect gateway',
  },
  // Pulse Secure / Ivanti Connect Secure
  {
    vendor: 'pulse',
    product: 'Pulse Connect Secure',
    jarmHash: '29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38',
    description: 'Pulse Secure / Ivanti Connect Secure',
  },
  {
    vendor: 'ivanti',
    product: 'Connect Secure',
    jarmHash: '29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38',
    description: 'Ivanti Connect Secure (same as Pulse)',
  },
  // Cisco ASA
  {
    vendor: 'cisco',
    product: 'ASA SSL VPN',
    jarmHash: '07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175',
    description: 'Cisco ASA AnyConnect/WebVPN',
  },
  {
    vendor: 'cisco',
    product: 'ASA SSL VPN',
    jarmHash: '07d14d16d21d21d00007d14d07d21d9b2f5869a6985368a9dec764186a9175',
    description: 'Cisco ASA variant',
  },
  // SonicWall
  {
    vendor: 'sonicwall',
    product: 'SMA/SSL VPN',
    jarmHash: '28d28d28d00028d00042d41d00041d2d6e5b0e390e3b3cad77c3fc1db3d9aa',
    description: 'SonicWall SMA / NetExtender',
  },
  // Citrix NetScaler / Gateway
  {
    vendor: 'citrix',
    product: 'NetScaler Gateway',
    jarmHash: '21d19d00000000021c21d19d21d21da1a818a999858855444ec8681c8ebef4',
    description: 'Citrix NetScaler / ADC Gateway',
  },
  {
    vendor: 'citrix',
    product: 'NetScaler Gateway',
    jarmHash: '2ad2ad0002ad2ad22c2ad2ad2ad2ada1a818a999858855444ec8681c8ebef4',
    description: 'Citrix Gateway variant',
  },
];

/**
 * Look up a JARM hash against known VPN signatures.
 */
export function lookupJarmHash(hash: string): KnownJarmSignature | undefined {
  return KNOWN_JARM_HASHES.find(k => k.jarmHash === hash);
}
