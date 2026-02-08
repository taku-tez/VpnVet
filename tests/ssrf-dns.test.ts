import * as dns from 'node:dns/promises';

jest.mock('node:dns/promises');
const mockLookup = dns.lookup as jest.MockedFunction<typeof dns.lookup>;

// Import after mock
import { VpnScanner } from '../src/scanner';
const isHostSafe = (VpnScanner as any).isHostSafe.bind(VpnScanner);
const resolveSafeAddresses = VpnScanner.resolveSafeAddresses.bind(VpnScanner);
const isUnsafeIP = VpnScanner.isUnsafeIP.bind(VpnScanner);

describe('SSRF DNS multi-address resolution', () => {
  beforeEach(() => {
    mockLookup.mockReset();
  });

  it('should block hostname when any resolved address is private', async () => {
    mockLookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.1', family: 4 },
    ] as any);

    expect(await isHostSafe('mixed.example.com')).toBe(false);
  });

  it('should allow hostname when all resolved addresses are public', async () => {
    mockLookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '8.8.8.8', family: 4 },
    ] as any);

    expect(await isHostSafe('safe.example.com')).toBe(true);
  });

  it('should block hostname when DNS lookup fails (fail-closed)', async () => {
    mockLookup.mockRejectedValue(new Error('ENOTFOUND'));

    expect(await isHostSafe('nonexistent.example.com')).toBe(false);
  });

  it('should block hostname with mixed IPv4/IPv6 including private', async () => {
    mockLookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '::1', family: 6 },
    ] as any);

    expect(await isHostSafe('mixed-v6.example.com')).toBe(false);
  });
});

describe('Expanded unsafe IP ranges (#1)', () => {
  // IPv4 unsafe ranges
  it.each([
    ['0.0.0.0', '0.0.0.0/8 (this network)'],
    ['0.255.255.255', '0.0.0.0/8 (this network)'],
    ['10.0.0.1', '10.0.0.0/8 (RFC1918)'],
    ['100.64.0.1', '100.64.0.0/10 (CGN)'],
    ['100.127.255.254', '100.64.0.0/10 (CGN)'],
    ['127.0.0.1', '127.0.0.0/8 (loopback)'],
    ['169.254.1.1', '169.254.0.0/16 (link-local)'],
    ['172.16.0.1', '172.16.0.0/12 (RFC1918)'],
    ['192.168.1.1', '192.168.0.0/16 (RFC1918)'],
    ['198.18.0.1', '198.18.0.0/15 (benchmarking)'],
    ['198.19.255.255', '198.18.0.0/15 (benchmarking)'],
    ['224.0.0.1', '224.0.0.0/4 (multicast)'],
    ['239.255.255.255', '224.0.0.0/4 (multicast)'],
    ['240.0.0.1', '240.0.0.0+ (reserved)'],
    ['255.255.255.255', 'broadcast'],
  ])('should block %s (%s)', (ip) => {
    expect(isUnsafeIP(ip)).toBe(true);
  });

  // IPv4 safe ranges
  it.each([
    ['1.1.1.1'],
    ['8.8.8.8'],
    ['93.184.216.34'],
    ['100.63.255.255'],  // just below CGN
    ['100.128.0.0'],     // just above CGN
    ['198.17.255.255'],  // just below benchmarking
    ['198.20.0.0'],      // just above benchmarking
    ['223.255.255.255'], // just below multicast
  ])('should allow %s', (ip) => {
    expect(isUnsafeIP(ip)).toBe(false);
  });

  // IPv6 unsafe
  it.each([
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fc00::1', 'ULA fc00::/7'],
    ['fd12:3456::1', 'ULA fd'],
    ['fe80::1', 'link-local'],
    ['ff02::1', 'multicast ff00::/8'],
    ['ff00::0', 'multicast ff00::/8'],
    ['ffff::1', 'multicast ff00::/8'],
    ['2001:db8::1', 'documentation 2001:db8::/32'],
    ['2001:db8:1234::1', 'documentation 2001:db8::/32'],
  ])('should block IPv6 %s (%s)', (ip) => {
    expect(isUnsafeIP(ip)).toBe(true);
  });

  // IPv4-mapped IPv6
  it.each([
    ['::ffff:127.0.0.1', true],
    ['::ffff:10.0.0.1', true],
    ['::ffff:100.64.0.1', true],
    ['::ffff:198.18.0.1', true],
    ['::ffff:8.8.8.8', false],
    ['::ffff:93.184.216.34', false],
    ['0:0:0:0:0:ffff:127.0.0.1', true],    // Expanded form (#1)
    ['0000:0000:0000:0000:0000:ffff:10.0.0.1', true],
  ])('should handle IPv4-mapped IPv6 %s → unsafe=%s', (ip, expected) => {
    expect(isUnsafeIP(ip)).toBe(expected);
  });

  // New special-use ranges (Agent P / #1)
  it.each([
    ['192.0.0.1', true, '192.0.0.0/24 (IETF Protocol Assignments)'],
    ['192.0.0.254', true, '192.0.0.0/24 (IETF Protocol Assignments)'],
    ['192.0.2.1', true, '192.0.2.0/24 (TEST-NET-1)'],
    ['192.0.2.254', true, '192.0.2.0/24 (TEST-NET-1)'],
    ['192.88.99.0', true, '192.88.99.0/24 (6to4 Relay)'],
    ['192.88.99.255', true, '192.88.99.0/24 (6to4 Relay)'],
    ['198.51.100.1', true, '198.51.100.0/24 (TEST-NET-2)'],
    ['198.51.100.254', true, '198.51.100.0/24 (TEST-NET-2)'],
    ['203.0.113.1', true, '203.0.113.0/24 (TEST-NET-3)'],
    ['203.0.113.254', true, '203.0.113.0/24 (TEST-NET-3)'],
    // Boundary: just outside new ranges should be safe
    ['192.0.1.0', false, 'just above 192.0.0.0/24'],
    ['192.0.3.0', false, 'just above 192.0.2.0/24'],
    ['192.88.98.255', false, 'just below 192.88.99.0/24'],
    ['192.88.100.0', false, 'just above 192.88.99.0/24'],
    ['198.51.99.255', false, 'just below 198.51.100.0/24'],
    ['198.51.101.0', false, 'just above 198.51.100.0/24'],
    ['203.0.112.255', false, 'just below 203.0.113.0/24'],
    ['203.0.114.0', false, 'just above 203.0.113.0/24'],
  ])('should handle %s → unsafe=%s (%s)', (ip, expected) => {
    expect(isUnsafeIP(ip)).toBe(expected);
  });

  // IPv4-mapped IPv6 hex form (Agent P / #2)
  it.each([
    ['::ffff:c0a8:0101', true, '192.168.1.1'],
    ['::ffff:0a00:0001', true, '10.0.0.1'],
    ['::ffff:7f00:0001', true, '127.0.0.1'],
    ['::ffff:6440:0001', true, '100.64.0.1 (CGN)'],
    ['::ffff:c000:0201', true, '192.0.2.1 (TEST-NET-1)'],
    ['::ffff:c633:6401', true, '198.51.100.1 (TEST-NET-2)'],
    ['::ffff:0808:0808', false, '8.8.8.8'],
    ['::ffff:5db8:d822', false, '93.184.216.34'],
    ['0:0:0:0:0:ffff:c0a8:0101', true, 'expanded form 192.168.1.1'],
  ])('should handle hex IPv4-mapped %s → unsafe=%s (%s)', (ip, expected) => {
    expect(isUnsafeIP(ip)).toBe(expected);
  });

  // fe80::/10 full range (#1)
  it.each([
    ['fe80::1', true],
    ['febf::1', true],
    ['febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', true],
    ['fec0::1', false],  // outside fe80::/10
  ])('should handle fe80::/10 link-local %s → unsafe=%s', (ip, expected) => {
    expect(isUnsafeIP(ip)).toBe(expected);
  });
});

describe('DNS pinning / rebinding resistance (#2)', () => {
  beforeEach(() => {
    mockLookup.mockReset();
  });

  it('resolveSafeAddresses returns pinned IPs for safe host', async () => {
    mockLookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '93.184.216.35', family: 4 },
    ] as any);

    const addrs = await resolveSafeAddresses('example.com');
    expect(addrs).toEqual(['93.184.216.34', '93.184.216.35']);
  });

  it('resolveSafeAddresses returns empty for unsafe host', async () => {
    mockLookup.mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.1', family: 4 },
    ] as any);

    const addrs = await resolveSafeAddresses('evil.example.com');
    expect(addrs).toEqual([]);
  });

  it('resolveSafeAddresses returns empty on DNS failure', async () => {
    mockLookup.mockRejectedValue(new Error('ENOTFOUND'));
    const addrs = await resolveSafeAddresses('nonexistent.example.com');
    expect(addrs).toEqual([]);
  });

  it('resolveSafeAddresses handles direct IP input', async () => {
    expect(await resolveSafeAddresses('8.8.8.8')).toEqual(['8.8.8.8']);
    expect(await resolveSafeAddresses('127.0.0.1')).toEqual([]);
    expect(await resolveSafeAddresses('10.0.0.1')).toEqual([]);
  });
});
