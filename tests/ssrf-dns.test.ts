import * as dns from 'node:dns/promises';

jest.mock('node:dns/promises');
const mockLookup = dns.lookup as jest.MockedFunction<typeof dns.lookup>;

// Import after mock
import { VpnScanner } from '../src/scanner';
const isHostSafe = (VpnScanner as any).isHostSafe.bind(VpnScanner);

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
