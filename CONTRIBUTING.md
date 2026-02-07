# Contributing to VpnVet

Thanks for your interest in contributing! 🦞

## Quick Start

```bash
git clone https://github.com/taku-tez/VpnVet.git
cd VpnVet
npm install
npm run build
npm test
```

## Adding a New Vendor

### 1. Add Vendor Type

Edit `src/types.ts`:

```typescript
export type VpnVendor =
  // ... existing vendors
  | 'newvendor'  // Add your vendor
  | 'unknown';
```

### 2. Add Fingerprint

Fingerprints are organized into **category files** under `src/fingerprints/`:

| Category File | Vendors | Description |
|---------------|---------|-------------|
| `tier1-enterprise.ts` | Fortinet, Palo Alto, Cisco, Pulse/Ivanti, Citrix | Top-tier enterprise vendors (16 KEV) |
| `tier2-enterprise.ts` | SonicWall, Check Point, F5, Juniper, etc. | Other enterprise vendors (10 KEV) |
| `asia.ts` | Sangfor, Huawei, H3C, and regional vendors | Asia-Pacific regional vendors |
| `smb-soho.ts` | DrayTek, MikroTik, pfSense, etc. | Small business / SOHO solutions |
| `cloud-ztna.ts` | Meraki, Aruba, Zscaler, Cloudflare | Cloud-native and ZTNA solutions |

> **Note:** `src/fingerprints/index.ts` aggregates all category files into a single `fingerprints` array. You should **not** edit `index.ts` directly — add your fingerprint to the appropriate category file.

#### Choosing the right category

- Enterprise vendor with CISA KEV CVEs → `tier1-enterprise.ts` or `tier2-enterprise.ts`
- Asia-Pacific regional vendor → `asia.ts`
- Small business / home office product → `smb-soho.ts`
- Cloud-native, SaaS, or ZTNA product → `cloud-ztna.ts`

#### Example: adding to a category file

Edit the appropriate category file (e.g., `src/fingerprints/smb-soho.ts`) and append to the exported array:

```typescript
// In src/fingerprints/smb-soho.ts
export const smbsohoFingerprints: Fingerprint[] = [
  // ... existing entries ...
  {
    vendor: 'newvendor',
    product: 'Product Name',
    patterns: [
      {
        type: 'endpoint',
        path: '/login',
        method: 'GET',
        match: 'NewVendor|newvendor',
        weight: 10,  // 1-10, higher = more confident
      },
      {
        type: 'header',
        match: 'X-NewVendor-Cookie',
        weight: 9,
      },
      {
        type: 'body',
        path: '/',
        match: 'NewVendor VPN|Copyright NewVendor',
        weight: 8,
      },
      {
        type: 'certificate',
        match: 'NewVendor Inc',
        weight: 7,
      },
    ],
  },
];
```

### Pattern Types

| Type | Description | Example |
|------|-------------|---------|
| `endpoint` | URL path that returns vendor-specific content | `/remote/login` |
| `header` | HTTP response header | `SVPNCOOKIE` |
| `body` | HTML content pattern | `FortiGate SSL VPN` |
| `certificate` | SSL cert CN/O field | `Fortinet Inc` |
| `favicon` | Favicon hash (partial) | `f8b3c21a` |

### Weight Guidelines

| Weight | Meaning |
|--------|---------|
| 10 | Definitive match (unique endpoint) |
| 8-9 | Strong indicator (specific header/content) |
| 6-7 | Good indicator (certificate, generic patterns) |
| 1-5 | Weak indicator (common patterns) |

### 3. Add Vulnerabilities (if applicable)

Edit `src/vulnerabilities.ts`:

```typescript
{
  cve: 'CVE-2024-XXXXX',
  severity: 'critical',  // critical | high | medium | low
  cvss: 9.8,
  description: 'Description of the vulnerability',
  affected: [
    { 
      vendor: 'newvendor', 
      product: 'Product Name',
      versionStart: '1.0.0',  // Optional
      versionEnd: '1.5.0',    // Optional
    },
  ],
  references: [
    'https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX',
  ],
  exploitAvailable: true,
  cisaKev: true,  // Is it in CISA KEV catalog?
},
```

### 4. Add Tests

Edit `tests/fingerprints.test.ts`:

```typescript
describe('NewVendor patterns', () => {
  it('should have NewVendor fingerprint', () => {
    const vendor = getFingerprintsByVendor('newvendor')[0];
    expect(vendor).toBeDefined();
    expect(vendor.product).toBe('Product Name');
  });
});
```

### 5. Run Tests

```bash
npm test
```

## Code Style

- TypeScript strict mode
- ES modules
- Use `type` imports for types-only
- Keep functions small and focused

### Linting

Run ESLint before submitting a PR:

```bash
npm run lint
```

The project uses ESLint v9 flat config (`eslint.config.js`) with `@typescript-eslint`. All files under `src/**/*.ts` are checked. Warnings are acceptable but errors must be zero.

## Commit Messages

Use conventional commits:

```
feat: add NewVendor fingerprint
fix: correct FortiGate endpoint pattern
docs: update README with new vendors
test: add NewVendor detection tests
refactor: split fingerprints by region
```

## Pull Request Process

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/new-vendor`)
3. Make your changes
4. Run `npm test` and ensure all pass
5. Submit PR with clear description

## Finding Fingerprints

Good sources for fingerprint research:

- Shodan/Censys searches
- Vendor documentation
- Security advisories
- CVE details
- Product login pages

## Pre-release Checklist

Before releasing, verify that documentation statistics match the actual source data:

```bash
node scripts/count-stats.mjs
```

Update README.md and CHANGELOG.md if the counts have changed.

## Test Guidelines

### Principles

- **Network-independent**: Tests must not depend on real network connectivity. All HTTP/TLS calls should be mocked.
- **Deterministic**: Every test must produce the same result on every run, in any environment.
- **No `it.skip` without reason**: If a test is skipped, it must have a comment explaining why and what would be needed to enable it.

### Mocking Network Calls

VpnScanner has three private methods that perform I/O. Mock all of them to isolate tests from the network:

```typescript
import { VpnScanner } from '../src/scanner.js';

const scanner = new VpnScanner({ timeout: 1000 });

// Mock all network I/O
jest.spyOn(scanner as any, 'httpRequest').mockResolvedValue(null);
jest.spyOn(scanner as any, 'httpRequestBinary').mockResolvedValue(null);
jest.spyOn(scanner as any, 'getCertificateInfo').mockResolvedValue(null);

// Simulate a specific HTTP response:
jest.spyOn(scanner as any, 'httpRequest').mockResolvedValue({
  statusCode: 200,
  headers: { 'content-type': 'text/html' },
  body: '<html>mock</html>',
});

// Always restore mocks:
afterEach(() => jest.restoreAllMocks());
```

### Test File Organization

| File | Scope |
|------|-------|
| `scanner.test.ts` | Constructor, options, URL normalization, scan result structure, multi-port, redirects |
| `errors.test.ts` | Error handling: invalid targets, network errors (mocked), timeouts |
| `detection.test.ts` | Fingerprint matching against mock HTTP responses |
| `ssrf-sni.test.ts` | SSRF redirect protection and TLS SNI (security regression tests) |
| `cli-validation.test.ts` | CLI argument parsing and validation |
| `vulnerabilities.test.ts` | Vulnerability data integrity |
| `fingerprints.test.ts` | Fingerprint data integrity |

Avoid duplicating the same assertion across multiple files. Each test should live in exactly one place.

### CLI Integration Tests

Tests in `cli-validation.test.ts` spawn a child process (`npx tsx src/cli.ts ...`). These are acceptable because they test CLI argument parsing, not network behavior.

## Questions?

Open an issue or discussion on GitHub!
