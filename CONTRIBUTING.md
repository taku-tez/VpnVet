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

Edit `src/fingerprints/index.ts`:

```typescript
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

## Questions?

Open an issue or discussion on GitHub!
