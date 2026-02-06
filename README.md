# VpnVet 🦞

**VPN Device Detection & Vulnerability Scanner for Attack Surface Management**

VpnVet detects VPN appliances exposed on the internet and checks them against known critical vulnerabilities, with a focus on CISA Known Exploited Vulnerabilities (KEV).

[![npm version](https://img.shields.io/npm/v/vpnvet.svg)](https://www.npmjs.com/package/vpnvet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔍 **44 VPN Vendors** - Comprehensive global coverage
- 🛡️ **41+ Critical CVEs** - CISA KEV prioritized
- 📊 **Multiple Formats** - JSON, SARIF, CSV, Table
- 🚀 **Fast & Lightweight** - No heavy dependencies
- 🔧 **CI/CD Ready** - Exit codes based on severity

## Supported Vendors

### Enterprise (Tier 1)
| Vendor | Products | Key CVEs |
|--------|----------|----------|
| Fortinet | FortiGate | CVE-2024-21762, CVE-2023-27997 |
| Palo Alto | GlobalProtect | CVE-2024-3400 |
| Cisco | AnyConnect, ASA | CVE-2023-20269 |
| Check Point | Mobile Access | - |
| F5 | BIG-IP APM | CVE-2022-1388, CVE-2020-5902 |
| Juniper | SRX SSL VPN | CVE-2023-36844 |

### SSL VPN Specialists
| Vendor | Products | Key CVEs |
|--------|----------|----------|
| Pulse Secure | Connect Secure | CVE-2019-11510 |
| Ivanti | Connect Secure | CVE-2024-21887, CVE-2023-46805 |
| Citrix | Gateway/NetScaler | CVE-2023-4966 (Citrix Bleed) |
| Array Networks | AG Series | CVE-2023-28461 |
| SonicWall | SMA | CVE-2021-20016 |

### UTM / NGFW
Sophos XG, WatchGuard Firebox, Barracuda CloudGen, Zyxel USG/ZyWALL, Stormshield SNS

### SMB / SOHO
DrayTek Vigor, MikroTik RouterOS, Ubiquiti UniFi, pfSense, OPNsense, NETGEAR ProSAFE, TP-Link Omada

### Asia / China
Huawei USG, H3C SecPath, Hillstone NGFW, Sangfor SSL VPN, Ruijie RG, NSFOCUS, Venustech, TopSec, DPtech

### Korea
AhnLab TrusGuard, SECUI MF2

### European
Stormshield (FR), LANCOM (DE), Kerio Control, Endian UTM (IT)

### Cloud / ZTNA
Zscaler ZPA, Cloudflare Access

### Other
OpenVPN Access Server, Cisco Meraki MX, Aruba ClearPass, Untangle NG Firewall, NetMotion Mobility

## Installation

```bash
npm install -g vpnvet
```

## Quick Start

```bash
# Scan a single target
vpnvet scan vpn.example.com

# Scan multiple targets
vpnvet scan --targets domains.txt

# JSON output
vpnvet scan vpn.example.com -f json -o result.json

# SARIF for GitHub Security tab
vpnvet scan --targets domains.txt -f sarif -o results.sarif
```

## CLI Reference

### Commands

```bash
vpnvet scan <target>              # Scan single target
vpnvet scan --targets <file>      # Scan from file
vpnvet list vendors               # List supported vendors
vpnvet list vulns                 # List known CVEs
vpnvet list vulns --severity critical  # Filter by severity
vpnvet version                    # Show version
```

### Scan Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --targets <file>` | File with targets (one per line) | - |
| `-o, --output <file>` | Output file path | stdout |
| `-f, --format <fmt>` | Output format: json, sarif, csv, table | table |
| `--timeout <ms>` | Request timeout | 10000 |
| `--skip-vuln` | Skip vulnerability check | false |
| `--skip-version` | Skip version detection | false |
| `-q, --quiet` | Suppress progress output | false |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | High/Medium/Low vulnerabilities found |
| 2 | Critical vulnerabilities found |

## API Usage

```typescript
import { VpnScanner, scan } from 'vpnvet';

// Simple scan
const result = await scan('vpn.example.com');

if (result.device) {
  console.log(`Found: ${result.device.vendor} ${result.device.product}`);
  console.log(`Confidence: ${result.device.confidence}%`);
  
  for (const vuln of result.vulnerabilities) {
    console.log(`[${vuln.vulnerability.severity}] ${vuln.vulnerability.cve}`);
  }
}

// With options
const scanner = new VpnScanner({
  timeout: 15000,
  skipVulnCheck: false,
});

const results = await scanner.scanMultiple([
  'vpn1.example.com',
  'vpn2.example.com',
]);
```

## Detection Methods

VpnVet uses multiple detection techniques:

1. **Endpoint Probing** - Known login/admin paths for each vendor
2. **HTTP Headers** - Vendor-specific cookies and headers
3. **SSL Certificates** - Organization names in certificate CN/O fields
4. **HTML Analysis** - Page content patterns and vendor markers
5. **Confidence Scoring** - Weighted pattern matching (0-100%)

## Why VPN Security Matters

VPN appliances are prime targets for ransomware and APT groups:

- 🏥 **2022 Osaka Hospital** - Ransomware via FortiGate (CVE-2018-13379)
- 🚢 **2023 Nagoya Port** - Operations halted via VPN compromise
- 🏛️ **2024 Government Orgs** - Mass exploitation of Ivanti vulnerabilities

CISA maintains a [Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog - VpnVet prioritizes these CVEs.

## Project Structure

```
vpnvet/
├── src/
│   ├── cli.ts           # CLI entry point
│   ├── scanner.ts       # Core scanning logic
│   ├── types.ts         # TypeScript definitions
│   ├── vulnerabilities.ts  # CVE database
│   ├── fingerprints/
│   │   └── index.ts     # Vendor fingerprints
│   └── index.ts         # Public API
├── tests/
│   ├── fingerprints.test.ts
│   ├── vulnerabilities.test.ts
│   └── scanner.test.ts
└── dist/                # Compiled output
```

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding a New Vendor

1. Add vendor type to `src/types.ts`
2. Add fingerprint patterns to `src/fingerprints/index.ts`
3. Add relevant CVEs to `src/vulnerabilities.ts`
4. Add tests
5. Update README

## License

MIT

## Links

- [GitHub](https://github.com/taku-tez/VpnVet)
- [npm](https://www.npmjs.com/package/vpnvet)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
