# VpnVet 🦞

**VPN Device Detection & Vulnerability Scanner for Attack Surface Management**

VpnVet detects VPN appliances exposed on the internet and checks them against known critical vulnerabilities, with a focus on CISA Known Exploited Vulnerabilities (KEV).

[![CI](https://github.com/taku-tez/VpnVet/actions/workflows/ci.yml/badge.svg)](https://github.com/taku-tez/VpnVet/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/vpnvet.svg)](https://www.npmjs.com/package/vpnvet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔍 **44 VPN Vendors** - Comprehensive global coverage
- 🛡️ **52 Critical CVEs** - CISA KEV prioritized (48 KEV)
- ⚠️ **CVE Coverage Warnings** - Alerts when detected products lack vulnerability mappings
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

// With options (vendor filtering)
const scanner = new VpnScanner({
  timeout: 15000,
  skipVulnCheck: false,
  vendor: 'fortinet', // Filter to specific vendor (see VpnVendor type)
});

const results = await scanner.scanMultiple([
  'vpn1.example.com',
  'vpn2.example.com',
]);
```

## Output Examples

### JSON Output

```json
{
  "target": "vpn.example.com",
  "timestamp": "2026-02-07T09:00:00.000Z",
  "device": {
    "vendor": "fortinet",
    "product": "FortiGate",
    "version": "7.0.5",
    "confidence": 95,
    "detectionMethod": ["endpoint", "header", "favicon"],
    "endpoints": ["/remote/login", "/remote/fgt_lang"]
  },
  "vulnerabilities": [
    {
      "vulnerability": {
        "cve": "CVE-2024-21762",
        "severity": "critical",
        "cvss": 9.8,
        "cisaKev": true
      },
      "confidence": "confirmed",
      "evidence": "Version 7.0.5 is in affected range"
    }
  ],
  "errors": []
}
```

When a detected product has no CVE mappings in the database, a `coverageWarning` field is included:

```json
{
  "target": "vpn2.example.com",
  "timestamp": "2026-02-07T09:00:00.000Z",
  "device": {
    "vendor": "watchguard",
    "product": "Firebox",
    "confidence": 80,
    "detectionMethod": ["endpoint", "html"],
    "endpoints": ["/sslvpn_logon.shtml"]
  },
  "vulnerabilities": [],
  "coverageWarning": "No CVE mappings currently available for watchguard Firebox. Detection coverage and vulnerability coverage are independent — a detected product with zero CVEs does not imply it is secure.",
  "errors": []
}
```

### SARIF Output

SARIF output includes `coverageWarning` as a notification-level result:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "vpnvet" } },
    "results": [
      {
        "ruleId": "coverage-warning",
        "level": "note",
        "message": {
          "text": "No CVE mappings currently available for watchguard Firebox."
        }
      }
    ]
  }]
}
```

### Understanding `coverageWarning`

The `coverageWarning` field appears when VpnVet successfully **detects** a VPN device but has **no CVE mappings** for that vendor/product combination in its vulnerability database. This is important because:

- **Detection coverage ≠ Vulnerability coverage** — VpnVet can detect 44 vendors but CVE data varies per product.
- **Zero CVEs ≠ Secure** — The absence of CVE matches means the database lacks data, not that the device is safe.
- **Action required** — Investigate the device manually or supplement with other vulnerability sources.

## Product Alias Resolution

VPN vendors frequently rebrand products through acquisitions. VpnVet automatically resolves legacy product names to their canonical forms so vulnerability lookups work correctly:

| Legacy Name | Canonical Name | Reason |
|-------------|---------------|--------|
| Pulse Connect Secure | Ivanti Connect Secure | Ivanti acquired Pulse Secure (2021) |
| NetScaler Gateway | Citrix Gateway | Citrix rebrand (2018) |
| FortiOS | FortiGate | Product vs OS naming |
| Cyberoam | Sophos XG Firewall | Sophos acquired Cyberoam (2014) |
| PAN-OS | GlobalProtect | OS vs product naming |
| BIG-IP | BIG-IP APM | Product family disambiguation |

This means scanning a target that reports as "Pulse Connect Secure" will still match CVEs filed under "Ivanti Connect Secure".

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
│   ├── cli.ts              # CLI entry point
│   ├── scanner.ts          # Core scanning logic
│   ├── types.ts            # TypeScript definitions
│   ├── vulnerabilities.ts  # CVE database (52 CVEs)
│   ├── vendor.ts           # Vendor alias resolution
│   ├── product.ts          # Product alias resolution
│   ├── utils.ts            # Shared utilities
│   ├── fingerprints/
│   │   ├── index.ts              # Aggregator
│   │   ├── tier1-enterprise.ts   # Fortinet, Palo Alto, Cisco, etc.
│   │   ├── tier2-enterprise.ts   # SonicWall, F5, Juniper, etc.
│   │   ├── asia.ts               # Huawei, H3C, Sangfor, etc.
│   │   ├── smb-soho.ts           # DrayTek, MikroTik, pfSense, etc.
│   │   └── cloud-ztna.ts         # Zscaler, Cloudflare, Meraki, etc.
│   └── index.ts            # Public API
├── tests/                   # 636 tests across 30 files
├── scripts/                 # Utility scripts
└── dist/                    # Compiled output
```

## Detection Coverage vs CVE Coverage

VpnVet's **detection coverage** (44 vendors) and **vulnerability coverage** (CVE mappings) are independent. A product may be successfully detected but have zero CVE mappings in the database. This does **not** mean the product is secure — it means VpnVet does not yet have vulnerability data for it.

When a detected product has no CVE mappings, VpnVet displays a coverage warning in all output formats (table, JSON, CSV, SARIF) to prevent false confidence in the results.

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
