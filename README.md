# VpnVet 🦞

**VPN Device Detection & Vulnerability Scanner for ASM**

VpnVet detects VPN appliances exposed on the internet and checks them against known critical vulnerabilities, with a focus on CISA Known Exploited Vulnerabilities (KEV).

## Features

- 🔍 **Device Detection** - Fingerprints 9 major VPN vendors
- 🛡️ **Vulnerability Check** - 20+ critical CVEs with CISA KEV tracking
- 📊 **Multiple Output Formats** - JSON, SARIF, CSV, Table
- 🚀 **Fast & Lightweight** - No heavy dependencies
- 🔧 **CI/CD Ready** - Exit codes based on severity

## Supported Vendors

| Vendor | Products |
|--------|----------|
| Fortinet | FortiGate (SSL-VPN) |
| Palo Alto | GlobalProtect |
| Cisco | AnyConnect / ASA |
| Pulse Secure | Pulse Connect Secure |
| Ivanti | Connect Secure |
| SonicWall | SMA |
| Check Point | Mobile Access |
| Citrix | Citrix Gateway / NetScaler |
| OpenVPN | Access Server |

## Installation

```bash
npm install -g vpnvet
```

## Usage

### Basic Scan

```bash
# Scan a single target
vpnvet scan vpn.example.com

# Scan multiple targets from file
vpnvet scan --targets domains.txt
```

### Output Formats

```bash
# JSON output
vpnvet scan vpn.example.com -f json -o result.json

# SARIF format (for GitHub Security tab)
vpnvet scan --targets domains.txt -f sarif -o results.sarif

# CSV for spreadsheets
vpnvet scan --targets domains.txt -f csv -o results.csv
```

### List Commands

```bash
# Show supported vendors
vpnvet list vendors

# Show known vulnerabilities
vpnvet list vulns

# Filter by severity
vpnvet list vulns --severity critical
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found (high/medium/low) |
| 2 | Critical vulnerabilities found |

## Key Vulnerabilities Tracked

### CISA KEV (Known Exploited Vulnerabilities)

| CVE | Vendor | CVSS | Description |
|-----|--------|------|-------------|
| CVE-2024-21762 | Fortinet | 9.8 | FortiOS RCE via SSL VPN |
| CVE-2024-3400 | Palo Alto | 10.0 | GlobalProtect command injection |
| CVE-2024-21887 | Ivanti | 9.1 | Connect Secure RCE |
| CVE-2023-4966 | Citrix | 9.4 | NetScaler session hijacking (Citrix Bleed) |
| CVE-2023-27997 | Fortinet | 9.8 | FortiOS heap overflow (XORtigate) |
| CVE-2019-11510 | Pulse | 10.0 | Arbitrary file read |
| CVE-2019-19781 | Citrix | 9.8 | Path traversal RCE (Shitrix) |

## API Usage

```typescript
import { VpnScanner, scan } from 'vpnvet';

// Simple scan
const result = await scan('vpn.example.com');

if (result.device) {
  console.log(`Found: ${result.device.vendor} ${result.device.product}`);
  console.log(`Confidence: ${result.device.confidence}%`);
  
  for (const vuln of result.vulnerabilities) {
    console.log(`  - ${vuln.vulnerability.cve}: ${vuln.confidence}`);
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

1. **Endpoint Probing** - Known login/admin paths
2. **HTTP Headers** - Vendor-specific cookies and headers
3. **SSL Certificates** - Organization names in certs
4. **HTML Analysis** - Page content patterns
5. **Favicon Hashing** - Unique favicon signatures

## Why VPN Security Matters

VPN appliances are prime targets for attackers:

- 🏥 **2022 Osaka Hospital** - Ransomware via FortiGate vulnerability
- 🚢 **2023 Nagoya Port** - Operations halted via VPN compromise
- 🏛️ **2024 Government Orgs** - Mass exploitation of Ivanti vulnerabilities

Regular scanning helps identify exposed VPN devices before attackers do.

## License

MIT

## Contributing

Issues and PRs welcome at [github.com/taku-tez/VpnVet](https://github.com/taku-tez/VpnVet)
