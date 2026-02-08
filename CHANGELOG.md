# Changelog

All notable changes to VpnVet will be documented in this file.

## [1.0.0] - 2026-02-08

### 🎉 First Stable Release

VpnVet v1.0.0 — production-ready VPN device detection and vulnerability scanner.

### Stats
- **44 vendors** across 5 category files (Tier 1/2 Enterprise, Asia, SMB-SOHO, Cloud-ZTNA)
- **80 CVEs** tracked (**60 CISA KEV**)
- **633 tests** across 38 test files — all passing
- Zero `it.skip` without documented reason

### Added (since 0.9.0)
- **CVE semi-automation scripts** for maintaining vulnerability database
- **Version boundary tests** for edge-case version range matching
- **Performance & stability tests** (P2 test suite expansion)
- **False positive/negative test suites** with real-world regression cases
- **Output schema validation tests** for JSON, SARIF, CSV formats
- **ESLint v9 flat config** with `@typescript-eslint`

### Improved
- CLI UX: case-insensitive `--vendor`, per-subcommand flag validation, helpful error messages
- SSRF protection: expanded blocked IP ranges, hex IPv4-mapped IPv6 handling
- Normalizer hardening: URL normalization, strict numeric CLI validation
- Scanner refactoring: shared `httpRequest` core, adaptive concurrency
- Dead code removal, simplified CLI output, stabilized list ordering

### Security
- Input validation for all CLI arguments (target, file paths, options)
- SSRF redirect protection with DNS rebinding mitigation
- TLS SNI pinning for certificate verification
- No sensitive data (IPs/tokens) in log output

### Documentation
- LICENSE (MIT) file added
- README updated with accurate CVE/test counts and project structure
- CONTRIBUTING.md with category file guidelines and test conventions

## [0.9.0] - 2026-02-07

### Added
- **Product alias dictionary** (`src/product.ts`) — resolves legacy/rebranded product names to canonical forms (#2)
  - Pulse Connect Secure → Ivanti Connect Secure
  - NetScaler Gateway → Citrix Gateway
  - FortiOS → FortiGate, Cyberoam → Sophos XG, and 20+ more aliases
- Alias resolution integrated into `checkVulnerabilities()` and coverage warning logic
- New exports: `resolveProductAlias`, `resolveProductAndVendor`, `PRODUCT_ALIASES`

### Improved
- **README documentation** — added JSON/SARIF output examples with `coverageWarning` field (#8)
- Explained detection coverage vs vulnerability coverage distinction
- Product alias resolution table in README

## [0.8.0] - 2026-02-07

### Added - FortiGate Deep Fingerprint Research
Major accuracy improvements for FortiGate/FortiOS detection based on deep research
(Bishop Fox, Shadowserver, Nuclei templates, CVE PoCs).

#### New Detection Patterns
- **Favicon hash**: Shodan mmh3 `945408572`, `-76600061`
- **ETag header**: Unix timestamp extraction for firmware build date (FG-IR-23-224)
- **SSL certificate**: `O=Fortinet, OU=FortiGate, CN=FGT-<serial>` (model detection)
- **Security headers**: `X-Frame-Options`, `Content-Security-Policy` (FortiOS 7.x)
- **SAML SSO**: `/remote/saml/start` (FortiOS 7.x only)
- **WebSocket CLI**: `/ws/cli` (CVE-2024-55591 target)
- **Angular SPA**: `/ng/` (FortiOS 7.x admin UI)
- **Static resources**: `/remote/css/sslvpn.css`, `/remote/js/sslvpn.js`, `/css/login.css`
- **Host check**: `/remote/hostcheck_validate` (CVE-2023-27997, CVE-2024-21762)
- **REST API admin**: `/api/v2/cmdb/system/admin/admin` (CVE-2022-40684)

#### New CVE
- **CVE-2024-55591** (CVSS 9.8, CISA KEV): Node.js WebSocket auth bypass → super-admin

#### Pattern Organization
- 7-tier confidence hierarchy (most reliable → supplementary)
- CVE target endpoints documented
- FortiOS version-specific patterns (6.x vs 7.x)

### Stats
- 44 vendors, **38 CVEs (34 CISA KEV)**
- FortiGate: **6 critical CVEs** tracked
- 122 tests (115 passed, 7 skipped)

## [0.7.0] - 2026-02-06

### Added - Second Wave Official Documentation Research
Major fingerprint improvements for 5 additional vendors (10 CISA KEV CVEs total).

#### F5 BIG-IP APM
- `Server: BigIP` header
- `MRHSession`, `LastMRH_Session`, `MRHSHint` APM cookies (32-char hex)
- `BIGipServer` LTM persistence cookie (can leak internal IP)
- `/tmui/login.jsp` (CVE-2020-5902), `/mgmt/tm/util/bash` (CVE-2022-1388)
- `/vdesk/webtop.eui`, `/public/include/js/agent_common.js`

#### Juniper SRX / J-Web
- Title: "Log In - Juniper Web Device Manager"
- Favicon hash `2141724739` (Shodan)
- `/dynamic-vpn` SSL VPN portal
- `/webauth_operation.php` (CVE-2023-36844/45/46/47 target)
- `/jsdm/ajax/logging_browse.php` (CVE-2022-22241 Phar)
- Version format: `21.4R3`, `21.4R3-S4`

#### SonicWall SMA
- `Server: SonicWALL`, `Server: SMA/12.x` (version extractable)
- SMA 100 vs SMA 1000 detection
- `login_box_sonicwall` CSS class
- `/cgi-bin/userLogin`, `/__api__/v1/logon`
- Version format: `10.2.1.5-57sv` (SMA 100), `12.4.1` (SMA 1000)

#### Zyxel USG/ZyWALL/ATP
- Product names in HTML title (USG FLEX, ATP100, VPN50, etc.)
- `zyFunction.js` script reference (high confidence)
- `/zld_product_spec.js` version info
- `/ztp/cgi-bin/parse_config.py` (CVE-2023-33012)
- `authtok` auth cookie
- Version format: `V5.39`, `V4.72`

#### Sophos XG Firewall / SFOS
- `UserPortalLogin.js` script reference
- "Without JavaScript support user portal will not work" text
- User Portal (443/4443), WebAdmin (4444), VPN Portal (443)
- `/userportal/Controller`, `/webconsole/Controller`
- Legacy `Cyberoam.c$rFt0k3n` CSRF token
- Version format: `SFOS 19.5.3 MR-3`

### Stats
- 44 vendors with official documentation-based fingerprints
- 38 CVEs (34 CISA KEV)
- Top 10 vendors now research-backed
- 122 tests (115 passed, 7 skipped)

## [0.6.0] - 2026-02-06

### Added - Official Documentation Research
Major fingerprint accuracy improvements based on official vendor documentation research.

#### Fortinet FortiGate
- `Server: xxxxxxxx-xxxxx` header (most reliable, ~490K devices on Shodan)
- `SVPNNETWORKCOOKIE`, `SVPNTMPCOOKIE` cookies
- JS redirect pattern `top.location="/remote/login"`

#### Palo Alto GlobalProtect
- `/global-protect/prelogin.esp`, `/ssl-vpn/prelogin.esp` (pre-auth XML)
- `<prelogin-response>`, `<panos-version>` XML patterns
- ETag epoch method for version detection (panos-scanner)

#### Cisco AnyConnect/ASA
- `/CSCOSSLC/config-auth` version endpoint (`<version who="sg">`)
- `webvpnlogin`, `webvpn_portal`, `webvpncontext` cookies
- `/+CSCOT+/`, `/+CSCOU+/` path patterns

#### Ivanti Connect Secure (Pulse Secure)
- `DSBrowserID` cookie (Shodan fingerprint)
- SAML endpoints (`/dana-ws/saml20.ws`, `/dana-na/auth/saml-logout.cgi`)
- REST API endpoints (CVE-2024-21887 targets)
- HostCheckerInstaller.osx version extraction

#### Citrix Gateway (NetScaler)
- `NSC_AAAC`, `NSC_TMAS`, `NSC_TMAA` cookies
- `/vpn/pluginlist.xml` plugin version info
- `?v=<MD5hash>` version hash pattern (fox-it/citrix-netscaler-triage)
- EPA endpoints

### Improved
- Higher confidence detection for top 5 VPN vendors (16 CISA KEV CVEs)
- More accurate version extraction patterns
- Pre-auth endpoint coverage for vulnerability scanning

### Stats
- 44 vendors
- 38 CVEs (34 CISA KEV)
- 122 tests (115 passed, 7 skipped)

## [0.3.0] - 2026-02-06

### Added
- **25 new vendors** bringing total to 44
- New regional coverage:
  - China: Huawei, H3C, Ruijie, NSFOCUS, Venustech, TopSec, DPtech
  - Korea: AhnLab, SECUI
  - Europe: Stormshield (FR), LANCOM (DE), Endian (IT)
- SMB/SOHO vendors: DrayTek, MikroTik, Ubiquiti, pfSense, OPNsense, NETGEAR, TP-Link
- Cloud/ZTNA detection: Zscaler, Cloudflare Access
- Enterprise additions: Aruba, Meraki, Kerio, Untangle
- 12 new CVEs including:
  - CVE-2024-41592 (DrayTek)
  - CVE-2018-14847 (MikroTik)
  - CVE-2023-1389 (TP-Link)
  - CVE-2022-37913 (Aruba)

### Stats
- 44 vendors (was 19)
- 38 CVEs (was 29)

## [0.2.0] - 2026-02-06

### Added
- **10 new vendors** bringing total to 19
- F5 BIG-IP APM with CVE-2022-1388, CVE-2023-46747, CVE-2020-5902
- Juniper SRX with CVE-2023-36844, CVE-2024-21591
- Zyxel USG/ZyWALL with CVE-2022-30525, CVE-2023-28771
- Sophos XG with CVE-2022-3236, CVE-2020-12271 (Asnarök)
- WatchGuard Firebox
- Barracuda CloudGen with CVE-2023-2868
- Sangfor SSL VPN (China)
- Array Networks AG with CVE-2023-28461
- NetMotion Mobility
- Hillstone NGFW (China)

### Stats
- 19 vendors (was 9)
- 29 CVEs (was 20)

## [0.1.0] - 2026-02-06

### Added
- Initial release
- 9 VPN vendor fingerprints:
  - Fortinet FortiGate
  - Palo Alto GlobalProtect
  - Cisco AnyConnect
  - Pulse Secure
  - Ivanti Connect Secure
  - SonicWall SMA
  - Check Point Mobile Access
  - Citrix Gateway
  - OpenVPN Access Server
- 20 critical CVEs with CISA KEV tracking
- Multiple output formats: JSON, SARIF, CSV, table
- Exit codes for CI/CD (0/1/2 by severity)
- 41 passing tests
