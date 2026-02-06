# Changelog

All notable changes to VpnVet will be documented in this file.

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
- 41 CVEs (28 CISA KEV)
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
- 41 CVEs (28 CISA KEV)
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
- 41 CVEs (was 29)

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
