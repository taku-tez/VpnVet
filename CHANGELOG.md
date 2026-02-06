# Changelog

All notable changes to VpnVet will be documented in this file.

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
