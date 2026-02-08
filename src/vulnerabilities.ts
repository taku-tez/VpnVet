/**
 * VPN Vulnerability Database
 * 
 * Focus on actively exploited CVEs with high impact.
 * Priority: CISA KEV > Critical CVSS > Known exploits
 */

import type { Vulnerability } from './types.js';

export const vulnerabilities: Vulnerability[] = [
  // ============================================================
  // Fortinet FortiGate / FortiOS
  // ============================================================
  {
    cve: 'CVE-2024-21762',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiOS out-of-bounds write vulnerability allowing RCE via SSL VPN',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.4.0', versionEnd: '7.4.2' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.2.0', versionEnd: '7.2.6' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.0.13' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.4.0', versionEnd: '6.4.14' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.2.0', versionEnd: '6.2.15' },
    ],
    references: [
      'https://www.fortiguard.com/psirt/FG-IR-24-015',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21762',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2023-27997',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiOS heap-based buffer overflow (XORtigate) allowing RCE',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.2.0', versionEnd: '7.2.4' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.0.11' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.4.0', versionEnd: '6.4.12' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.2.0', versionEnd: '6.2.13' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.0.0', versionEnd: '6.0.16' },
    ],
    references: [
      'https://www.fortiguard.com/psirt/FG-IR-23-097',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-27997',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2022-42475',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiOS SSL-VPN heap-based buffer overflow allowing RCE',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.2.0', versionEnd: '7.2.2' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.0.8' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.4.0', versionEnd: '6.4.10' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.2.0', versionEnd: '6.2.11' },
    ],
    references: [
      'https://www.fortiguard.com/psirt/FG-IR-22-398',
      'https://nvd.nist.gov/vuln/detail/CVE-2022-42475',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2022-40684',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiOS authentication bypass via alternate path (admin panel takeover)',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.2.0', versionEnd: '7.2.1' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.0.6' },
    ],
    references: [
      'https://www.fortiguard.com/psirt/FG-IR-22-377',
      'https://nvd.nist.gov/vuln/detail/CVE-2022-40684',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2018-13379',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiOS SSL VPN path traversal allowing credential theft',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.0.0', versionEnd: '6.0.4' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '5.6.3', versionEnd: '5.6.7' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '5.4.6', versionEnd: '5.4.12' },
    ],
    references: [
      'https://www.fortiguard.com/psirt/FG-IR-18-384',
      'https://nvd.nist.gov/vuln/detail/CVE-2018-13379',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2024-55591',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiOS Node.js WebSocket authentication bypass allowing super-admin access',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.0.16' },
    ],
    references: [
      'https://www.fortiguard.com/psirt/FG-IR-24-535',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-55591',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2026-24858',
    severity: 'critical',
    cvss: 9.4,
    description: 'FortiOS/FortiManager/FortiAnalyzer FortiCloud SSO authentication bypass zero-day',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.4.10' },
    ],
    references: [
      'https://fortiguard.fortinet.com/psirt/FG-IR-26-060',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-24858',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-59718',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiOS/FortiProxy/FortiSwitchManager/FortiWeb FortiCloud SSO cryptographic signature bypass allowing unauthenticated admin access',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.6.1' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.4.0', versionEnd: '7.4.6' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.2.0', versionEnd: '7.2.10' },
    ],
    references: [
      'https://fortiguard.fortinet.com/psirt/FG-IR-25-254',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-59718',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-59719',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiWeb FortiCloud SSO authentication bypass allowing unauthorized device management access',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.4.0', versionEnd: '7.4.9' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.6.0', versionEnd: '7.6.4' },
    ],
    references: [
      'https://fortiguard.fortinet.com/psirt/FG-IR-25-255',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-59719',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-25249',
    severity: 'high',
    cvss: 8.1,
    description: 'FortiOS/FortiSwitchManager CAPWAP daemon RCE via crafted network packets',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.6.0', versionEnd: '7.6.3' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.4.0', versionEnd: '7.4.8' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.2.0', versionEnd: '7.2.11' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.0.17' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.4.0', versionEnd: '6.4.16' },
    ],
    references: [
      'https://fortiguard.fortinet.com/psirt/FG-IR-25-084',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-25249',
    ],
    exploitAvailable: false,
    cisaKev: false,
  },
  {
    cve: 'CVE-2025-64155',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiSIEM unauthenticated OS command injection allowing root-level RCE (PoC available, actively exploited)',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.2.0' },
    ],
    references: [
      'https://fortiguard.fortinet.com/psirt/FG-IR-25-085',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-64155',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-32756',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiOS/FortiVoice/FortiNDR/FortiMail/FortiRecorder stack-based buffer overflow allowing RCE',
    affected: [
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.4.0', versionEnd: '7.4.7' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.2.0', versionEnd: '7.2.11' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '7.0.0', versionEnd: '7.0.17' },
      { vendor: 'fortinet', product: 'FortiGate', versionStart: '6.4.0', versionEnd: '6.4.16' },
    ],
    references: [
      'https://fortiguard.fortinet.com/psirt/FG-IR-25-254',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-32756',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  {
    cve: 'CVE-2024-47575',
    severity: 'critical',
    cvss: 9.8,
    description: 'FortiManager missing authentication for critical function (FortiJump) allowing RCE',
    affected: [
      { vendor: 'fortinet', product: 'FortiManager', versionStart: '7.6.0', versionEnd: '7.6.0' },
      { vendor: 'fortinet', product: 'FortiManager', versionStart: '7.4.0', versionEnd: '7.4.4' },
      { vendor: 'fortinet', product: 'FortiManager', versionStart: '7.2.0', versionEnd: '7.2.7' },
      { vendor: 'fortinet', product: 'FortiManager', versionStart: '7.0.0', versionEnd: '7.0.12' },
    ],
    references: [
      'https://www.fortiguard.com/psirt/FG-IR-24-423',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-47575',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Palo Alto GlobalProtect / PAN-OS
  // ============================================================
  {
    cve: 'CVE-2024-3400',
    severity: 'critical',
    cvss: 10.0,
    description: 'PAN-OS GlobalProtect command injection allowing unauthenticated RCE',
    affected: [
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.1.0', versionEnd: '11.1.2-h2' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.0.0', versionEnd: '11.0.4-h1' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '10.2.0', versionEnd: '10.2.9-h1' },
    ],
    references: [
      'https://security.paloaltonetworks.com/CVE-2024-3400',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2020-2021',
    severity: 'critical',
    cvss: 10.0,
    description: 'PAN-OS SAML authentication bypass allowing unauthorized access',
    affected: [
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '9.1.0', versionEnd: '9.1.2' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '9.0.0', versionEnd: '9.0.8' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '8.1.0', versionEnd: '8.1.14' },
    ],
    references: [
      'https://security.paloaltonetworks.com/CVE-2020-2021',
      'https://nvd.nist.gov/vuln/detail/CVE-2020-2021',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  {
    cve: 'CVE-2024-0012',
    severity: 'critical',
    cvss: 9.8,
    description: 'PAN-OS management web interface authentication bypass allowing admin access',
    affected: [
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.2.0', versionEnd: '11.2.4-h1' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.1.0', versionEnd: '11.1.5-h1' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.0.0', versionEnd: '11.0.6-h1' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '10.2.0', versionEnd: '10.2.12-h2' },
    ],
    references: [
      'https://security.paloaltonetworks.com/CVE-2024-0012',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-0012',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2024-9474',
    severity: 'high',
    cvss: 7.2,
    description: 'PAN-OS privilege escalation in management web interface allowing root access',
    affected: [
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.2.0', versionEnd: '11.2.4-h1' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.1.0', versionEnd: '11.1.5-h1' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.0.0', versionEnd: '11.0.6-h1' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '10.2.0', versionEnd: '10.2.12-h2' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '10.1.0', versionEnd: '10.1.14-h6' },
    ],
    references: [
      'https://security.paloaltonetworks.com/CVE-2024-9474',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-9474',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2026-0227',
    severity: 'high',
    cvss: 7.7,
    description: 'PAN-OS GlobalProtect gateway/portal DoS via improper exceptional condition check (PoC available)',
    affected: [
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.2.0', versionEnd: '11.2.4-h4' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.1.0', versionEnd: '11.1.6-h1' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '11.0.0', versionEnd: '11.0.7' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '10.2.0', versionEnd: '10.2.13-h3' },
      { vendor: 'paloalto', product: 'GlobalProtect', versionStart: '10.1.0', versionEnd: '10.1.14-h11' },
    ],
    references: [
      'https://security.paloaltonetworks.com/CVE-2026-0227',
      'https://nvd.nist.gov/vuln/detail/CVE-2026-0227',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },

  // ============================================================
  // Cisco AnyConnect / ASA
  // ============================================================
  {
    cve: 'CVE-2023-20269',
    severity: 'critical',
    cvss: 9.1,
    description: 'Cisco ASA/FTD remote access VPN unauthorized access vulnerability',
    affected: [
      { vendor: 'cisco', product: 'AnyConnect' },
    ],
    references: [
      'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ravpn-auth-8LyfCkeC',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-20269',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2020-3452',
    severity: 'high',
    cvss: 7.5,
    description: 'Cisco ASA/FTD web services read-only path traversal',
    affected: [
      { vendor: 'cisco', product: 'AnyConnect' },
    ],
    references: [
      'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43',
      'https://nvd.nist.gov/vuln/detail/CVE-2020-3452',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Pulse Secure / Ivanti Connect Secure
  // ============================================================
  {
    cve: 'CVE-2024-21887',
    severity: 'critical',
    cvss: 9.1,
    description: 'Ivanti Connect Secure command injection allowing RCE',
    affected: [
      { vendor: 'pulse', product: 'Pulse Connect Secure' },
      { vendor: 'ivanti', product: 'Connect Secure', versionStart: '9.0', versionEnd: '22.6R1.1' },
      { vendor: 'ivanti', product: 'Connect Secure', versionStart: '22.1R1', versionEnd: '22.6R2.2' },
    ],
    references: [
      'https://forums.ivanti.com/s/article/CVE-2024-21887-Command-Injection-Vulnerability',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21887',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2024-21893',
    severity: 'critical',
    cvss: 8.2,
    description: 'Ivanti Connect Secure SSRF in SAML component',
    affected: [
      { vendor: 'pulse', product: 'Pulse Connect Secure' },
      { vendor: 'ivanti', product: 'Connect Secure' },
    ],
    references: [
      'https://forums.ivanti.com/s/article/CVE-2024-21893',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21893',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2023-46805',
    severity: 'critical',
    cvss: 8.2,
    description: 'Ivanti Connect Secure authentication bypass',
    affected: [
      { vendor: 'pulse', product: 'Pulse Connect Secure' },
      { vendor: 'ivanti', product: 'Connect Secure', versionStart: '9.0', versionEnd: '22.6R1.1' },
    ],
    references: [
      'https://forums.ivanti.com/s/article/CVE-2023-46805',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-46805',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-0282',
    severity: 'critical',
    cvss: 9.0,
    description: 'Ivanti Connect Secure stack-based buffer overflow allowing unauthenticated RCE',
    affected: [
      { vendor: 'ivanti', product: 'Connect Secure', versionStart: '22.7R2', versionEnd: '22.7R2.4' },
      { vendor: 'pulse', product: 'Pulse Connect Secure', versionStart: '9.1R18', versionEnd: '9.1R18.9' },
    ],
    references: [
      'https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-0283',
    severity: 'high',
    cvss: 7.0,
    description: 'Ivanti Connect Secure/Policy Secure/ZTA stack-based buffer overflow for local privilege escalation',
    affected: [
      { vendor: 'ivanti', product: 'Connect Secure', versionStart: '22.7R2', versionEnd: '22.7R2.4' },
      { vendor: 'pulse', product: 'Pulse Connect Secure', versionStart: '9.1R18', versionEnd: '9.1R18.9' },
    ],
    references: [
      'https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-0283',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },
  {
    cve: 'CVE-2025-22457',
    severity: 'critical',
    cvss: 9.0,
    description: 'Ivanti Connect Secure stack-based buffer overflow allowing RCE (TRAILBLAZE/BRUSHFIRE)',
    affected: [
      { vendor: 'ivanti', product: 'Connect Secure', versionStart: '22.7R2', versionEnd: '22.7R2.5' },
      { vendor: 'pulse', product: 'Pulse Connect Secure', versionStart: '9.1R18', versionEnd: '9.1R18.9' },
    ],
    references: [
      'https://forums.ivanti.com/s/article/April-Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-22457',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-22457',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2019-11510',
    severity: 'critical',
    cvss: 10.0,
    description: 'Pulse Secure arbitrary file reading (credential theft)',
    affected: [
      { vendor: 'pulse', product: 'Pulse Connect Secure', versionStart: '8.1R1', versionEnd: '8.1R15.1' },
      { vendor: 'pulse', product: 'Pulse Connect Secure', versionStart: '8.2', versionEnd: '8.2R12.1' },
      { vendor: 'pulse', product: 'Pulse Connect Secure', versionStart: '8.3', versionEnd: '8.3R7.1' },
      { vendor: 'pulse', product: 'Pulse Connect Secure', versionStart: '9.0', versionEnd: '9.0R3.4' },
    ],
    references: [
      'https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101',
      'https://nvd.nist.gov/vuln/detail/CVE-2019-11510',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Check Point
  // ============================================================
  {
    cve: 'CVE-2024-24919',
    severity: 'high',
    cvss: 8.6,
    description: 'Check Point Security Gateway information disclosure allowing credential theft via VPN',
    affected: [
      { vendor: 'checkpoint', product: 'Mobile Access' },
    ],
    references: [
      'https://support.checkpoint.com/results/sk/sk182336',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-24919',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // SonicWall
  // ============================================================
  {
    cve: 'CVE-2024-40766',
    severity: 'critical',
    cvss: 9.8,
    description: 'SonicWall SonicOS improper access control in management and SSLVPN',
    affected: [
      { vendor: 'sonicwall', product: 'SMA' },
    ],
    references: [
      'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-40766',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2024-53704',
    severity: 'critical',
    cvss: 9.8,
    description: 'SonicWall SonicOS SSL VPN authentication bypass allowing session hijacking',
    affected: [
      { vendor: 'sonicwall', product: 'SMA' },
    ],
    references: [
      'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0003',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-53704',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-32818',
    severity: 'high',
    cvss: 7.5,
    description: 'SonicWall SonicOS SSLVPN NULL pointer dereference causing DoS (Gen7/Gen8)',
    affected: [
      { vendor: 'sonicwall', product: 'SMA', versionStart: '7.1.1-7040', versionEnd: '7.1.3-7015' },
      { vendor: 'sonicwall', product: 'SMA', versionStart: '8.0.0', versionEnd: '8.0.0-8037' },
    ],
    references: [
      'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0009',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-32818',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2021-20016',
    severity: 'critical',
    cvss: 9.8,
    description: 'SonicWall SMA 100 SQL injection allowing credential access',
    affected: [
      { vendor: 'sonicwall', product: 'SMA', versionStart: '10.2.0.0', versionEnd: '10.2.0.5-d-29sv' },
    ],
    references: [
      'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0001',
      'https://nvd.nist.gov/vuln/detail/CVE-2021-20016',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-40599',
    severity: 'critical',
    cvss: 9.8,
    description: 'SonicWall SMA 100 Series pre-auth RCE with OVERSTEP rootkit in-the-wild exploitation',
    affected: [
      { vendor: 'sonicwall', product: 'SMA', versionStart: '10.2.0.0', versionEnd: '10.2.1.15-81sv' },
    ],
    references: [
      'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0011',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-40599',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-40602',
    severity: 'high',
    cvss: 7.8,
    description: 'SonicWall SMA 1000 AMC local privilege escalation zero-day',
    affected: [
      { vendor: 'sonicwall', product: 'SMA', versionStart: '12.4.0', versionEnd: '12.4.3-02758' },
    ],
    references: [
      'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0015',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-40602',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Citrix Gateway / NetScaler
  // ============================================================
  {
    cve: 'CVE-2023-4966',
    severity: 'critical',
    cvss: 9.4,
    description: 'Citrix NetScaler ADC/Gateway session token leakage (Citrix Bleed)',
    affected: [
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '14.1', versionEnd: '14.1-8.49' },
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '13.1', versionEnd: '13.1-49.14' },
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '13.0', versionEnd: '13.0-92.18' },
    ],
    references: [
      'https://support.citrix.com/article/CTX579459',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2023-3519',
    severity: 'critical',
    cvss: 9.8,
    description: 'Citrix NetScaler ADC/Gateway unauthenticated RCE',
    affected: [
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '13.1', versionEnd: '13.1-49.12' },
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '13.0', versionEnd: '13.0-91.12' },
    ],
    references: [
      'https://support.citrix.com/article/CTX561482',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-3519',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2019-19781',
    severity: 'critical',
    cvss: 9.8,
    description: 'Citrix ADC/Gateway path traversal allowing RCE (Shitrix)',
    affected: [
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '13.0', versionEnd: '13.0.47.24' },
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '12.1', versionEnd: '12.1.55.18' },
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '12.0', versionEnd: '12.0.63.13' },
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '11.1', versionEnd: '11.1.63.15' },
      { vendor: 'citrix', product: 'Citrix Gateway', versionStart: '10.5', versionEnd: '10.5.70.12' },
    ],
    references: [
      'https://support.citrix.com/article/CTX267027',
      'https://nvd.nist.gov/vuln/detail/CVE-2019-19781',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // F5 BIG-IP
  // ============================================================
  {
    cve: 'CVE-2022-1388',
    severity: 'critical',
    cvss: 9.8,
    description: 'F5 BIG-IP iControl REST authentication bypass allowing RCE',
    affected: [
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '16.1.0', versionEnd: '16.1.2.1' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '15.1.0', versionEnd: '15.1.5' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '14.1.0', versionEnd: '14.1.4.5' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '13.1.0', versionEnd: '13.1.4' },
    ],
    references: [
      'https://support.f5.com/csp/article/K23605346',
      'https://nvd.nist.gov/vuln/detail/CVE-2022-1388',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2023-46747',
    severity: 'critical',
    cvss: 9.8,
    description: 'F5 BIG-IP Configuration utility authentication bypass',
    affected: [
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '17.1.0', versionEnd: '17.1.0' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '16.1.0', versionEnd: '16.1.4' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '15.1.0', versionEnd: '15.1.10' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '14.1.0', versionEnd: '14.1.5' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '13.1.0', versionEnd: '13.1.5' },
    ],
    references: [
      'https://my.f5.com/manage/s/article/K000137353',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-46747',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2020-5902',
    severity: 'critical',
    cvss: 9.8,
    description: 'F5 BIG-IP TMUI RCE vulnerability',
    affected: [
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '15.0.0', versionEnd: '15.1.0.3' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '14.1.0', versionEnd: '14.1.2.5' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '13.1.0', versionEnd: '13.1.3.3' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '12.1.0', versionEnd: '12.1.5.1' },
      { vendor: 'f5', product: 'BIG-IP APM', versionStart: '11.6.1', versionEnd: '11.6.5.1' },
    ],
    references: [
      'https://support.f5.com/csp/article/K52145254',
      'https://nvd.nist.gov/vuln/detail/CVE-2020-5902',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Juniper
  // ============================================================
  {
    cve: 'CVE-2023-36844',
    severity: 'critical',
    cvss: 9.8,
    description: 'Juniper Junos OS J-Web PHP external variable modification (chained with CVE-2023-36845 for RCE)',
    affected: [
      { vendor: 'juniper', product: 'SRX SSL VPN' },
    ],
    references: [
      'https://supportportal.juniper.net/JSA72300',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-36844',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2023-36845',
    severity: 'critical',
    cvss: 9.8,
    description: 'Juniper Junos OS J-Web PHP environment variable manipulation enabling RCE (chained with CVE-2023-36844)',
    affected: [
      { vendor: 'juniper', product: 'SRX SSL VPN' },
    ],
    references: [
      'https://supportportal.juniper.net/JSA72300',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-36845',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2024-21591',
    severity: 'critical',
    cvss: 9.8,
    description: 'Juniper Junos OS J-Web out-of-bounds write allowing RCE',
    affected: [
      { vendor: 'juniper', product: 'SRX SSL VPN' },
    ],
    references: [
      'https://supportportal.juniper.net/JSA75729',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21591',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Zyxel
  // ============================================================
  {
    cve: 'CVE-2022-30525',
    severity: 'critical',
    cvss: 9.8,
    description: 'Zyxel firewall unauthenticated command injection',
    affected: [
      { vendor: 'zyxel', product: 'USG/ZyWALL' },
    ],
    references: [
      'https://www.zyxel.com/support/Zyxel-security-advisory-for-OS-command-injection-vulnerability-of-firewalls.shtml',
      'https://nvd.nist.gov/vuln/detail/CVE-2022-30525',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2023-28771',
    severity: 'critical',
    cvss: 9.8,
    description: 'Zyxel firewall OS command injection in IPSec VPN',
    affected: [
      { vendor: 'zyxel', product: 'USG/ZyWALL' },
    ],
    references: [
      'https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-remote-command-injection-vulnerability-of-firewalls',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-28771',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  {
    cve: 'CVE-2024-11667',
    severity: 'high',
    cvss: 7.5,
    description: 'Zyxel firewall directory traversal vulnerability exploited in ransomware attacks',
    affected: [
      { vendor: 'zyxel', product: 'USG/ZyWALL' },
    ],
    references: [
      'https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-firewalls-11-27-2024',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-11667',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2024-40891',
    severity: 'critical',
    cvss: 9.8,
    description: 'Zyxel CPE Series telnet command injection (zero-day actively exploited)',
    affected: [
      { vendor: 'zyxel', product: 'USG/ZyWALL' },
    ],
    references: [
      'https://www.greynoise.io/blog/active-exploitation-of-zero-day-zyxel-cpe-vulnerability-cve-2024-40891',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-40891',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-11730',
    severity: 'high',
    cvss: 7.2,
    description: 'Zyxel ATP/USG FLEX DDNS CLI command injection allowing OS command execution',
    affected: [
      { vendor: 'zyxel', product: 'USG/ZyWALL', versionStart: '5.35', versionEnd: '5.41' },
    ],
    references: [
      'https://www.zyxel.com/global/en/support/security-advisories',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-11730',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },
  {
    cve: 'CVE-2025-8078',
    severity: 'high',
    cvss: 7.2,
    description: 'Zyxel ATP/USG FLEX/USG20 post-authentication command injection via IPSec VPN configuration',
    affected: [
      { vendor: 'zyxel', product: 'USG/ZyWALL', versionStart: '4.32', versionEnd: '5.40' },
    ],
    references: [
      'https://www.zyxel.com/global/en/support/security-advisories',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-8078',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },

  // ============================================================
  // Sophos
  // ============================================================
  {
    cve: 'CVE-2020-15069',
    severity: 'critical',
    cvss: 9.8,
    description: 'Sophos XG Firewall buffer overflow in User Portal allowing RCE',
    affected: [
      { vendor: 'sophos', product: 'XG Firewall' },
    ],
    references: [
      'https://www.sophos.com/en-us/security-advisories/sophos-sa-20200625-xg-user-portal-rce',
      'https://nvd.nist.gov/vuln/detail/CVE-2020-15069',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2022-3236',
    severity: 'critical',
    cvss: 9.8,
    description: 'Sophos Firewall code injection in User Portal and Webadmin',
    affected: [
      { vendor: 'sophos', product: 'XG Firewall' },
    ],
    references: [
      'https://www.sophos.com/en-us/security-advisories/sophos-sa-20220923-sfos-rce',
      'https://nvd.nist.gov/vuln/detail/CVE-2022-3236',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2020-12271',
    severity: 'critical',
    cvss: 10.0,
    description: 'Sophos XG Firewall SQL injection (Asnarök)',
    affected: [
      { vendor: 'sophos', product: 'XG Firewall' },
    ],
    references: [
      'https://www.sophos.com/en-us/security-advisories/sophos-sa-20200421-asnarok',
      'https://nvd.nist.gov/vuln/detail/CVE-2020-12271',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // WatchGuard
  // ============================================================
  {
    cve: 'CVE-2025-14733',
    severity: 'critical',
    cvss: 9.3,
    description: 'WatchGuard Fireware OS IKEv2 VPN out-of-bounds write allowing unauthenticated RCE',
    affected: [
      { vendor: 'watchguard', product: 'Firebox' },
    ],
    references: [
      'https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2025-00027',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-14733',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2022-23176',
    severity: 'critical',
    cvss: 8.8,
    description: 'WatchGuard Firebox/XTM privilege escalation allowing management access via exposed endpoint',
    affected: [
      { vendor: 'watchguard', product: 'Firebox' },
    ],
    references: [
      'https://www.watchguard.com/wgrd-psirt/advisory/wgsa-2022-00002',
      'https://nvd.nist.gov/vuln/detail/CVE-2022-23176',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Barracuda
  // ============================================================
  {
    cve: 'CVE-2023-2868',
    severity: 'critical',
    cvss: 9.8,
    description: 'Barracuda ESG command injection via .tar file processing',
    affected: [
      { vendor: 'barracuda', product: 'CloudGen Firewall' },
    ],
    references: [
      'https://www.barracuda.com/company/legal/esg-vulnerability',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-2868',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Array Networks
  // ============================================================
  {
    cve: 'CVE-2023-28461',
    severity: 'critical',
    cvss: 9.8,
    description: 'Array Networks AG/vxAG remote code execution',
    affected: [
      { vendor: 'array', product: 'AG Series' },
    ],
    references: [
      'https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/documentation/index.html?documentation/advisories.html',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-28461',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Sangfor
  // ============================================================
  {
    cve: 'CVE-2021-22005',
    severity: 'critical',
    cvss: 9.8,
    description: 'Sangfor SSL VPN arbitrary file write leading to RCE',
    affected: [
      { vendor: 'sangfor', product: 'SSL VPN' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-22005',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },

  // ============================================================
  // DrayTek
  // ============================================================
  {
    cve: 'CVE-2024-41592',
    severity: 'critical',
    cvss: 10.0,
    description: 'DrayTek Vigor routers stack buffer overflow in web UI',
    affected: [
      { vendor: 'draytek', product: 'Vigor' },
    ],
    references: [
      'https://www.draytek.com/support/security-advisories',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-41592',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },
  {
    cve: 'CVE-2020-8515',
    severity: 'critical',
    cvss: 10.0,
    description: 'DrayTek Vigor pre-auth remote code execution',
    affected: [
      { vendor: 'draytek', product: 'Vigor' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2020-8515',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // MikroTik
  // ============================================================
  {
    cve: 'CVE-2018-14847',
    severity: 'critical',
    cvss: 9.1,
    description: 'MikroTik RouterOS Winbox authentication bypass',
    affected: [
      { vendor: 'mikrotik', product: 'RouterOS' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2018-14847',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // pfSense
  // ============================================================
  {
    cve: 'CVE-2022-31814',
    severity: 'high',
    cvss: 8.8,
    description: 'pfBlockerNG unauthenticated RCE via command injection',
    affected: [
      { vendor: 'pfsense', product: 'pfSense' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2022-31814',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },

  // ============================================================
  // NETGEAR
  // ============================================================
  {
    cve: 'CVE-2021-45382',
    severity: 'critical',
    cvss: 9.8,
    description: 'NETGEAR router remote code execution via SOAP',
    affected: [
      { vendor: 'netgear', product: 'ProSAFE' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-45382',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // TP-Link
  // ============================================================
  {
    cve: 'CVE-2023-1389',
    severity: 'critical',
    cvss: 9.8,
    description: 'TP-Link Archer routers command injection',
    affected: [
      { vendor: 'tplink', product: 'Omada' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-1389',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Huawei
  // ============================================================
  {
    cve: 'CVE-2017-17215',
    severity: 'critical',
    cvss: 9.8,
    description: 'Huawei HG532 router remote code execution',
    affected: [
      { vendor: 'huawei', product: 'USG' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2017-17215',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },

  // ============================================================
  // Aruba
  // ============================================================
  {
    cve: 'CVE-2022-37913',
    severity: 'critical',
    cvss: 9.8,
    description: 'Aruba EdgeConnect Enterprise Orchestrator RCE',
    affected: [
      { vendor: 'aruba', product: 'ClearPass' },
    ],
    references: [
      'https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2022-016.txt',
      'https://nvd.nist.gov/vuln/detail/CVE-2022-37913',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },

  // ============================================================
  // Cisco ASA / FTD (2025)
  // ============================================================
  {
    cve: 'CVE-2025-20333',
    severity: 'critical',
    cvss: 9.8,
    description: 'Cisco ASA and FTD Software VPN Web Server RCE allowing root-level code execution',
    affected: [
      { vendor: 'cisco', product: 'ASA', versionStart: '9.8.0', versionEnd: '9.22.99' },
      { vendor: 'cisco', product: 'FTD' },
    ],
    references: [
      'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-z5xP8EUB',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-20333',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-20362',
    severity: 'critical',
    cvss: 9.8,
    description: 'Cisco ASA and FTD Software VPN Web Server vulnerability causing device reload and potential RCE',
    affected: [
      { vendor: 'cisco', product: 'ASA' },
      { vendor: 'cisco', product: 'FTD' },
    ],
    references: [
      'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-webvpn-z5xP8EUB',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-20362',
    ],
    exploitAvailable: true,
    cisaKev: true,
  },
  {
    cve: 'CVE-2025-20363',
    severity: 'critical',
    cvss: 9.8,
    description: 'Cisco ASA and FTD Software privilege escalation via VPN web services',
    affected: [
      { vendor: 'cisco', product: 'ASA' },
      { vendor: 'cisco', product: 'FTD' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2025-20363',
    ],
    exploitAvailable: true,
    cisaKev: false,
  },

  // ============================================================
  // SonicWall (2025)
  // ============================================================
  {
    cve: 'CVE-2025-40601',
    severity: 'high',
    cvss: 7.5,
    description: 'SonicOS SSLVPN buffer overflow causing remote firewall crash (Gen7/Gen8)',
    affected: [
      { vendor: 'sonicwall', product: 'SMA', versionStart: '7.0.0', versionEnd: '7.3.0-7012' },
      { vendor: 'sonicwall', product: 'SMA', versionStart: '8.0.0', versionEnd: '8.0.2-8011' },
    ],
    references: [
      'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0016',
      'https://nvd.nist.gov/vuln/detail/CVE-2025-40601',
    ],
    exploitAvailable: false,
    cisaKev: false,
  },
  // Zyxel - Missing Authorization (2025)
  {
    cve: 'CVE-2025-9133',
    severity: 'high',
    cvss: 7.2,
    description: 'Zyxel ATP/USG FLEX/USG20-VPN missing authorization vulnerability allowing unauthorized configuration access',
    affected: [
      { vendor: 'zyxel', product: 'USG/ZyWALL', versionStart: 'V4.16', versionEnd: 'V5.40' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2025-9133',
    ],
    exploitAvailable: false,
    cisaKev: false,
  },
  // Juniper - SRX GTP DoS (2026)
  {
    cve: 'CVE-2026-21914',
    severity: 'high',
    cvss: 7.5,
    description: 'Juniper Junos OS SRX Series GTP plugin improper locking DoS via malformed GTP Modify Bearer Request',
    affected: [
      { vendor: 'juniper', product: 'SRX SSL VPN', versionEnd: '22.4R3-S8' },
      { vendor: 'juniper', product: 'SRX SSL VPN', versionStart: '23.2', versionEnd: '23.2R2-S5' },
      { vendor: 'juniper', product: 'SRX SSL VPN', versionStart: '23.4', versionEnd: '23.4R2-S6' },
      { vendor: 'juniper', product: 'SRX SSL VPN', versionStart: '24.2', versionEnd: '24.2R2-S3' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2026-21914',
    ],
    exploitAvailable: false,
    cisaKev: false,
  },
  // Juniper - SRX IPsec/GRE DoS (2026)
  {
    cve: 'CVE-2026-21906',
    severity: 'high',
    cvss: 7.5,
    description: 'Juniper Junos OS SRX Series PFE crash via ICMP packet through GRE tunnel with PMI enabled',
    affected: [
      { vendor: 'juniper', product: 'SRX SSL VPN', versionEnd: '21.4R3-S12' },
      { vendor: 'juniper', product: 'SRX SSL VPN', versionStart: '22.4', versionEnd: '22.4R3-S8' },
      { vendor: 'juniper', product: 'SRX SSL VPN', versionStart: '23.2', versionEnd: '23.2R2-S5' },
      { vendor: 'juniper', product: 'SRX SSL VPN', versionStart: '23.4', versionEnd: '23.4R2-S5' },
    ],
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2026-21906',
    ],
    exploitAvailable: false,
    cisaKev: false,
  },
];

export function getVulnerabilitiesByVendor(vendor: string): Vulnerability[] {
  return vulnerabilities.filter(v =>
    v.affected.some(a => a.vendor === vendor)
  );
}

export function getCriticalVulnerabilities(): Vulnerability[] {
  return vulnerabilities.filter(v => v.severity === 'critical');
}

export function getKevVulnerabilities(): Vulnerability[] {
  return vulnerabilities.filter(v => v.cisaKev);
}
