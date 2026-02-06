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
  // SonicWall
  // ============================================================
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

  // ============================================================
  // Sophos
  // ============================================================
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
