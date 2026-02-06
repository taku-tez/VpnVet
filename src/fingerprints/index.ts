/**
 * VPN Device Fingerprints Database
 * Updated with official documentation research (2026-02-06)
 */

import type { Fingerprint } from '../types.js';

export const fingerprints: Fingerprint[] = [
  // ============================================================
  // Fortinet FortiGate (5 CISA KEV CVEs)
  // Official Docs: docs.fortinet.com, fortiguard.com/psirt
  // ============================================================
  {
    vendor: 'fortinet',
    product: 'FortiGate',
    patterns: [
      // Most reliable: Server header (Shodan: ~490,000 devices)
      {
        type: 'header',
        match: 'Server: xxxxxxxx-xxxxx',
        weight: 10,
      },
      // SSL VPN cookies (definitive)
      {
        type: 'header',
        match: 'SVPNCOOKIE',
        weight: 10,
      },
      {
        type: 'header',
        match: 'SVPNNETWORKCOOKIE',
        weight: 10,
      },
      {
        type: 'header',
        match: 'SVPNTMPCOOKIE',
        weight: 9,
      },
      // SSL VPN login endpoints
      {
        type: 'endpoint',
        path: '/remote/login',
        method: 'GET',
        match: 'FortiToken|fortinet|fgt_lang|sslvpn',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/remote/logincheck',
        method: 'GET',
        match: 'remote|login',
        weight: 8,
      },
      {
        type: 'endpoint',
        path: '/login',
        method: 'GET',
        match: 'fgt_lang|ftnt-fortinet|NEUTRINO_THEME',
        weight: 10,
      },
      // Language file (CVE-2018-13379 target)
      {
        type: 'endpoint',
        path: '/remote/fgt_lang?lang=en',
        method: 'GET',
        match: '"msg"\\s*:',
        weight: 9,
      },
      // JS redirect pattern
      {
        type: 'body',
        path: '/',
        match: 'top\\.location="/remote/login"',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'top\\.location="/login"',
        weight: 9,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/remote/login',
        match: 'fgt_lang|fortigate|fgd_icon',
        weight: 9,
      },
      {
        type: 'body',
        path: '/login',
        match: 'fgt_lang|ftnt-fortinet',
        weight: 9,
      },
      // Version detection via API (requires auth usually)
      {
        type: 'endpoint',
        path: '/api/v2/monitor/system/firmware',
        method: 'GET',
        match: 'current|version',
        weight: 8,
        versionExtract: /"version"\s*:\s*"v?(\d+\.\d+\.\d+)"/,
      },
      // Certificate
      {
        type: 'certificate',
        match: 'FortiGate|Fortinet',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Palo Alto GlobalProtect (2 CISA KEV CVEs)
  // Official Docs: docs.paloaltonetworks.com
  // Version detection: ETag epoch method (panos-scanner)
  // ============================================================
  {
    vendor: 'paloalto',
    product: 'GlobalProtect',
    patterns: [
      // Server header (most reliable)
      {
        type: 'header',
        match: 'Server: PanWeb Server',
        weight: 10,
      },
      // Prelogin endpoints (pre-auth, XML response)
      {
        type: 'endpoint',
        path: '/global-protect/prelogin.esp',
        method: 'GET',
        match: 'prelogin-response|status',
        weight: 10,
        versionExtract: /<panos-version>([^<]+)<\/panos-version>/,
      },
      {
        type: 'endpoint',
        path: '/ssl-vpn/prelogin.esp',
        method: 'GET',
        match: 'prelogin-response',
        weight: 10,
        versionExtract: /<panos-version>([^<]+)<\/panos-version>/,
      },
      // Portal login
      {
        type: 'endpoint',
        path: '/global-protect/login.esp',
        method: 'GET',
        match: 'GlobalProtect|pan-globalprotect|PAN_FORM_CONTENT',
        weight: 10,
      },
      // Portal page
      {
        type: 'endpoint',
        path: '/global-protect/portal/portal.esp',
        method: 'GET',
        match: 'GlobalProtect|Palo Alto',
        weight: 9,
      },
      // HIP report (CVE-2024-3400 target)
      {
        type: 'endpoint',
        path: '/global-protect/hipreport.esp',
        method: 'GET',
        match: 'Palo Alto|GlobalProtect|hip',
        weight: 9,
      },
      // Static resources for ETag version detection
      {
        type: 'endpoint',
        path: '/global-protect/portal/images/favicon.ico',
        method: 'GET',
        match: '.*',
        weight: 7,
      },
      {
        type: 'endpoint',
        path: '/global-protect/portal/css/login.css',
        method: 'GET',
        match: 'global-protect|gp-portal',
        weight: 8,
      },
      // XML body patterns
      {
        type: 'body',
        path: '/global-protect/prelogin.esp',
        match: '<prelogin-response>|<saml-auth-method>|<authentication-message>',
        weight: 10,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: 'GlobalProtect|Palo Alto Networks|PaloAltoNetworks',
        weight: 9,
      },
      // Certificate
      {
        type: 'certificate',
        match: 'Palo Alto Networks',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Cisco AnyConnect / ASA (2 CISA KEV CVEs)
  // Official Docs: cisco.com/c/en/us/support
  // Version detection: /CSCOSSLC/config-auth XML
  // ============================================================
  {
    vendor: 'cisco',
    product: 'AnyConnect',
    patterns: [
      // Definitive: Version info endpoint
      {
        type: 'endpoint',
        path: '/CSCOSSLC/config-auth',
        method: 'GET',
        match: 'config-auth|version',
        weight: 10,
        versionExtract: /<version who="sg">([^<]+)<\/version>/,
      },
      // Login endpoints
      {
        type: 'endpoint',
        path: '/+CSCOE+/logon.html',
        method: 'GET',
        match: 'webvpn|anyconnect|AnyConnect|csco_',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/+webvpn+/index.html',
        method: 'GET',
        match: 'Cisco|WebVPN|ASA',
        weight: 9,
      },
      // Translation table (CVE-2020-3452 target)
      {
        type: 'endpoint',
        path: '/+CSCOT+/translation-table',
        method: 'GET',
        match: 'translation|cisco',
        weight: 8,
      },
      // Pre-auth content path
      {
        type: 'endpoint',
        path: '/+CSCOU+/',
        method: 'GET',
        match: '.*',
        weight: 7,
      },
      // WebVPN cookies
      {
        type: 'header',
        match: 'webvpnlogin',
        weight: 10,
      },
      {
        type: 'header',
        match: 'webvpn_portal',
        weight: 10,
      },
      {
        type: 'header',
        match: 'webvpncontext',
        weight: 9,
      },
      {
        type: 'header',
        match: 'webvpn_as',
        weight: 9,
      },
      // Protocol headers
      {
        type: 'header',
        match: 'X-Transcend-Version',
        weight: 10,
      },
      {
        type: 'header',
        match: 'X-Aggregate-Auth',
        weight: 9,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: 'csco_ShowLoginForm|/\\+CSCOE\\+/|/\\+CSCOU\\+/',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'SSL VPN Service|Cisco ASA|Cisco Secure Firewall',
        weight: 9,
      },
      // XML patterns
      {
        type: 'body',
        path: '/CSCOSSLC/config-auth',
        match: '<config-auth|<version who=',
        weight: 10,
      },
      // Certificate
      {
        type: 'certificate',
        match: 'Cisco|ASA',
        weight: 6,
      },
    ],
  },

  // ============================================================
  // Pulse Secure (Now Ivanti) - Legacy branding
  // ============================================================
  {
    vendor: 'pulse',
    product: 'Pulse Connect Secure',
    patterns: [
      // Cookie fingerprints (most reliable)
      {
        type: 'header',
        match: 'DSID',
        weight: 10,
      },
      {
        type: 'header',
        match: 'DSBrowserID',
        weight: 10,
      },
      {
        type: 'header',
        match: 'DSSignInURL',
        weight: 10,
      },
      {
        type: 'header',
        match: 'DSLastAccess',
        weight: 9,
      },
      // Login endpoints
      {
        type: 'endpoint',
        path: '/dana-na/auth/url_default/welcome.cgi',
        method: 'GET',
        match: 'Pulse Secure|dana|welcome',
        weight: 10,
        versionExtract: /ProductVersion"\s+VALUE="([0-9.]+)"/,
      },
      {
        type: 'endpoint',
        path: '/dana-na/auth/url_admin/welcome.cgi',
        method: 'GET',
        match: 'dana|admin',
        weight: 9,
        versionExtract: /ProductVersion"\s+VALUE="([0-9.]+)"/,
      },
      // SAML endpoints (CVE-2024-21893 targets)
      {
        type: 'endpoint',
        path: '/dana-ws/saml20.ws',
        method: 'GET',
        match: 'saml|dana',
        weight: 8,
      },
      {
        type: 'endpoint',
        path: '/dana-na/auth/saml-sso.cgi',
        method: 'GET',
        match: 'saml',
        weight: 8,
      },
      // Host Checker (version detection)
      {
        type: 'endpoint',
        path: '/dana-cached/hc/HostCheckerInstaller.osx',
        method: 'HEAD',
        match: '.*',
        weight: 7,
        versionExtract: /<string>([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)<\/string>/,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: '/dana-na/|/dana-cached/|Pulse Secure',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'PulseSecure_Host_Checker|danaparams|xsauth_token',
        weight: 9,
      },
      // Certificate
      {
        type: 'certificate',
        match: 'Pulse Secure|Ivanti',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Ivanti Connect Secure (4 CISA KEV CVEs)
  // Official Docs: forums.ivanti.com/s/documentation
  // Version format: XX.YRZ.W (e.g., 22.7R2.7)
  // ============================================================
  {
    vendor: 'ivanti',
    product: 'Connect Secure',
    patterns: [
      // Cookie fingerprints (most reliable)
      {
        type: 'header',
        match: 'DSID',
        weight: 10,
      },
      {
        type: 'header',
        match: 'DSBrowserID',
        weight: 10,
      },
      {
        type: 'header',
        match: 'DSSignInURL',
        weight: 10,
      },
      {
        type: 'header',
        match: 'DSLastAccess',
        weight: 9,
      },
      // Login endpoints
      {
        type: 'endpoint',
        path: '/dana-na/auth/url_default/welcome.cgi',
        method: 'GET',
        match: 'Ivanti|Connect Secure|dana',
        weight: 10,
        versionExtract: /ProductVersion"\s+VALUE="([0-9.]+)"/,
      },
      {
        type: 'endpoint',
        path: '/dana-na/auth/url_admin/welcome.cgi?type=inter',
        method: 'GET',
        match: 'Ivanti|dana',
        weight: 9,
        versionExtract: /ProductVersion"\s+VALUE="([0-9.]+)"/,
      },
      // REST API (CVE-2024-21887 target)
      {
        type: 'endpoint',
        path: '/api/v1/totp/user-backup-code',
        method: 'GET',
        match: 'Ivanti|totp',
        weight: 8,
      },
      {
        type: 'endpoint',
        path: '/api/v1/license/keys-status',
        method: 'GET',
        match: 'license|keys',
        weight: 8,
      },
      // SAML endpoints (CVE-2024-21893 SSRF targets)
      {
        type: 'endpoint',
        path: '/dana-ws/saml20.ws',
        method: 'GET',
        match: 'saml',
        weight: 8,
      },
      {
        type: 'endpoint',
        path: '/dana-na/auth/saml-logout.cgi',
        method: 'GET',
        match: 'saml',
        weight: 8,
      },
      // Host Checker (version in binary)
      {
        type: 'endpoint',
        path: '/dana-cached/hc/HostCheckerInstaller.osx',
        method: 'HEAD',
        match: '.*',
        weight: 7,
        versionExtract: /<string>([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)<\/string>/,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: '/dana-na/|Ivanti Connect Secure',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: '/dana-cached/|danaparams',
        weight: 9,
      },
      // Certificate
      {
        type: 'certificate',
        match: 'Ivanti',
        weight: 8,
      },
    ],
  },

  // ============================================================
  // Citrix Gateway / NetScaler (3 CISA KEV CVEs)
  // Official Docs: docs.citrix.com
  // Version detection: ?v=<MD5hash> in HTML (fox-it/citrix-netscaler-triage)
  // ============================================================
  {
    vendor: 'citrix',
    product: 'Citrix Gateway',
    patterns: [
      // NSC_ cookies (most reliable)
      {
        type: 'header',
        match: 'NSC_AAAC',
        weight: 10,
      },
      {
        type: 'header',
        match: 'NSC_TMAS',
        weight: 10,
      },
      {
        type: 'header',
        match: 'NSC_TMAA',
        weight: 10,
      },
      {
        type: 'header',
        match: 'NSC_',
        weight: 9,
      },
      // Login pages
      {
        type: 'endpoint',
        path: '/vpn/index.html',
        method: 'GET',
        match: 'Citrix|NetScaler|nsg-',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/logon/LogonPoint/index.html',
        method: 'GET',
        match: 'Citrix|logon/LogonPoint',
        weight: 10,
      },
      // Plugin version info
      {
        type: 'endpoint',
        path: '/vpn/pluginlist.xml',
        method: 'GET',
        match: 'plugin|version|Netscaler',
        weight: 9,
        versionExtract: /version="([^"]+)"/,
      },
      // EPA endpoints
      {
        type: 'endpoint',
        path: '/epa/scripts/win/nsepa_setup.exe',
        method: 'HEAD',
        match: '.*',
        weight: 8,
      },
      {
        type: 'endpoint',
        path: '/epa/epa.html',
        method: 'GET',
        match: 'epa|Citrix',
        weight: 8,
      },
      // HTML patterns (includes version hash)
      {
        type: 'body',
        path: '/vpn/index.html',
        match: '\\?v=[a-f0-9]{32}',
        weight: 9,
      },
      {
        type: 'body',
        path: '/',
        match: 'Citrix Gateway|NetScaler Gateway|NetScaler AAA',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: '/vpn/images/AccessGateway\\.ico|frame-busting',
        weight: 8,
      },
      // Certificate
      {
        type: 'certificate',
        match: 'Citrix|NetScaler',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // SonicWall (1 CISA KEV CVE)
  // Official Docs: psirt.global.sonicwall.com
  // Products: SMA 100 Series, SMA 1000 Series
  // ============================================================
  {
    vendor: 'sonicwall',
    product: 'SMA',
    patterns: [
      // Server header (most reliable, version extractable for SMA 1000)
      {
        type: 'header',
        match: 'Server: SonicWALL',
        weight: 10,
      },
      {
        type: 'header',
        match: 'Server: SMA/',
        weight: 10,
        versionExtract: /SMA\/(\d+\.\d+(?:\.\d+)?)/,
      },
      {
        type: 'header',
        match: 'Server: SonicWALL SSL-VPN Web Server',
        weight: 10,
      },
      // CGI endpoints
      {
        type: 'endpoint',
        path: '/cgi-bin/welcome',
        method: 'GET',
        match: 'SonicWall|SonicWALL|NetExtender',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/cgi-bin/userLogin',
        method: 'POST',
        match: 'SonicWall|sslvpn|userLogin',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/cgi-bin/supportLogin',
        method: 'GET',
        match: 'SonicWall|support',
        weight: 8,
      },
      // REST API
      {
        type: 'endpoint',
        path: '/__api__/v1/logon',
        method: 'GET',
        match: 'api|logon',
        weight: 8,
      },
      // SonicOS 7.x login
      {
        type: 'endpoint',
        path: '/sonicui/7/login/',
        method: 'GET',
        match: 'sonicui|login',
        weight: 9,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: 'login_box_sonicwall|Virtual Office|NetExtender',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'SonicWall SSL VPN|SonicWALL Secure Access',
        weight: 9,
      },
      {
        type: 'body',
        path: '/',
        match: 'WorkPlace|Appliance Management Console',
        weight: 9,
      },
      // Version extraction
      {
        type: 'body',
        path: '/',
        match: 'SonicWall|SonicWALL',
        weight: 8,
        versionExtract: /(\d+\.\d+\.\d+\.\d+)-(\d+)sv/,
      },
      {
        type: 'certificate',
        match: 'SonicWall|SonicWALL',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Check Point
  // ============================================================
  {
    vendor: 'checkpoint',
    product: 'Mobile Access',
    patterns: [
      {
        type: 'endpoint',
        path: '/sslvpn/Login/Login',
        method: 'GET',
        match: 'Check Point|checkpoint',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/sslvpn/SNX/EXTENDER',
        method: 'GET',
        match: 'SNX|Check Point',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Check Point|cpws',
        weight: 10,
      },
      {
        type: 'certificate',
        match: 'Check Point',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // OpenVPN Access Server
  // ============================================================
  {
    vendor: 'openvpn',
    product: 'Access Server',
    patterns: [
      {
        type: 'endpoint',
        path: '/__session_start__/',
        method: 'GET',
        match: 'OpenVPN|openvpn',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/admin',
        method: 'GET',
        match: 'OpenVPN Access Server',
        weight: 9,
      },
      {
        type: 'header',
        match: 'openvpn',
        weight: 8,
      },
      {
        type: 'body',
        path: '/',
        match: 'OpenVPN Access Server|openvpn-as',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'OpenVPN',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // F5 BIG-IP APM (3 CISA KEV CVEs)
  // Official Docs: my.f5.com, techdocs.f5.com
  // ============================================================
  {
    vendor: 'f5',
    product: 'BIG-IP APM',
    patterns: [
      // Server header
      {
        type: 'header',
        match: 'Server: BigIP',
        weight: 10,
      },
      // APM session cookies (most reliable, 32-char hex)
      {
        type: 'header',
        match: 'MRHSession',
        weight: 10,
      },
      {
        type: 'header',
        match: 'LastMRH_Session',
        weight: 10,
      },
      {
        type: 'header',
        match: 'MRHSHint',
        weight: 9,
      },
      // LTM persistence cookie (can leak internal IP)
      {
        type: 'header',
        match: 'BIGipServer',
        weight: 10,
      },
      // APM endpoints
      {
        type: 'endpoint',
        path: '/my.policy',
        method: 'GET',
        match: 'F5|BIG-IP|Access Policy|302',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/vdesk/webtop.eui',
        method: 'GET',
        match: 'webtop|vdesk',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/vdesk/index.php3',
        method: 'GET',
        match: 'F5|BIG-IP|APM',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/public/include/js/agent_common.js',
        method: 'GET',
        match: 'agent|F5',
        weight: 8,
      },
      // TMUI (CVE-2020-5902 target)
      {
        type: 'endpoint',
        path: '/tmui/login.jsp',
        method: 'GET',
        match: 'tmui|BIG-IP|Configuration Utility',
        weight: 10,
      },
      // iControl REST (CVE-2022-1388 target)
      {
        type: 'endpoint',
        path: '/mgmt/tm/util/bash',
        method: 'GET',
        match: 'mgmt|bash',
        weight: 8,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: 'apmui/page/logon|f5-w-|F5_ST=',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'F5 Networks|BIG-IP|/vdesk/',
        weight: 9,
      },
      {
        type: 'body',
        path: '/',
        match: '<title>BIG-IP',
        weight: 10,
      },
      {
        type: 'certificate',
        match: 'F5 Networks|BIG-IP',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Juniper SRX / Junos (2 CISA KEV CVEs)
  // Official Docs: supportportal.juniper.net
  // J-Web: PHP-based, GoAhead httpd
  // ============================================================
  {
    vendor: 'juniper',
    product: 'SRX SSL VPN',
    patterns: [
      // J-Web title (most reliable)
      {
        type: 'body',
        path: '/',
        match: 'Log In - Juniper Web Device Manager|Juniper Web Device Manager',
        weight: 10,
      },
      // Dynamic VPN portal
      {
        type: 'endpoint',
        path: '/dynamic-vpn',
        method: 'GET',
        match: 'Dynamic VPN|Juniper|download',
        weight: 10,
      },
      // Vulnerable endpoints (CVE-2023-36844/45/46/47)
      {
        type: 'endpoint',
        path: '/webauth_operation.php',
        method: 'GET',
        match: 'webauth|php',
        weight: 9,
      },
      // CVE-2022-22241 Phar deserialization
      {
        type: 'endpoint',
        path: '/jsdm/ajax/logging_browse.php',
        method: 'GET',
        match: 'logging|jsdm',
        weight: 8,
      },
      // Error page (CVE-2022-22242 XSS)
      {
        type: 'endpoint',
        path: '/error.php',
        method: 'GET',
        match: 'error|Juniper',
        weight: 7,
      },
      // Dana endpoints (legacy Juniper Pulse)
      {
        type: 'endpoint',
        path: '/dana-na/',
        method: 'GET',
        match: 'Juniper|Junos|SRX|dana',
        weight: 9,
      },
      {
        type: 'endpoint',
        path: '/login/login.cgi',
        method: 'GET',
        match: 'Juniper|SRX|Dynamic VPN',
        weight: 10,
      },
      // Headers
      {
        type: 'header',
        match: 'Juniper',
        weight: 10,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: 'Juniper Networks|J-Web|junos',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Juniper',
        weight: 8,
      },
      // Favicon hash (Shodan: 2141724739)
      {
        type: 'favicon',
        path: '/favicon.ico',
        match: '2141724739',
        weight: 9,
      },
    ],
  },

  // ============================================================
  // Zyxel USG / ZyWALL / ATP / USG FLEX (2 CISA KEV CVEs)
  // Official Docs: www.zyxel.com/support
  // ZLD Firmware, ExtJS-based UI
  // ============================================================
  {
    vendor: 'zyxel',
    product: 'USG/ZyWALL',
    patterns: [
      // Product names in title (most reliable)
      {
        type: 'body',
        path: '/',
        match: '<title>(USG FLEX|ATP\\d+|VPN\\d+|ZyWALL)',
        weight: 10,
      },
      // Zyxel-specific JavaScript (high confidence)
      {
        type: 'body',
        path: '/',
        match: 'zyFunction\\.js',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'zld_product_spec',
        weight: 9,
      },
      // ExtJS Zyxel app
      {
        type: 'body',
        path: '/',
        match: 'Ext\\.create.*Zyxel',
        weight: 9,
      },
      // Version info endpoint
      {
        type: 'endpoint',
        path: '/zld_product_spec.js',
        method: 'GET',
        match: 'ZLD|version|product',
        weight: 9,
        versionExtract: /ZLD\s*V?(\d+\.\d+)/i,
      },
      // ZTP endpoints (CVE-2023-33012 target)
      {
        type: 'endpoint',
        path: '/ztp/cgi-bin/parse_config.py',
        method: 'GET',
        match: 'ParseError|0xC0DE',
        weight: 8,
      },
      {
        type: 'endpoint',
        path: '/ztp/cgi-bin/dumpztplog.py',
        method: 'GET',
        match: 'ztp|log',
        weight: 8,
      },
      // CGI endpoints
      {
        type: 'endpoint',
        path: '/weblogin.cgi',
        method: 'GET',
        match: 'ZyXEL|Zyxel|ZyWALL|USG',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/cgi-bin/dispatcher.cgi',
        method: 'GET',
        match: 'Zyxel|dispatcher',
        weight: 9,
      },
      // Cookie
      {
        type: 'header',
        match: 'authtok',
        weight: 9,
      },
      // Headers
      {
        type: 'header',
        match: 'ZyXEL|Zyxel',
        weight: 10,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: 'ZyXEL|Zyxel|ZyWALL|USG FLEX|ATP\\d+',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'ZyXEL|Zyxel',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Sophos XG Firewall / SFOS (2 CISA KEV CVEs)
  // Official Docs: docs.sophos.com
  // SFOS: User Portal (443/4443), WebAdmin (4444), VPN Portal (443)
  // ============================================================
  {
    vendor: 'sophos',
    product: 'XG Firewall',
    patterns: [
      // User Portal JavaScript (most reliable)
      {
        type: 'body',
        path: '/',
        match: 'UserPortalLogin\\.js',
        weight: 10,
      },
      // Noscript messages (high confidence)
      {
        type: 'body',
        path: '/',
        match: 'Without JavaScript support user portal will not work',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Without JavaScript support web console will not work',
        weight: 10,
      },
      // User Portal endpoints
      {
        type: 'endpoint',
        path: '/userportal/webpages/myaccount/login.jsp',
        method: 'GET',
        match: 'Sophos|XG|UTM|userportal',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/userportal/Controller',
        method: 'GET',
        match: 'Controller|mode=451',
        weight: 9,
      },
      // WebAdmin Console (port 4444)
      {
        type: 'endpoint',
        path: '/webconsole/webpages/login.jsp',
        method: 'GET',
        match: 'Sophos|XG Firewall|webconsole',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/webconsole/Controller',
        method: 'GET',
        match: 'Controller|mode=151',
        weight: 9,
      },
      // VPN Portal (SFOS 20.0+)
      {
        type: 'endpoint',
        path: '/vpnportal/',
        method: 'GET',
        match: 'VPN|Sophos|portal',
        weight: 9,
      },
      // Legacy Cyberoam patterns
      {
        type: 'body',
        path: '/',
        match: 'Cyberoam\\.c\\$rFt0k3n',
        weight: 9,
      },
      // HTML title
      {
        type: 'body',
        path: '/',
        match: '<title>Sophos</title>',
        weight: 9,
      },
      // HTML body patterns
      {
        type: 'body',
        path: '/',
        match: 'Sophos|XG Firewall|Cyberoam|sfos|sophos-firewall',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Sophos',
        weight: 10,
      },
      {
        type: 'certificate',
        match: 'Sophos',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // WatchGuard Firebox SSL VPN
  // ============================================================
  {
    vendor: 'watchguard',
    product: 'Firebox',
    patterns: [
      {
        type: 'endpoint',
        path: '/sslvpn_logon.shtml',
        method: 'GET',
        match: 'WatchGuard|Firebox|SSL VPN',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/auth/login',
        method: 'GET',
        match: 'WatchGuard|Firebox',
        weight: 9,
      },
      {
        type: 'endpoint',
        path: '/wgcgi.cgi',
        method: 'GET',
        match: 'WatchGuard',
        weight: 8,
      },
      {
        type: 'header',
        match: 'WatchGuard',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'WatchGuard|Firebox|XTM|Fireware',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'WatchGuard',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Barracuda CloudGen / SSL VPN
  // ============================================================
  {
    vendor: 'barracuda',
    product: 'CloudGen Firewall',
    patterns: [
      {
        type: 'endpoint',
        path: '/cgi-mod/index.cgi',
        method: 'GET',
        match: 'Barracuda|CloudGen|NG Firewall',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/cgi-bin/index.cgi',
        method: 'GET',
        match: 'Barracuda|SSL VPN',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Barracuda',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Barracuda Networks|CloudGen|NextGen',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Barracuda',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Sangfor SSL VPN (Popular in Asia)
  // ============================================================
  {
    vendor: 'sangfor',
    product: 'SSL VPN',
    patterns: [
      {
        type: 'endpoint',
        path: '/por/login_auth.csp',
        method: 'GET',
        match: 'Sangfor|SANGFOR|SSL VPN',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/svpn_html/login/login.html',
        method: 'GET',
        match: 'Sangfor|SANGFOR',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/sslvpn/sslvpn.html',
        method: 'GET',
        match: 'Sangfor|SANGFOR',
        weight: 9,
      },
      {
        type: 'header',
        match: 'SANGFOR|Sangfor',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'SANGFOR|Sangfor|深信服',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Sangfor|SANGFOR',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Array Networks SSL VPN
  // ============================================================
  {
    vendor: 'array',
    product: 'AG Series',
    patterns: [
      {
        type: 'endpoint',
        path: '/prx/000/http/localhost/login',
        method: 'GET',
        match: 'Array Networks|ArrayOS',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/portal/portal.html',
        method: 'GET',
        match: 'Array|AG Series|APV',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Array',
        weight: 8,
      },
      {
        type: 'body',
        path: '/',
        match: 'Array Networks|ArrayOS|MotionPro',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Array Networks',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // NetMotion Mobility (Enterprise mobility)
  // ============================================================
  {
    vendor: 'netmotion',
    product: 'Mobility',
    patterns: [
      {
        type: 'endpoint',
        path: '/mobility/',
        method: 'GET',
        match: 'NetMotion|Mobility',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/nmclient/',
        method: 'GET',
        match: 'NetMotion|Mobility',
        weight: 9,
      },
      {
        type: 'header',
        match: 'NetMotion',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'NetMotion|Mobility XE|Absolute',
        weight: 8,
      },
      {
        type: 'certificate',
        match: 'NetMotion|Absolute',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Hillstone Networks SSL VPN
  // ============================================================
  {
    vendor: 'hillstone',
    product: 'NGFW',
    patterns: [
      {
        type: 'endpoint',
        path: '/login.html',
        method: 'GET',
        match: 'Hillstone|NGFW',
        weight: 9,
      },
      {
        type: 'endpoint',
        path: '/sslvpn/',
        method: 'GET',
        match: 'Hillstone|山石网科',
        weight: 10,
      },
      {
        type: 'header',
        match: 'Hillstone',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Hillstone Networks|Hillstone NGFW|山石网科',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Hillstone',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Huawei USG / SecoManager
  // ============================================================
  {
    vendor: 'huawei',
    product: 'USG',
    patterns: [
      {
        type: 'endpoint',
        path: '/view/pages/login.html',
        method: 'GET',
        match: 'Huawei|HUAWEI|USG|SecoManager',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/webui/',
        method: 'GET',
        match: 'Huawei|USG|华为',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Huawei|HUAWEI',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Huawei Technologies|USG6000|华为',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Huawei',
        weight: 8,
      },
    ],
  },

  // ============================================================
  // H3C SecPath
  // ============================================================
  {
    vendor: 'h3c',
    product: 'SecPath',
    patterns: [
      {
        type: 'endpoint',
        path: '/wnm/ssl/web/frame/login.php',
        method: 'GET',
        match: 'H3C|SecPath',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/login.html',
        method: 'GET',
        match: 'H3C|新华三',
        weight: 9,
      },
      {
        type: 'header',
        match: 'H3C',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'H3C Technologies|SecPath|新华三',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'H3C',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // DrayTek Vigor
  // ============================================================
  {
    vendor: 'draytek',
    product: 'Vigor',
    patterns: [
      {
        type: 'endpoint',
        path: '/weblogin.htm',
        method: 'GET',
        match: 'DrayTek|Vigor',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/doc/login.shtml',
        method: 'GET',
        match: 'DrayTek|Vigor',
        weight: 9,
      },
      {
        type: 'header',
        match: 'DrayTek',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'DrayTek|Vigor|VigorConnect',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'DrayTek',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // MikroTik RouterOS
  // ============================================================
  {
    vendor: 'mikrotik',
    product: 'RouterOS',
    patterns: [
      {
        type: 'endpoint',
        path: '/webfig/',
        method: 'GET',
        match: 'MikroTik|RouterOS|webfig',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/winbox/',
        method: 'GET',
        match: 'MikroTik|winbox',
        weight: 9,
      },
      {
        type: 'header',
        match: 'MikroTik',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'MikroTik|RouterOS|RouterBOARD',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'MikroTik',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Ubiquiti UniFi
  // ============================================================
  {
    vendor: 'ubiquiti',
    product: 'UniFi',
    patterns: [
      {
        type: 'endpoint',
        path: '/manage/account/login',
        method: 'GET',
        match: 'Ubiquiti|UniFi|UI.com',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/login',
        method: 'GET',
        match: 'UniFi Network|UniFi OS',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Ubiquiti|UniFi',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Ubiquiti|UniFi|Dream Machine|EdgeRouter',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Ubiquiti|UniFi',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // pfSense
  // ============================================================
  {
    vendor: 'pfsense',
    product: 'pfSense',
    patterns: [
      {
        type: 'endpoint',
        path: '/index.php',
        method: 'GET',
        match: 'pfSense|pfsense',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/wizard.php',
        method: 'GET',
        match: 'pfSense',
        weight: 8,
      },
      {
        type: 'body',
        path: '/',
        match: 'pfSense|Netgate|FreeBSD',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'pfSense|Netgate',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // OPNsense
  // ============================================================
  {
    vendor: 'opnsense',
    product: 'OPNsense',
    patterns: [
      {
        type: 'endpoint',
        path: '/ui/core/login',
        method: 'GET',
        match: 'OPNsense',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/api/core/firmware/status',
        method: 'GET',
        match: 'OPNsense|opnsense',
        weight: 9,
      },
      {
        type: 'body',
        path: '/',
        match: 'OPNsense|Deciso',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'OPNsense',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // NETGEAR ProSAFE
  // ============================================================
  {
    vendor: 'netgear',
    product: 'ProSAFE',
    patterns: [
      {
        type: 'endpoint',
        path: '/cgi-bin/login.cgi',
        method: 'GET',
        match: 'NETGEAR|ProSAFE|ProSecure',
        weight: 10,
      },
      {
        type: 'header',
        match: 'NETGEAR',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'NETGEAR|ProSAFE|Orbi',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'NETGEAR',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // TP-Link Omada
  // ============================================================
  {
    vendor: 'tplink',
    product: 'Omada',
    patterns: [
      {
        type: 'endpoint',
        path: '/login',
        method: 'GET',
        match: 'TP-Link|TP-LINK|Omada',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/webpages/login.html',
        method: 'GET',
        match: 'TP-Link|TP-LINK',
        weight: 9,
      },
      {
        type: 'header',
        match: 'TP-Link|TP-LINK',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'TP-Link|TP-LINK|Omada|SafeStream',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'TP-Link|TP-LINK',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Stormshield (French)
  // ============================================================
  {
    vendor: 'stormshield',
    product: 'SNS',
    patterns: [
      {
        type: 'endpoint',
        path: '/auth/admin.html',
        method: 'GET',
        match: 'Stormshield|SNS',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/auth/login.html',
        method: 'GET',
        match: 'Stormshield|Network Security',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Stormshield',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Stormshield|Arkoon|Netasq',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Stormshield',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // LANCOM (German)
  // ============================================================
  {
    vendor: 'lancom',
    product: 'LANCOM',
    patterns: [
      {
        type: 'endpoint',
        path: '/config/',
        method: 'GET',
        match: 'LANCOM|lancom',
        weight: 10,
      },
      {
        type: 'header',
        match: 'LANCOM',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'LANCOM Systems|LANCOM VPN',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'LANCOM',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Kerio Control
  // ============================================================
  {
    vendor: 'kerio',
    product: 'Kerio Control',
    patterns: [
      {
        type: 'endpoint',
        path: '/internal/admin/',
        method: 'GET',
        match: 'Kerio|kerio',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/nonauth/login.php',
        method: 'GET',
        match: 'Kerio Control|GFI',
        weight: 9,
      },
      {
        type: 'body',
        path: '/',
        match: 'Kerio Control|Kerio VPN|GFI Software',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Kerio|GFI',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Untangle / Arista Edge Threat Management
  // ============================================================
  {
    vendor: 'untangle',
    product: 'NG Firewall',
    patterns: [
      {
        type: 'endpoint',
        path: '/auth/login',
        method: 'GET',
        match: 'Untangle|Arista|Edge Threat',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/admin/index.do',
        method: 'GET',
        match: 'Untangle|NG Firewall',
        weight: 9,
      },
      {
        type: 'body',
        path: '/',
        match: 'Untangle|Arista Edge|NG Firewall',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Untangle|Arista',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Endian UTM (Italian)
  // ============================================================
  {
    vendor: 'endian',
    product: 'Endian UTM',
    patterns: [
      {
        type: 'endpoint',
        path: '/cgi-bin/index.cgi',
        method: 'GET',
        match: 'Endian|endian',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/login/',
        method: 'GET',
        match: 'Endian Firewall|Endian UTM',
        weight: 9,
      },
      {
        type: 'body',
        path: '/',
        match: 'Endian|Endian Firewall|Endian UTM',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Endian',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Ruijie (China)
  // ============================================================
  {
    vendor: 'ruijie',
    product: 'RG Series',
    patterns: [
      {
        type: 'endpoint',
        path: '/login.htm',
        method: 'GET',
        match: 'Ruijie|锐捷',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/cgi-bin/login.cgi',
        method: 'GET',
        match: 'Ruijie|RG-',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Ruijie',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Ruijie Networks|锐捷网络',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Ruijie',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // NSFOCUS (China)
  // ============================================================
  {
    vendor: 'nsfocus',
    product: 'NSFOCUS',
    patterns: [
      {
        type: 'endpoint',
        path: '/login/',
        method: 'GET',
        match: 'NSFOCUS|绿盟',
        weight: 10,
      },
      {
        type: 'header',
        match: 'NSFOCUS',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'NSFOCUS|绿盟科技|NF',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'NSFOCUS',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Venustech (China)
  // ============================================================
  {
    vendor: 'venustech',
    product: 'Venusense',
    patterns: [
      {
        type: 'endpoint',
        path: '/webui/',
        method: 'GET',
        match: 'Venustech|启明星辰|Venusense',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Venustech|启明星辰|Venus',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Venustech|Venus',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // TopSec (China)
  // ============================================================
  {
    vendor: 'topsec',
    product: 'TopSec',
    patterns: [
      {
        type: 'endpoint',
        path: '/id/login.php',
        method: 'GET',
        match: 'TopSec|天融信',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'TopSec|天融信|TOPSEC',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'TopSec|天融信',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // DPtech (China)
  // ============================================================
  {
    vendor: 'dptech',
    product: 'DPtech',
    patterns: [
      {
        type: 'endpoint',
        path: '/login/',
        method: 'GET',
        match: 'DPtech|迪普',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'DPtech|迪普科技|DP',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'DPtech',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // AhnLab (Korea)
  // ============================================================
  {
    vendor: 'ahnlab',
    product: 'TrusGuard',
    patterns: [
      {
        type: 'endpoint',
        path: '/webui/login',
        method: 'GET',
        match: 'AhnLab|TrusGuard|안랩',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'AhnLab|TrusGuard|안랩',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'AhnLab',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // SECUI (Korea)
  // ============================================================
  {
    vendor: 'secui',
    product: 'MF2',
    patterns: [
      {
        type: 'endpoint',
        path: '/login.html',
        method: 'GET',
        match: 'SECUI|시큐아이',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'SECUI|MF2|시큐아이',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'SECUI',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Cisco Meraki
  // ============================================================
  {
    vendor: 'meraki',
    product: 'MX',
    patterns: [
      {
        type: 'endpoint',
        path: '/login/login',
        method: 'GET',
        match: 'Meraki|meraki',
        weight: 10,
      },
      {
        type: 'header',
        match: 'Meraki',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Meraki|Cisco Meraki|Dashboard',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Meraki',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Aruba (HPE)
  // ============================================================
  {
    vendor: 'aruba',
    product: 'ClearPass',
    patterns: [
      {
        type: 'endpoint',
        path: '/tips/tipsLogin.action',
        method: 'GET',
        match: 'Aruba|ClearPass',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/guest/captive_portal.php',
        method: 'GET',
        match: 'Aruba|VIA',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Aruba',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Aruba Networks|ClearPass|Aruba VIA|HPE Aruba',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Aruba|HPE',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Zscaler (Cloud but has detectable endpoints)
  // ============================================================
  {
    vendor: 'zscaler',
    product: 'ZPA',
    patterns: [
      {
        type: 'endpoint',
        path: '/signin',
        method: 'GET',
        match: 'Zscaler|zscaler',
        weight: 10,
      },
      {
        type: 'header',
        match: 'Zscaler',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Zscaler|ZPA|ZIA',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Zscaler',
        weight: 8,
      },
    ],
  },

  // ============================================================
  // Cloudflare Access
  // ============================================================
  {
    vendor: 'cloudflare',
    product: 'Access',
    patterns: [
      {
        type: 'header',
        match: 'CF-Access|cloudflare',
        weight: 10,
      },
      {
        type: 'header',
        match: 'cf-ray',
        weight: 6,
      },
      {
        type: 'body',
        path: '/',
        match: 'Cloudflare Access|cloudflareaccess',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Cloudflare',
        weight: 7,
      },
    ],
  },
];

export function getFingerprintsByVendor(vendor: string): Fingerprint[] {
  return fingerprints.filter(f => f.vendor === vendor);
}

export function getAllVendors(): string[] {
  return [...new Set(fingerprints.map(f => f.vendor))];
}
