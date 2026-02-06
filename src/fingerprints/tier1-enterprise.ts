/**
 * Tier 1 Enterprise (16 CISA KEV CVEs)
 */

import type { Fingerprint } from '../types.js';

export const tier1enterpriseFingerprints: Fingerprint[] = [
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
];
