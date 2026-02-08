/**
 * Tier 1 Enterprise (16 CISA KEV CVEs)
 */

import type { Fingerprint } from '../types.js';

export const tier1enterpriseFingerprints: Fingerprint[] = [
  // ============================================================
  // Fortinet FortiGate (5 CISA KEV CVEs)
  // Deep research: Bishop Fox, Shadowserver, Nuclei templates
  // Detection: ~490K SSL VPN interfaces on Shodan
  // Version: ETag/Last-Modified timestamp, CSS/JS hash mapping
  // ============================================================
  {
    vendor: 'fortinet',
    product: 'FortiGate',
    patterns: [
      // === TIER 1: Highest Confidence ===

      // Server header - FortiOS unique masked pattern (most reliable)
      {
        type: 'header',
        match: 'Server: xxxxxxxx-xxxxx',
        weight: 10,
      },
      // SSL VPN session cookies (definitive proof of FortiOS SSL VPN)
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
      // JS redirect to SSL VPN login (Bishop Fox primary detection)
      {
        type: 'body',
        path: '/',
        match: 'top\\.location="/remote/login"',
        weight: 10,
      },
      // JS redirect to admin login
      {
        type: 'body',
        path: '/',
        match: 'top\\.location="/login"',
        weight: 9,
      },

      // === TIER 2: SSL VPN Endpoints (pre-auth) ===

      // SSL VPN login page (may contain version in hidden fields or JS)
      {
        type: 'endpoint',
        path: '/remote/login',
        method: 'GET',
        match: 'FortiToken|fortinet|fgt_lang|sslvpn|realm',
        weight: 10,
        versionExtract: /FortiOS\s+v?(\d+\.\d+\.\d+)/i,
      },
      // SSL VPN auth check (CVE-2023-27997 XORtigate target)
      {
        type: 'endpoint',
        path: '/remote/logincheck',
        method: 'GET',
        match: 'remote|login',
        weight: 8,
      },
      // Host check validation (CVE-2023-27997, CVE-2024-21762 target)
      {
        type: 'endpoint',
        path: '/remote/hostcheck_validate',
        method: 'GET',
        match: 'hostcheck|validate',
        weight: 8,
      },
      // Language file (CVE-2018-13379 path traversal target)
      // May contain version hints in JSON metadata
      {
        type: 'endpoint',
        path: '/remote/fgt_lang?lang=en',
        method: 'GET',
        match: '"msg"\\s*:',
        weight: 9,
        versionExtract: /"build"\s*:\s*"(\d+)"/,
      },
      // Language file JS variant
      {
        type: 'endpoint',
        path: '/remote/fgt_lang.js',
        method: 'GET',
        match: 'msg|lang',
        weight: 8,
      },
      // SSL VPN error page
      {
        type: 'endpoint',
        path: '/remote/error',
        method: 'GET',
        match: 'remote|error|FortiGate',
        weight: 7,
      },
      // SAML SSO (FortiOS 7.x only)
      {
        type: 'endpoint',
        path: '/remote/saml/start',
        method: 'GET',
        match: 'saml|redirect',
        weight: 8,
      },

      // === TIER 3: Admin Interface Endpoints (pre-auth) ===

      // Admin login page
      {
        type: 'endpoint',
        path: '/login',
        method: 'GET',
        match: 'fgt_lang|ftnt-fortinet|NEUTRINO_THEME',
        weight: 10,
      },
      // Angular/Vue SPA (FortiOS 7.x admin UI)
      {
        type: 'endpoint',
        path: '/ng/',
        method: 'GET',
        match: 'ng|angular|app',
        weight: 7,
      },
      // WebSocket CLI (CVE-2024-55591 target - FortiOS 7.x)
      {
        type: 'endpoint',
        path: '/ws/cli',
        method: 'GET',
        match: 'websocket|upgrade|cli',
        weight: 7,
      },

      // === TIER 4: Static Resources & Fingerprinting ===

      // SSL VPN CSS (pre-auth accessible)
      {
        type: 'endpoint',
        path: '/remote/css/sslvpn.css',
        method: 'GET',
        match: 'sslvpn|vpn|fortigate',
        weight: 7,
      },
      // SSL VPN JavaScript (pre-auth accessible)
      {
        type: 'endpoint',
        path: '/remote/js/sslvpn.js',
        method: 'GET',
        match: 'sslvpn|vpn|fortigate',
        weight: 7,
      },
      // Login CSS (version-specific hash for fingerprinting)
      {
        type: 'endpoint',
        path: '/css/login.css',
        method: 'GET',
        match: '.*',
        weight: 5,
      },
      // Favicon (Shodan mmh3: 945408572, -76600061)
      {
        type: 'favicon',
        path: '/favicon.ico',
        match: '945408572|-76600061',
        weight: 8,
      },

      // === TIER 5: HTML Body Patterns ===

      // SSL VPN login body patterns
      {
        type: 'body',
        path: '/remote/login',
        match: 'fgt_lang|fortigate|fgd_icon|sslvpn/js/webvpn',
        weight: 9,
      },
      // Admin login body patterns
      {
        type: 'body',
        path: '/login',
        match: 'fgt_lang|ftnt-fortinet',
        weight: 9,
      },
      // Security headers (FortiOS 7.x adds these - very common across all web servers,
      // kept at weight 1 to avoid false positives on generic sites)
      {
        type: 'header',
        match: 'X-Frame-Options: SAMEORIGIN',
        weight: 1,
      },
      {
        type: 'header',
        match: 'Content-Security-Policy: frame-ancestors',
        weight: 1,
      },

      // === TIER 6: Version Detection ===

      // ETag header (FG-IR-23-224: version info leak)
      // Last 8 hex chars = Unix timestamp of firmware build date
      // Affected: FortiOS 7.4.0-7.4.1, 7.2.0-7.2.5, 7.0.x, 6.4.x
      // Weight 1: ETag is present on virtually all web servers; only useful as supporting signal
      {
        type: 'header',
        match: 'ETag',
        weight: 1,
      },
      // REST API firmware version (requires auth usually)
      {
        type: 'endpoint',
        path: '/api/v2/monitor/system/firmware',
        method: 'GET',
        match: 'current|version',
        weight: 8,
        versionExtract: /"version"\s*:\s*"v?(\d+\.\d+\.\d+)"/,
      },
      // REST API admin endpoint (CVE-2022-40684 target)
      {
        type: 'endpoint',
        path: '/api/v2/cmdb/system/admin/admin',
        method: 'GET',
        match: 'results|status|http_status',
        weight: 7,
      },

      // === TIER 7: Certificate ===

      // Default self-signed cert: O=Fortinet, OU=FortiGate, CN=FGT-<serial>
      // Serial number in CN reveals model: FGT60F=60F, FG100F=100F, FGVM64=VM
      {
        type: 'certificate',
        match: 'FortiGate|Fortinet|FGT-|FGT\\d',
        weight: 8,
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
      // Login endpoints (may contain version in page content)
      {
        type: 'endpoint',
        path: '/+CSCOE+/logon.html',
        method: 'GET',
        match: 'webvpn|anyconnect|AnyConnect|csco_',
        weight: 10,
        versionExtract: /Version\s+(\d+\.\d+(?:\.\d+)?(?:\(\d+\))?)/,
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
      // Protocol headers (X-Transcend-Version contains ASA version)
      {
        type: 'header',
        match: 'X-Transcend-Version',
        weight: 10,
        versionExtract: /X-Transcend-Version:\s*(\d+)/,
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
        versionExtract: /\?v=([a-f0-9]{32})/,
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
      // EPA endpoints (version in Content-Disposition or Last-Modified)
      // GreyNoise Feb 2026: 63K+ residential proxies scanning these paths
      {
        type: 'endpoint',
        path: '/epa/scripts/win/nsepa_setup.exe',
        method: 'HEAD',
        match: '.*',
        weight: 8,
        versionExtract: /nsepa_setup[_-]?(\d+\.\d+\.\d+\.\d+)/,
      },
      // EPA macOS installer (also targeted in scanning campaigns)
      {
        type: 'endpoint',
        path: '/epa/scripts/mac/nsepa_setup.dmg',
        method: 'HEAD',
        match: '.*',
        weight: 8,
        versionExtract: /nsepa_setup[_-]?(\d+\.\d+\.\d+\.\d+)/,
      },
      // EPA Linux installer
      {
        type: 'endpoint',
        path: '/epa/scripts/linux/nsepa_setup.sh',
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
      // NSAPI detection (admin API, can leak version info)
      {
        type: 'endpoint',
        path: '/nitro/v1/config/nsversion',
        method: 'GET',
        match: 'version|NetScaler|Citrix ADC',
        weight: 9,
        versionExtract: /NS(\d+\.\d+).*Build\s+(\d+\.\d+)/,
      },
      // DTLS endpoint (indicates Gateway with DTLS enabled)
      {
        type: 'endpoint',
        path: '/cginfra/https/scripts/ctxnsap.js',
        method: 'GET',
        match: 'CTXS|nsap|dtls',
        weight: 8,
      },
      // HTML patterns (includes version hash - MD5 of build timestamp)
      // Fox-IT/citrix-netscaler-triage maps these hashes to specific versions
      {
        type: 'body',
        path: '/vpn/index.html',
        match: '\\?v=[a-f0-9]{32}',
        weight: 9,
        versionExtract: /\?v=([a-f0-9]{32})/,
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
