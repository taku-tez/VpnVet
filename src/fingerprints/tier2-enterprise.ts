/**
 * Tier 2 Enterprise (10 CISA KEV CVEs)
 */

import type { Fingerprint } from '../types.js';

export const tier2enterpriseFingerprints: Fingerprint[] = [
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
        versionExtract: /SonicOS\s+(\d+\.\d+(?:\.\d+)*(?:-\d+[a-z]?)?)/i,
      },
      // SonicOS 7.x API version endpoint
      {
        type: 'endpoint',
        path: '/api/sonicos/version',
        method: 'GET',
        match: 'firmware_version|SonicOS',
        weight: 9,
        versionExtract: /(\d+\.\d+\.\d+(?:\.\d+)*)/,
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
      // Version extraction from main page
      {
        type: 'body',
        path: '/',
        match: 'SonicWall|SonicWALL',
        weight: 8,
        versionExtract: /(\d+\.\d+\.\d+\.\d+)-(\d+)sv/,
      },
      // SSLVPN firmware version from login page JS
      {
        type: 'endpoint',
        path: '/cgi-bin/sslvpnclient',
        method: 'GET',
        match: 'SonicWall|sslvpn|firmware',
        weight: 9,
        versionExtract: /firmwareVersion['":\s]*['"]([\d.]+)['"]/,
      },
      // SonicWall cookie-based detection (swap cookie)
      {
        type: 'header',
        match: 'Set-Cookie: swap=',
        weight: 7,
      },
      {
        type: 'certificate',
        match: 'SonicWall|SonicWALL',
        weight: 7,
      },
    ],
  },
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
        versionExtract: /Check\s*Point.*?(?:R|Version\s*)(\d+(?:\.\d+)*)/i,
      },
      {
        type: 'endpoint',
        path: '/sslvpn/SNX/EXTENDER',
        method: 'GET',
        match: 'SNX|Check Point',
        weight: 9,
        versionExtract: /SNX\s+(?:build\s+)?(\d+)/i,
      },
      {
        type: 'header',
        match: 'Check Point|cpws',
        weight: 10,
      },
      // Check Point SmartPortal
      {
        type: 'endpoint',
        path: '/UserCheck/wa498247.js',
        method: 'GET',
        match: 'Check Point|UserCheck',
        weight: 8,
      },
      {
        type: 'body',
        path: '/',
        match: 'Check Point|checkpoint\\.com|SmartPortal|Mobile Access',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Check Point',
        weight: 7,
      },
    ],
  },
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
        versionExtract: /Access\s+Server\s+(\d+\.\d+(?:\.\d+)*)/i,
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
      {
        type: 'endpoint',
        path: '/api/status/0',
        method: 'GET',
        match: 'openvpn|ovpn_status',
        weight: 8,
        versionExtract: /\"version\"\s*:\s*\"(\d+\.\d+(?:\.\d+)*)\"/i,
      },
      {
        type: 'endpoint',
        path: '/rest/GetUserlogin',
        method: 'GET',
        match: 'openvpn',
        weight: 7,
      },
      {
        type: 'body',
        path: '/__session_start__/',
        match: 'ovpnc|openvpn_client',
        weight: 6,
      },
    ],
  },
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
      // TMUI (CVE-2020-5902 target) - version in page title or body
      {
        type: 'endpoint',
        path: '/tmui/login.jsp',
        method: 'GET',
        match: 'tmui|BIG-IP|Configuration Utility',
        weight: 10,
        versionExtract: /BIG-IP\s*(?:APM)?\s*(\d+\.\d+\.\d+(?:\.\d+)?)/i,
      },
      // iControl REST version endpoint
      {
        type: 'endpoint',
        path: '/mgmt/tm/sys/version',
        method: 'GET',
        match: 'Version|Build',
        weight: 9,
        versionExtract: /"version"\s*:\s*"(\d+\.\d+\.\d+(?:\.\d+)?)"/,
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
      // Junos version from login page or J-Web
      {
        type: 'body',
        path: '/',
        match: 'Junos|JUNOS',
        weight: 9,
        versionExtract: /JUNOS?\s+(\d+\.\d+[A-Z]?\d*(?:\.\d+)?)/i,
      },
      // Version from J-Web API
      {
        type: 'endpoint',
        path: '/api/v1/configuration/system/information',
        method: 'GET',
        match: 'version|junos',
        weight: 8,
        versionExtract: /"version"\s*:\s*"(\d+\.\d+[A-Z]?\d*(?:[.-][A-Za-z0-9]+)*)"/i,
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
      // J-Web system info API (version extraction)
      {
        type: 'endpoint',
        path: '/api/v1/system-information',
        method: 'GET',
        match: 'junos-version|hardware-model|host-name',
        weight: 9,
        versionExtract: /junos-version['":\s]+(\d+\.\d+[A-Z]?\d*(?:[.-][A-Za-z0-9]+)*)/i,
      },
      // SRX Cluster status page
      {
        type: 'endpoint',
        path: '/api/v1/high-availability/information',
        method: 'GET',
        match: 'cluster|redundancy-group|node',
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
        versionExtract: /ZLD\s*V?(\d+\.\d+(?:\.\d+)*)/i,
      },
      // Zyxel firmware info API (ZLD 5.x+)
      {
        type: 'endpoint',
        path: '/api/firmware/info',
        method: 'GET',
        match: 'firmware|version|model',
        weight: 9,
        versionExtract: /(?:fw_ver|version)['":\s]+V?(\d+\.\d+(?:\.\d+)*)/i,
      },
      // Model detection from HTML title
      {
        type: 'body',
        path: '/',
        match: '<title>(?:USG\\s*FLEX|ATP|VPN|ZyWALL)\\s*\\d+',
        weight: 10,
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
      // Zyxel SecuExtender SSL VPN client download
      {
        type: 'endpoint',
        path: '/ext-ui/index.html',
        method: 'GET',
        match: 'SecuExtender|Zyxel|SSL VPN',
        weight: 10,
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
      // Version from login page JS
      {
        type: 'body',
        path: '/',
        match: 'Sophos.*Firmware|SFOS',
        weight: 9,
        versionExtract: /(?:Firmware|SFOS)\s*(?:Version\s*)?v?(\d+\.\d+(?:\.\d+)*)/i,
      },
      // WebAdmin version endpoint
      {
        type: 'endpoint',
        path: '/webconsole/APIController?reqXML=<Request><Login><Username></Username><Password></Password></Login></Request>',
        method: 'GET',
        match: 'Sophos|Response|Status',
        weight: 8,
        versionExtract: /Firmware[Vv]ersion.*?(\d+\.\d+(?:\.\d+)*)/i,
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
        versionExtract: /Fireware\s*(?:XTM\s*)?v?(\d+\.\d+(?:\.\d+)*)/i,
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
        versionExtract: /Fireware\s*(?:XTM\s*)?v?(\d+\.\d+(?:\.\d+)*)/i,
      },
      {
        type: 'certificate',
        match: 'WatchGuard',
        weight: 7,
      },
      // Admin interface (port 8080) - Wizard portal
      {
        type: 'endpoint',
        path: '/wizard/Wizard_Portal.html',
        method: 'GET',
        match: 'WatchGuard|Wizard',
        weight: 9,
      },
      // Fireware OS login page title pattern
      {
        type: 'body',
        path: '/',
        match: '<title>Fireware\\s+(?:XTM\\s+)?Web\\s*UI',
        weight: 10,
        versionExtract: /Fireware\s*(?:XTM\s*)?v?(\d+\.\d+(?:\.\d+)*)/i,
      },
      // Static resource paths unique to WatchGuard
      {
        type: 'body',
        path: '/',
        match: '/wgrd-assets/|/wg_resources/',
        weight: 8,
      },
      // Mobile VPN with SSL portal
      {
        type: 'endpoint',
        path: '/sslvpn.html',
        method: 'GET',
        match: 'WatchGuard|Mobile VPN|SSLVPN',
        weight: 9,
      },
      // Fireware 2026.x version pattern
      {
        type: 'body',
        path: '/',
        match: 'Fireware\\s+(?:v)?2026|Fireware\\s+(?:v)?12\\.(?:5|11)',
        weight: 9,
        versionExtract: /Fireware\s*v?(20\d{2}\.\d+(?:\.\d+)*|\d+\.\d+\.\d+)/i,
      },
    ],
  },
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
];
