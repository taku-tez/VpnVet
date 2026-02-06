/**
 * VPN Device Fingerprints Database
 */

import type { Fingerprint } from '../types.js';

export const fingerprints: Fingerprint[] = [
  // ============================================================
  // Fortinet FortiGate
  // ============================================================
  {
    vendor: 'fortinet',
    product: 'FortiGate',
    patterns: [
      {
        type: 'endpoint',
        path: '/remote/login',
        method: 'GET',
        match: 'FortiToken|fortinet|fgt_lang',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/remote/fgt_lang?lang=en',
        method: 'GET',
        match: '"msg"\\s*:',
        weight: 9,
      },
      {
        type: 'header',
        match: 'SVPNCOOKIE',
        weight: 10,
      },
      {
        type: 'header',
        match: 'Server: xxxxxxxx-xxxxx',
        weight: 5,
      },
      {
        type: 'body',
        path: '/remote/login',
        match: 'sslvpn/js/webvpn',
        weight: 8,
      },
      {
        type: 'certificate',
        match: 'FortiGate|Fortinet',
        weight: 7,
      },
      {
        type: 'favicon',
        path: '/favicon.ico',
        match: 'f8b3c21a', // FortiGate favicon hash (partial)
        weight: 6,
      },
    ],
  },

  // ============================================================
  // Palo Alto GlobalProtect
  // ============================================================
  {
    vendor: 'paloalto',
    product: 'GlobalProtect',
    patterns: [
      {
        type: 'endpoint',
        path: '/global-protect/portal/css/login.css',
        method: 'GET',
        match: 'global-protect|gp-portal',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/global-protect/login.esp',
        method: 'GET',
        match: 'GlobalProtect|pan-globalprotect',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/ssl-vpn/hipreport.esp',
        method: 'GET',
        match: 'Palo Alto|GlobalProtect',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Server: PanWeb Server',
        weight: 10,
      },
      {
        type: 'body',
        path: '/global-protect/portal/portal.cgi',
        match: 'portal-prelogon|prelogon-response',
        weight: 8,
      },
      {
        type: 'certificate',
        match: 'Palo Alto Networks',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Cisco AnyConnect / ASA
  // ============================================================
  {
    vendor: 'cisco',
    product: 'AnyConnect',
    patterns: [
      {
        type: 'endpoint',
        path: '/+CSCOE+/logon.html',
        method: 'GET',
        match: 'webvpn|anyconnect|AnyConnect',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/+webvpn+/index.html',
        method: 'GET',
        match: 'Cisco|WebVPN',
        weight: 9,
      },
      {
        type: 'endpoint',
        path: '/CACHE/sdesktop/install/binaries/',
        method: 'GET',
        match: 'anyconnect|hostscan',
        weight: 8,
      },
      {
        type: 'header',
        match: 'webvpn',
        weight: 9,
      },
      {
        type: 'header',
        match: 'X-Transcend-Version',
        weight: 10,
      },
      {
        type: 'certificate',
        match: 'Cisco|ASA',
        weight: 6,
      },
    ],
  },

  // ============================================================
  // Pulse Secure (Now Ivanti)
  // ============================================================
  {
    vendor: 'pulse',
    product: 'Pulse Connect Secure',
    patterns: [
      {
        type: 'endpoint',
        path: '/dana-na/auth/url_default/welcome.cgi',
        method: 'GET',
        match: 'Pulse Secure|dana|welcome_msg',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/dana-na/auth/url_admin/welcome.cgi',
        method: 'GET',
        match: 'dana|admin',
        weight: 9,
      },
      {
        type: 'endpoint',
        path: '/dana/home/index.cgi',
        method: 'GET',
        match: 'Pulse|dana-na',
        weight: 8,
      },
      {
        type: 'header',
        match: 'DSSignInURL',
        weight: 10,
      },
      {
        type: 'header',
        match: 'DSID',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Pulse Secure|Ivanti',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Ivanti Connect Secure (Newer version of Pulse)
  // ============================================================
  {
    vendor: 'ivanti',
    product: 'Connect Secure',
    patterns: [
      {
        type: 'endpoint',
        path: '/dana-na/auth/url_default/welcome.cgi',
        method: 'GET',
        match: 'Ivanti|Connect Secure',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/api/v1/totp/user-backup-code',
        method: 'GET',
        match: 'Ivanti',
        weight: 8,
      },
      {
        type: 'header',
        match: 'DSSignInURL',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Ivanti',
        weight: 8,
      },
    ],
  },

  // ============================================================
  // SonicWall
  // ============================================================
  {
    vendor: 'sonicwall',
    product: 'SMA',
    patterns: [
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
        method: 'GET',
        match: 'SonicWall|sslvpn',
        weight: 9,
      },
      {
        type: 'header',
        match: 'SonicWall',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'SonicWall SSL VPN|Virtual Office',
        weight: 8,
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
  // Citrix Gateway (NetScaler)
  // ============================================================
  {
    vendor: 'citrix',
    product: 'Citrix Gateway',
    patterns: [
      {
        type: 'endpoint',
        path: '/vpn/index.html',
        method: 'GET',
        match: 'Citrix|NetScaler|nsg-',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/cgi/login',
        method: 'GET',
        match: 'Citrix Gateway|NetScaler',
        weight: 9,
      },
      {
        type: 'endpoint',
        path: '/logon/LogonPoint/index.html',
        method: 'GET',
        match: 'Citrix|logon/LogonPoint',
        weight: 10,
      },
      {
        type: 'header',
        match: 'NSC_',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Citrix',
        weight: 10,
      },
      {
        type: 'certificate',
        match: 'Citrix|NetScaler',
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
  // F5 BIG-IP APM (Access Policy Manager)
  // ============================================================
  {
    vendor: 'f5',
    product: 'BIG-IP APM',
    patterns: [
      {
        type: 'endpoint',
        path: '/my.policy',
        method: 'GET',
        match: 'F5|BIG-IP|Access Policy',
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
        path: '/my.logout.php3',
        method: 'GET',
        match: 'F5|BIG-IP',
        weight: 8,
      },
      {
        type: 'header',
        match: 'BIGipServer',
        weight: 10,
      },
      {
        type: 'header',
        match: 'MRHSession',
        weight: 9,
      },
      {
        type: 'header',
        match: 'F5',
        weight: 8,
      },
      {
        type: 'body',
        path: '/',
        match: 'F5 Networks|BIG-IP|/vdesk/',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'F5 Networks|BIG-IP',
        weight: 7,
      },
    ],
  },

  // ============================================================
  // Juniper SRX / Junos Pulse
  // ============================================================
  {
    vendor: 'juniper',
    product: 'SRX SSL VPN',
    patterns: [
      {
        type: 'endpoint',
        path: '/dana-na/',
        method: 'GET',
        match: 'Juniper|Junos|SRX',
        weight: 9,
      },
      {
        type: 'endpoint',
        path: '/login/login.cgi',
        method: 'GET',
        match: 'Juniper|SRX|Dynamic VPN',
        weight: 10,
      },
      {
        type: 'header',
        match: 'Juniper',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Juniper Networks|Dynamic VPN|SRX',
        weight: 9,
      },
      {
        type: 'certificate',
        match: 'Juniper',
        weight: 8,
      },
    ],
  },

  // ============================================================
  // Zyxel USG / ZyWALL VPN
  // ============================================================
  {
    vendor: 'zyxel',
    product: 'USG/ZyWALL',
    patterns: [
      {
        type: 'endpoint',
        path: '/weblogin.cgi',
        method: 'GET',
        match: 'ZyXEL|Zyxel|ZyWALL|USG',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/ext-js/app.js',
        method: 'GET',
        match: 'ZyXEL|Zyxel',
        weight: 8,
      },
      {
        type: 'endpoint',
        path: '/webman/index.cgi',
        method: 'GET',
        match: 'ZyXEL|Zyxel|USG|ATP',
        weight: 9,
      },
      {
        type: 'header',
        match: 'ZyXEL|Zyxel',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'ZyXEL|Zyxel|ZyWALL|USG FLEX',
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
  // Sophos XG / UTM SSL VPN
  // ============================================================
  {
    vendor: 'sophos',
    product: 'XG Firewall',
    patterns: [
      {
        type: 'endpoint',
        path: '/userportal/webpages/myaccount/login.jsp',
        method: 'GET',
        match: 'Sophos|XG|UTM',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/webconsole/webpages/login.jsp',
        method: 'GET',
        match: 'Sophos|XG Firewall',
        weight: 10,
      },
      {
        type: 'endpoint',
        path: '/sslvpnLogin.html',
        method: 'GET',
        match: 'Sophos|SSL VPN',
        weight: 9,
      },
      {
        type: 'header',
        match: 'Sophos',
        weight: 10,
      },
      {
        type: 'body',
        path: '/',
        match: 'Sophos|XG Firewall|Cyberoam|sfos',
        weight: 9,
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
];

export function getFingerprintsByVendor(vendor: string): Fingerprint[] {
  return fingerprints.filter(f => f.vendor === vendor);
}

export function getAllVendors(): string[] {
  return [...new Set(fingerprints.map(f => f.vendor))];
}
