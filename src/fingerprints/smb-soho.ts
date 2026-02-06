/**
 * SMB/SOHO (Small/Medium Business)
 */

import type { Fingerprint } from '../types.js';

export const smbsohoFingerprints: Fingerprint[] = [
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
];
