/**
 * Cloud/ZTNA (Zero Trust Network Access)
 */

import type { Fingerprint } from '../types.js';

export const cloudztnaFingerprints: Fingerprint[] = [
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
        versionExtract: /(?:firmware|version)['":\s]+v?(\d+\.\d+(?:\.\d+)?)/i,
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
        versionExtract: /ClearPass[^0-9]*(\d+\.\d+\.\d+)/i,
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
        versionExtract: /(?:version|build)['":\s]+v?(\d+\.\d+\.\d+(?:\.\d+)?)/i,
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
        versionExtract: /cf-ray:\s*[0-9a-f]+-\w+|cloudflare[^0-9]*(\d+\.\d+\.\d+)/i,
      },
      {
        type: 'certificate',
        match: 'Cloudflare',
        weight: 7,
      },
    ],
  },
];
