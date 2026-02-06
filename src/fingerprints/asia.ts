/**
 * Asia Regional (China, Korea, Japan)
 */

import type { Fingerprint } from '../types.js';

export const asiaFingerprints: Fingerprint[] = [
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
];
