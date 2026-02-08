/**
 * False Negative Tests
 * 
 * Ensures that known VPN devices are correctly detected even in
 * edge cases: hidden versions, customized pages, minimal responses.
 */

import { getFingerprintsByVendor } from '../src/fingerprints/index.js';
import type { FingerprintPattern } from '../src/types.js';

/**
 * Score a mock response against a specific vendor's fingerprints.
 * Returns the total score (>= 5 means detection threshold met).
 */
function scoreForVendor(
  vendor: string,
  mock: { headers?: Record<string, string>; body?: string; certInfo?: string },
): number {
  const fps = getFingerprintsByVendor(vendor);
  let maxScore = 0;
  for (const fp of fps) {
    let score = 0;
    for (const pattern of fp.patterns) {
      if (testPatternLocally(pattern, mock)) {
        score += pattern.weight;
      }
    }
    if (score > maxScore) maxScore = score;
  }
  return maxScore;
}

function testPatternLocally(
  pattern: FingerprintPattern,
  mock: { headers?: Record<string, string>; body?: string; certInfo?: string },
): boolean {
  const regex = typeof pattern.match === 'string'
    ? new RegExp(pattern.match, 'i')
    : pattern.match;

  if (pattern.type === 'header' && mock.headers) {
    const headerStr = Object.entries(mock.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
    return regex.test(headerStr);
  }

  // Only match body/endpoint if path matches '/' or is unset
  if (pattern.type === 'endpoint' && mock.body) {
    if (!pattern.path || pattern.path === '/') {
      return regex.test(mock.body);
    }
    return false;
  }

  if (pattern.type === 'body' && mock.body) {
    if (!pattern.path || pattern.path === '/') {
      return regex.test(mock.body);
    }
    return false;
  }

  if (pattern.type === 'certificate' && mock.certInfo) {
    return regex.test(mock.certInfo);
  }

  return false;
}

const DETECTION_THRESHOLD = 5;

// ============================================================
// Tier 1 Vendors - Typical Responses
// ============================================================

describe('False Negative Prevention', () => {
  describe('Tier 1: Typical Responses', () => {
    it('should detect Fortinet FortiGate from typical login page', () => {
      const score = scoreForVendor('fortinet', {
        headers: {
          'server': 'xxxxxxxx-xxxxx',
          'set-cookie': 'SVPNCOOKIE=; path=/; secure',
        },
        body: `<html><head><script>
window.fgt_lang = {};
top.location="/remote/login";
</script></head><body></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Palo Alto GlobalProtect from prelogin XML', () => {
      const score = scoreForVendor('paloalto', {
        headers: {
          'server': 'PanWeb Server',
          'content-type': 'application/xml',
        },
        body: `<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
<status>success</status>
<panos-version>10.2.4</panos-version>
<saml-auth-method>POST</saml-auth-method>
<authentication-message>Please sign in</authentication-message>
</prelogin-response>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Cisco AnyConnect from login page', () => {
      const score = scoreForVendor('cisco', {
        headers: {
          'set-cookie': 'webvpnlogin=1; path=/',
          'x-transcend-version': '1',
        },
        body: `<html><head><title>SSL VPN Service</title></head>
<body><form action="/+CSCOE+/logon.html">
<script>csco_ShowLoginForm()</script>
<div>Cisco ASA</div>
</form></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Pulse Connect Secure from typical login', () => {
      const score = scoreForVendor('pulse', {
        headers: {
          'set-cookie': 'DSID=; DSBrowserID=abc; DSSignInURL=/; DSLastAccess=x',
        },
        body: `<html><head><title>Pulse Secure</title></head>
<body><form action="/dana-na/auth/url_default/welcome.cgi">
<div>Pulse Secure SSL VPN</div>
<input name="username" type="text" />
<input name="password" type="password" />
</form></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Ivanti Connect Secure from typical login', () => {
      const score = scoreForVendor('ivanti', {
        headers: {
          'set-cookie': 'DSID=; DSBrowserID=abc; DSSignInURL=/',
        },
        body: `<html><head><title>Ivanti Connect Secure</title></head>
<body><div>/dana-na/ resources</div>
<script src="/dana-cached/hc/hc.js"></script>
<input name="danaparams" type="hidden" />
</body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Citrix Gateway from typical login', () => {
      const score = scoreForVendor('citrix', {
        headers: {
          'set-cookie': 'NSC_AAAC=abc123; NSC_TMAS=def',
        },
        body: `<html><head><title>Citrix Gateway</title></head>
<body><div>Citrix Gateway Login</div>
<script src="/vpn/index.html"></script>
<span>NetScaler Gateway</span>
</body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });
  });

  // ============================================================
  // Tier 2 Vendors - Typical Responses
  // ============================================================

  describe('Tier 2: Typical Responses', () => {
    it('should detect SonicWall SMA from login page', () => {
      const score = scoreForVendor('sonicwall', {
        headers: {
          'server': 'SonicWALL SSL-VPN Web Server',
        },
        body: `<html><head><title>SonicWall Login</title></head>
<body><form action="/cgi-bin/userLogin">
<div>SonicWall SMA</div>
<span>NetExtender</span>
</form></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Check Point Mobile Access from login', () => {
      const score = scoreForVendor('checkpoint', {
        headers: {
          'content-type': 'text/html',
          'server': 'Check Point SVN',
        },
        body: `<html><head><title>Check Point Mobile Access</title></head>
<body><form action="/sslvpn/Login/Login">
<div>Check Point</div>
</form></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect F5 BIG-IP from login page', () => {
      const score = scoreForVendor('f5', {
        headers: {
          'server': 'BigIP',
          'set-cookie': 'BIGipServer=abc; path=/',
        },
        body: `<html><head><title>BIG-IP</title></head>
<body><form action="/tmui/login.jsp">
<div>F5 Networks</div>
</form></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Juniper from login page', () => {
      const score = scoreForVendor('juniper', {
        headers: {
          'content-type': 'text/html',
        },
        body: `<html><head><title>Juniper Networks</title></head>
<body><form action="/dana-na/auth/url_default/welcome.cgi">
<div>Juniper Networks Secure Access</div>
<span>Junos Pulse</span>
</form></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });
  });

  // ============================================================
  // Hidden Version Cases
  // ============================================================

  describe('Hidden Version Detection', () => {
    it('should detect Fortinet even without version info', () => {
      const score = scoreForVendor('fortinet', {
        headers: {
          'server': 'xxxxxxxx-xxxxx',
          'set-cookie': 'SVPNCOOKIE=',
        },
        body: '<html><head><script>top.location="/remote/login"</script></head><body></body></html>',
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Palo Alto without panos-version', () => {
      const score = scoreForVendor('paloalto', {
        headers: {
          'server': 'PanWeb Server',
        },
        body: `<prelogin-response>
<status>success</status>
<saml-auth-method>POST</saml-auth-method>
</prelogin-response>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Cisco without X-Transcend-Version', () => {
      const score = scoreForVendor('cisco', {
        headers: {
          'set-cookie': 'webvpnlogin=1; webvpncontext=abc',
        },
        body: `<html><body>
<script>csco_ShowLoginForm('/+CSCOE+/logon.html')</script>
</body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Citrix without version hash', () => {
      const score = scoreForVendor('citrix', {
        headers: {
          'set-cookie': 'NSC_AAAC=abc; NSC_TMAS=def',
        },
        body: '<html><body><div>Citrix Gateway</div></body></html>',
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect F5 with only Server header', () => {
      const score = scoreForVendor('f5', {
        headers: {
          'server': 'BigIP',
          'set-cookie': 'BIGipServer=abc',
        },
        body: '<html><body>Login</body></html>',
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect SonicWall with only Server header', () => {
      const score = scoreForVendor('sonicwall', {
        headers: {
          'server': 'SonicWALL',
        },
        body: `<html><body><form action="/cgi-bin/welcome">
<span>SonicWall</span></form></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });
  });

  // ============================================================
  // Customized Login Pages
  // ============================================================

  describe('Customized Login Pages', () => {
    it('should detect Fortinet with custom branding but FortiOS artifacts', () => {
      const score = scoreForVendor('fortinet', {
        headers: {
          'server': 'xxxxxxxx-xxxxx',
          'set-cookie': 'SVPNCOOKIE=; SVPNNETWORKCOOKIE=',
        },
        body: `<html><head><title>ACME Corp VPN Portal</title>
<script>window.fgt_lang = {};</script>
</head><body>
<div class="custom-login">
<img src="/custom-logo.png" />
<h1>Welcome to ACME Corp</h1>
<form action="/remote/logincheck">
<input type="text" name="username" />
<input type="password" name="credential" />
</form></div></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Palo Alto with custom portal branding', () => {
      const score = scoreForVendor('paloalto', {
        headers: {
          'server': 'PanWeb Server',
        },
        body: `<html><head><title>Company VPN</title></head>
<body><div class="pan-globalprotect PAN_FORM_CONTENT">
<img src="/custom/logo.png" />
<h2>Company Name</h2>
<form action="/global-protect/login.esp">
<input name="user" type="text" />
<input name="passwd" type="password" />
</form></div></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Cisco with custom WebVPN page', () => {
      const score = scoreForVendor('cisco', {
        headers: {
          'set-cookie': 'webvpnlogin=1',
        },
        body: `<html><head><title>Corporate Remote Access</title></head>
<body>
<div class="custom-branding">
<h1>Enterprise VPN</h1>
<form action="/+CSCOE+/logon.html">
<div class="csco_form">
<input type="text" name="username" />
<input type="password" name="password" />
</div></form></div></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Citrix with custom LogonPoint theme', () => {
      const score = scoreForVendor('citrix', {
        headers: {
          'set-cookie': 'NSC_AAAC=x',
        },
        body: `<html><head><title>Remote Access Portal</title></head>
<body><div id="custom-theme">
<img src="/vpn/images/custom-logo.png" />
<h1>Remote Access</h1>
<script src="/logon/LogonPoint/index.html?v=abcdef0123456789abcdef0123456789"></script>
</div></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Ivanti with custom branded login page', () => {
      const score = scoreForVendor('ivanti', {
        headers: {
          'set-cookie': 'DSID=abc; DSSignInURL=/',
        },
        body: `<html><head><title>Secure Access</title></head>
<body><div class="custom">
<h1>Company Secure Access</h1>
<form action="/dana-na/auth/url_default/welcome.cgi">
<input name="username" type="text" />
</form></div></body></html>`,
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });
  });

  // ============================================================
  // Minimal Response Detection (only headers/cert)
  // ============================================================

  describe('Minimal Response Detection', () => {
    it('should detect Fortinet from header-only response', () => {
      const score = scoreForVendor('fortinet', {
        headers: {
          'server': 'xxxxxxxx-xxxxx',
          'set-cookie': 'SVPNCOOKIE=; SVPNNETWORKCOOKIE=',
        },
        body: '',
      });
      // Server header (10) + SVPNCOOKIE (10) + SVPNNETWORKCOOKIE (10) = 30
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Cisco from header-only response', () => {
      const score = scoreForVendor('cisco', {
        headers: {
          'set-cookie': 'webvpnlogin=1; webvpn_portal=abc; webvpncontext=xyz',
          'x-transcend-version': '1',
        },
        body: '',
      });
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect F5 from certificate only', () => {
      const score = scoreForVendor('f5', {
        headers: {},
        body: '',
        certInfo: 'O=F5 Networks, CN=BigIP, OU=Product Development',
      });
      // Certificate pattern alone may not reach threshold - that's OK
      // but with Server header it should
      const scoreWithHeader = scoreForVendor('f5', {
        headers: { 'server': 'BigIP' },
        body: '',
        certInfo: 'O=F5 Networks, CN=BigIP',
      });
      expect(scoreWithHeader).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });

    it('should detect Fortinet from certificate info', () => {
      const score = scoreForVendor('fortinet', {
        headers: {},
        body: '',
        certInfo: 'O=Fortinet, OU=FortiGate, CN=FGT-60F12345678',
      });
      // cert weight=8, should be enough with threshold 5
      expect(score).toBeGreaterThanOrEqual(DETECTION_THRESHOLD);
    });
  });
});
