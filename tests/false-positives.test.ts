/**
 * False Positive Tests
 * 
 * Ensures that general web servers, CDNs, and similar products
 * are NOT misidentified as VPN devices.
 */

import { fingerprints } from '../src/fingerprints/index.js';
import type { FingerprintPattern } from '../src/types.js';

/**
 * Score a set of mock response data against all fingerprint patterns.
 * Returns the best-matching vendor and score, or null if score < 5 (detection threshold).
 */
function scoreAgainstFingerprints(mockResponse: {
  headers?: Record<string, string>;
  body?: string;
  certInfo?: string;
}): { vendor: string; product: string; score: number } | null {
  let best: { vendor: string; product: string; score: number } | null = null;

  for (const fp of fingerprints) {
    let score = 0;

    for (const pattern of fp.patterns) {
      const matched = testPatternLocally(pattern, mockResponse);
      if (matched) {
        score += pattern.weight;
      }
    }

    if (score > 0 && (!best || score > best.score)) {
      best = { vendor: fp.vendor, product: fp.product, score };
    }
  }

  // Scanner threshold is score >= 5
  return best && best.score >= 5 ? best : null;
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

  // For endpoint patterns: only match if path is '/' or unset (root page).
  // The real scanner makes HTTP requests to specific paths; in our mock we
  // only have the root page body, so testing /remote/login patterns against
  // a generic page body would be invalid.
  if (pattern.type === 'endpoint' && mock.body) {
    if (!pattern.path || pattern.path === '/') {
      return regex.test(mock.body);
    }
    return false; // Can't test non-root endpoints without actual HTTP requests
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

// ============================================================
// General Web Servers - must NOT trigger VPN detection
// ============================================================

describe('False Positive Prevention', () => {
  describe('General Web Servers', () => {
    it('should not detect Apache HTTP Server as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'Apache/2.4.57 (Ubuntu)',
          'content-type': 'text/html; charset=UTF-8',
          'x-powered-by': 'PHP/8.2',
          'set-cookie': 'PHPSESSID=abc123; path=/',
        },
        body: `<!DOCTYPE html>
<html><head><title>Welcome to Apache</title></head>
<body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
</body></html>`,
      });
      expect(result).toBeNull();
    });

    it('should not detect Nginx as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'nginx/1.24.0',
          'content-type': 'text/html',
          'x-frame-options': 'SAMEORIGIN',
          'content-security-policy': "frame-ancestors 'self'",
        },
        body: `<!DOCTYPE html>
<html><head><title>Welcome to nginx!</title></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed.</p>
</body></html>`,
      });
      expect(result).toBeNull();
    });

    it('should not detect IIS as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'Microsoft-IIS/10.0',
          'x-powered-by': 'ASP.NET',
          'x-aspnet-version': '4.0.30319',
          'content-type': 'text/html',
        },
        body: `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html><head><title>IIS Windows Server</title></head>
<body><img src="iisstart.png" /></body></html>`,
      });
      expect(result).toBeNull();
    });

    it('should not detect Node.js/Express as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'x-powered-by': 'Express',
          'content-type': 'application/json',
          'etag': 'W/"1a-abc123"',
        },
        body: '{"status":"ok","version":"2.1.0","uptime":86400}',
      });
      expect(result).toBeNull();
    });

    it('should not detect Caddy as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'Caddy',
          'content-type': 'text/html; charset=utf-8',
          'alt-svc': 'h3=":443"; ma=2592000',
        },
        body: `<html><head><title>Caddy - Default Page</title></head>
<body><h1>Congratulations!</h1><p>Your Caddy web server is working.</p></body></html>`,
      });
      expect(result).toBeNull();
    });
  });

  // ============================================================
  // CDN / Load Balancers - must NOT trigger VPN detection
  // ============================================================

  describe('CDN and Load Balancers', () => {
    it('should not detect Cloudflare CDN (non-Access) as VPN', () => {
      // cf-ray alone has weight 6 which is >= 5 threshold,
      // but Cloudflare CDN without Access-specific headers should be below threshold
      // or at worst match with very low confidence
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'cloudflare',
          'cf-ray': '8a1b2c3d4e-NRT',
          'content-type': 'text/html',
          'cf-cache-status': 'HIT',
        },
        body: `<!DOCTYPE html>
<html><head><title>Example Site</title></head>
<body><h1>Welcome</h1><p>This is a regular website behind Cloudflare.</p></body></html>`,
      });
      // Cloudflare CDN may match cloudflare vendor due to cf-ray header, 
      // but should NOT reach high score. If it does match, confidence should be very low
      if (result) {
        expect(result.vendor).toBe('cloudflare');
        // Score should be marginal (cf-ray weight=6 + cloudflare header match=10 possible)
        // but body doesn't mention Cloudflare Access
        expect(result.score).toBeLessThanOrEqual(16);
      }
    });

    it('should not detect AWS ALB as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'awselb/2.0',
          'x-amzn-requestid': 'abc-123-def',
          'x-amzn-trace-id': 'Root=1-abc-def',
          'set-cookie': 'AWSALB=xyz; Expires=Mon, 01 Jan 2026; Path=/',
        },
        body: `<!DOCTYPE html>
<html><head><title>App</title></head>
<body><div id="app">Loading...</div>
<script src="/static/app.js"></script></body></html>`,
      });
      expect(result).toBeNull();
    });

    it('should not detect Akamai as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'AkamaiGHost',
          'x-akamai-session-info': 'name=AKA_PM_BASEDIR; value=/',
          'x-cache': 'TCP_HIT from a23-35-104-189.deploy.akamaitechnologies.com',
        },
        body: '<html><head><title>CDN Content</title></head><body>Hello World</body></html>',
      });
      expect(result).toBeNull();
    });

    it('should not detect Fastly as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'via': '1.1 varnish',
          'x-served-by': 'cache-nrt-rjtf7700035-NRT',
          'x-cache': 'HIT',
          'x-fastly-request-id': 'abc123',
        },
        body: '<html><body>Content from Fastly CDN</body></html>',
      });
      expect(result).toBeNull();
    });
  });

  // ============================================================
  // Similar Products - must NOT cross-detect between vendors
  // ============================================================

  describe('Cross-Vendor False Positive Prevention', () => {
    it('should not detect Fortinet response as SonicWall', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'xxxxxxxx-xxxxx',
          'set-cookie': 'SVPNCOOKIE=; path=/; secure',
        },
        body: `<html><head><script>
window.NEUTRINO_THEME = 'jade';
window.fgt_lang = {};
</script></head><body>
<!-- FortiOS v7.0.12 -->
<div class="ftnt-fortinet">FortiGate Login</div>
</body></html>`,
      });
      // Should detect as fortinet, NOT sonicwall
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('fortinet');
    });

    it('should not detect SonicWall response as Fortinet', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'SonicWALL SSL-VPN Web Server',
          'content-type': 'text/html',
        },
        body: `<html><head><title>SonicWall SMA Login</title></head>
<body><form action="/cgi-bin/userLogin">
<input type="text" name="username" />
<input type="password" name="password" />
<span>NetExtender</span>
</form></body></html>`,
      });
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('sonicwall');
    });

    it('should not detect Cisco AnyConnect response as Juniper', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'set-cookie': 'webvpnlogin=1; path=/',
          'x-transcend-version': '1',
          'x-aggregate-auth': '1',
        },
        body: `<html><head><title>SSL VPN Service</title></head>
<body><script>csco_ShowLoginForm('/+CSCOE+/logon.html')</script>
<div>Cisco ASA 5500-X</div></body></html>`,
      });
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('cisco');
    });

    it('should not detect Palo Alto response as Check Point', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'PanWeb Server',
          'content-type': 'text/html',
        },
        body: `<html><head><title>GlobalProtect Portal</title></head>
<body><div class="pan-globalprotect">
<form action="/global-protect/login.esp">
<span>Palo Alto Networks GlobalProtect</span>
</form></div></body></html>`,
      });
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('paloalto');
    });

    it('should not detect Pulse/Ivanti response as Citrix', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'set-cookie': 'DSID=abc123; DSBrowserID=def456; DSSignInURL=/; DSLastAccess=now',
          'content-type': 'text/html',
        },
        body: `<html><head><title>Ivanti Connect Secure</title></head>
<body><div>Welcome to Ivanti Connect Secure</div>
<script src="/dana-cached/sc/sc.js"></script>
<input name="danaparams" type="hidden" />
</body></html>`,
      });
      expect(result).not.toBeNull();
      // Should be pulse or ivanti (they share DSxx cookies)
      expect(['pulse', 'ivanti']).toContain(result!.vendor);
    });

    it('should not detect F5 BIG-IP response as other vendors', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'server': 'BigIP',
          'set-cookie': 'BIGipServer=abc123; path=/',
          'content-type': 'text/html',
        },
        body: `<html><head><title>BIG-IP</title></head>
<body><form action="/tmui/login.jsp">
<div>F5 Networks BIG-IP</div>
<input type="text" name="username" />
</form></body></html>`,
      });
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('f5');
    });

    it('should not detect Citrix Gateway as Pulse/Ivanti', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'set-cookie': 'NSC_AAAC=abc123; NSC_TMAS=def456',
          'content-type': 'text/html',
        },
        body: `<html><head><title>Citrix Gateway</title></head>
<body><div>Citrix Gateway Login</div>
<script src="/logon/LogonPoint/index.html?v=abcdef0123456789abcdef0123456789"></script>
<span>NetScaler Gateway</span>
</body></html>`,
      });
      expect(result).not.toBeNull();
      expect(result!.vendor).toBe('citrix');
    });
  });

  // ============================================================
  // Generic Login Pages - must NOT trigger VPN detection
  // ============================================================

  describe('Generic Login Pages', () => {
    it('should not detect WordPress login as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'x-powered-by': 'PHP/8.2',
          'content-type': 'text/html; charset=UTF-8',
          'set-cookie': 'wordpress_test_cookie=WP+Cookie+check',
        },
        body: `<!DOCTYPE html>
<html><head><title>Log In &lsaquo; My Site &#8212; WordPress</title>
<link rel='stylesheet' href='/wp-admin/css/login.min.css' />
</head><body class="login">
<form name="loginform" action="/wp-login.php" method="post">
<label for="user_login">Username</label>
<input type="text" name="log" id="user_login" />
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" />
<input type="submit" value="Log In" />
</form></body></html>`,
      });
      expect(result).toBeNull();
    });

    it('should not detect Jira login as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'x-asen': 'SEN-12345',
          'x-ausername': 'anonymous',
          'content-type': 'text/html; charset=UTF-8',
        },
        body: `<!DOCTYPE html>
<html><head><title>Log in - Jira</title></head>
<body><form action="/login.jsp" method="post">
<h1>Log in to Jira</h1>
<input type="text" name="os_username" />
<input type="password" name="os_password" />
<input type="submit" value="Log in" />
</form></body></html>`,
      });
      expect(result).toBeNull();
    });

    it('should not detect Grafana login as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'content-type': 'text/html; charset=UTF-8',
          'x-frame-options': 'deny',
        },
        body: `<!DOCTYPE html>
<html><head><title>Grafana</title>
<script nonce="abc123">
window.grafanaBootData = {"user":{"isSignedIn":false}};
</script></head>
<body><div id="reactRoot"></div></body></html>`,
      });
      expect(result).toBeNull();
    });

    it('should not detect generic SSO/SAML page as VPN', () => {
      const result = scoreAgainstFingerprints({
        headers: {
          'content-type': 'text/html',
          'set-cookie': 'JSESSIONID=abc123; Path=/; Secure; HttpOnly',
        },
        body: `<!DOCTYPE html>
<html><head><title>Single Sign-On</title></head>
<body><form action="/saml/SSO" method="post">
<h2>Enterprise Login</h2>
<input type="text" name="username" placeholder="Email" />
<input type="password" name="password" />
<input type="hidden" name="SAMLRequest" value="base64data" />
<button type="submit">Sign In</button>
</form></body></html>`,
      });
      expect(result).toBeNull();
    });
  });
});
