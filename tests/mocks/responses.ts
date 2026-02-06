/**
 * Mock HTTP responses for testing fingerprint detection
 * Based on real-world VPN device responses (sanitized)
 */

export const mockResponses: Record<string, { headers: Record<string, string>; body: string }> = {
  // ============================================================
  // Fortinet FortiGate
  // ============================================================
  'fortinet-login': {
    headers: {
      'content-type': 'text/html',
      'set-cookie': 'SVPNCOOKIE=; path=/; secure',
      'x-frame-options': 'SAMEORIGIN',
    },
    body: `<!DOCTYPE html>
<html class="main-app">
<head>
<meta charset="UTF-8">
<script type='text/javascript'>
    window.NEUTRINO_THEME = 'jade';
</script>
<script type='text/javascript'>
    (function() {
        var xhr = new XMLHttpRequest();
        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    window.fgt_lang = JSON.parse(xhr.responseText);
                } catch (e) {}
            }
        };
        xhr.open('GET', '/static/lang/en.json', false);
        xhr.send();
    })();
</script>
</head>
<body>
<div class="view-container ng1">
<form class="prompt legacy-prompt">
<f-icon class="ftnt-fortinet-grid icon-xl"></f-icon>
<!-- FortiOS v7.0.12 -->
</form>
</div>
</body>
</html>`,
  },

  'fortinet-remote-login': {
    headers: {
      'content-type': 'text/html',
      'set-cookie': 'SVPNCOOKIE=deleted; path=/remote',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>SSL VPN Login</title></head>
<body>
<script src="/sslvpn/js/webvpn.js"></script>
<div id="login-form">
  <input type="text" name="username" />
  <input type="password" name="credential" />
  <input type="hidden" name="realm" value="FortiToken" />
</div>
<!-- Version: FortiOS 7.2.5 -->
</body>
</html>`,
  },

  // ============================================================
  // Palo Alto GlobalProtect
  // ============================================================
  'paloalto-portal': {
    headers: {
      'content-type': 'text/html',
      'server': 'PanWeb Server',
    },
    body: `<!DOCTYPE html>
<html>
<head>
<title>GlobalProtect Portal</title>
<link href="/global-protect/portal/css/login.css" rel="stylesheet">
</head>
<body class="gp-portal">
<div id="pan-globalprotect-portal">
  <form action="/global-protect/portal/portal.cgi" method="POST">
    <input type="text" name="user" />
    <input type="password" name="passwd" />
  </form>
</div>
<!-- PAN-OS 10.2.3 -->
</body>
</html>`,
  },

  'paloalto-prelogon': {
    headers: {
      'content-type': 'application/xml',
      'server': 'PanWeb Server',
    },
    body: `<?xml version="1.0" encoding="UTF-8"?>
<prelogon-response>
  <portal-version>10.2.3</portal-version>
  <status>success</status>
</prelogon-response>`,
  },

  // ============================================================
  // Cisco AnyConnect
  // ============================================================
  'cisco-logon': {
    headers: {
      'content-type': 'text/html',
      'x-transcend-version': '9.16(3)',
      'set-cookie': 'webvpn=; path=/; secure',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>Cisco ASA - Login</title></head>
<body>
<div id="webvpn-login">
  <h1>AnyConnect</h1>
  <form action="/+webvpn+/index.html" method="POST">
    <input type="text" name="username" />
    <input type="password" name="password" />
  </form>
</div>
<!-- Cisco ASA Version 9.16(3)19 -->
</body>
</html>`,
  },

  // ============================================================
  // Pulse Secure / Ivanti
  // ============================================================
  'pulse-welcome': {
    headers: {
      'content-type': 'text/html',
      'set-cookie': 'DSSignInURL=/; path=/; DSID=; path=/',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>Pulse Secure - Welcome</title></head>
<body>
<div id="dana-na-welcome">
  <h1>Pulse Connect Secure</h1>
  <div class="welcome_msg">Welcome to the VPN Portal</div>
  <form action="/dana-na/auth/url_default/login.cgi" method="POST">
    <input type="text" name="username" />
    <input type="password" name="password" />
  </form>
</div>
<!-- Pulse Connect Secure 9.1R15 -->
</body>
</html>`,
  },

  'ivanti-welcome': {
    headers: {
      'content-type': 'text/html',
      'set-cookie': 'DSSignInURL=/; path=/',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>Ivanti Connect Secure</title></head>
<body>
<div id="ivanti-portal">
  <h1>Ivanti Connect Secure</h1>
  <form action="/dana-na/auth/url_default/login.cgi" method="POST">
    <input type="text" name="username" />
  </form>
</div>
<!-- Connect Secure 22.6R2.1 -->
</body>
</html>`,
  },

  // ============================================================
  // Citrix Gateway
  // ============================================================
  'citrix-vpn': {
    headers: {
      'content-type': 'text/html',
      'set-cookie': 'NSC_AAAC=; path=/',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>Citrix Gateway</title></head>
<body>
<div id="nsg-login">
  <img src="/vpn/images/CitrixLogo.png" />
  <form action="/cgi/login" method="POST">
    <input type="text" name="login" />
    <input type="password" name="passwd" />
  </form>
</div>
<!-- NetScaler Gateway 13.1-49.15 -->
</body>
</html>`,
  },

  // ============================================================
  // SonicWall
  // ============================================================
  'sonicwall-welcome': {
    headers: {
      'content-type': 'text/html',
      'server': 'SonicWall',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>SonicWall SSL VPN</title></head>
<body>
<div id="sonicwall-sslvpn">
  <h1>SonicWall SSL VPN</h1>
  <div class="Virtual Office">NetExtender</div>
  <form action="/cgi-bin/userLogin" method="POST">
    <input type="text" name="uname" />
  </form>
</div>
<!-- SonicOS 7.0.1-5035 -->
</body>
</html>`,
  },

  // ============================================================
  // F5 BIG-IP
  // ============================================================
  'f5-apm': {
    headers: {
      'content-type': 'text/html',
      'set-cookie': 'BIGipServer=deleted; path=/; MRHSession=deleted; path=/',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>F5 BIG-IP APM</title></head>
<body>
<div id="f5-logon">
  <img src="/public/images/F5Logo.png" />
  <form action="/my.policy" method="POST">
    <input type="text" name="username" />
    <input type="password" name="password" />
  </form>
</div>
<script src="/vdesk/index.php3"></script>
<!-- F5 BIG-IP 16.1.3 -->
</body>
</html>`,
  },

  // ============================================================
  // Sophos XG
  // ============================================================
  'sophos-xg': {
    headers: {
      'content-type': 'text/html',
      'server': 'Sophos',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>Sophos XG Firewall</title></head>
<body>
<div id="sfos-login">
  <h1>Sophos XG Firewall</h1>
  <form action="/webconsole/webpages/login.jsp" method="POST">
    <input type="text" name="username" />
  </form>
</div>
<!-- SFOS 19.5.2 -->
</body>
</html>`,
  },

  // ============================================================
  // pfSense
  // ============================================================
  'pfsense-login': {
    headers: {
      'content-type': 'text/html',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>pfSense - Login</title></head>
<body>
<div id="pfsense-login">
  <img src="/themes/pfsense/images/logo.png" />
  <h1>pfSense</h1>
  <form action="/index.php" method="POST">
    <input type="text" name="usernamefld" />
    <input type="password" name="passwordfld" />
  </form>
</div>
<!-- pfSense 2.7.0-RELEASE (Netgate) -->
</body>
</html>`,
  },

  // ============================================================
  // MikroTik
  // ============================================================
  'mikrotik-webfig': {
    headers: {
      'content-type': 'text/html',
      'server': 'MikroTik',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>MikroTik RouterOS</title></head>
<body>
<div id="webfig-login">
  <h1>RouterOS</h1>
  <div>MikroTik RouterBOARD</div>
  <form action="/webfig/" method="POST">
    <input type="text" name="username" />
  </form>
</div>
<!-- RouterOS 7.12.1 -->
</body>
</html>`,
  },

  // ============================================================
  // Zyxel
  // ============================================================
  'zyxel-usg': {
    headers: {
      'content-type': 'text/html',
      'server': 'Zyxel',
    },
    body: `<!DOCTYPE html>
<html>
<head><title>ZyXEL USG FLEX</title></head>
<body>
<div id="zyxel-login">
  <h1>ZyWALL USG FLEX 500</h1>
  <form action="/weblogin.cgi" method="POST">
    <input type="text" name="username" />
  </form>
</div>
<!-- ZLD 5.36 -->
</body>
</html>`,
  },
};

/**
 * Get mock response for a vendor/endpoint combination
 */
export function getMockResponse(key: string): { headers: Record<string, string>; body: string } | undefined {
  return mockResponses[key];
}

/**
 * Get all mock keys for a vendor
 */
export function getMockKeysForVendor(vendor: string): string[] {
  return Object.keys(mockResponses).filter(key => key.startsWith(vendor));
}
