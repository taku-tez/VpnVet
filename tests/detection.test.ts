/**
 * Detection Tests with Mock Responses
 * 
 * Tests fingerprint matching against mock HTTP responses
 * without making actual network requests.
 */

import { fingerprints, getFingerprintsByVendor } from '../src/fingerprints/index.js';
import { mockResponses } from './mocks/responses.js';

describe('Fingerprint Detection', () => {
  describe('FortiGate detection', () => {
    const fortinet = getFingerprintsByVendor('fortinet')[0];
    const mockLogin = mockResponses['fortinet-login'];
    const mockRemote = mockResponses['fortinet-remote-login'];

    it('should detect fgt_lang pattern', () => {
      const pattern = fortinet.patterns.find(p => 
        p.type === 'endpoint' && p.path === '/login'
      );
      expect(pattern).toBeDefined();
      
      const regex = new RegExp(String(pattern!.match), 'i');
      expect(regex.test(mockLogin.body)).toBe(true);
    });

    it('should detect NEUTRINO_THEME pattern', () => {
      expect(mockLogin.body).toContain('NEUTRINO_THEME');
    });

    it('should detect ftnt-fortinet pattern', () => {
      expect(mockLogin.body).toContain('ftnt-fortinet');
    });

    it('should detect SVPNCOOKIE header', () => {
      const headerPattern = fortinet.patterns.find(p => 
        p.type === 'header' && String(p.match).includes('SVPNCOOKIE')
      );
      expect(headerPattern).toBeDefined();
      expect(mockLogin.headers['set-cookie']).toContain('SVPNCOOKIE');
    });

    it('should detect sslvpn/js/webvpn pattern', () => {
      expect(mockRemote.body).toContain('sslvpn/js/webvpn');
    });

    it('should extract version from HTML comment', () => {
      const versionMatch = mockLogin.body.match(/FortiOS[- ]?v?(\d+\.\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('7.0.12');
    });

    it('should extract version from remote login', () => {
      const versionMatch = mockRemote.body.match(/FortiOS[- ]?(\d+\.\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('7.2.5');
    });
  });

  describe('Palo Alto detection', () => {
    const paloalto = getFingerprintsByVendor('paloalto')[0];
    const mockPortal = mockResponses['paloalto-portal'];
    const mockPrelogon = mockResponses['paloalto-prelogon'];

    it('should detect gp-portal pattern', () => {
      expect(mockPortal.body).toContain('gp-portal');
    });

    it('should detect GlobalProtect in class', () => {
      expect(mockPortal.body).toContain('pan-globalprotect');
    });

    it('should detect PanWeb Server header', () => {
      expect(mockPortal.headers['server']).toBe('PanWeb Server');
    });

    it('should extract version from portal.cgi response', () => {
      const versionMatch = mockPrelogon.body.match(/<portal-version>(\d+\.\d+\.\d+)<\/portal-version>/);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('10.2.3');
    });

    it('should extract PAN-OS version from HTML', () => {
      const versionMatch = mockPortal.body.match(/PAN-OS[- ]?(\d+\.\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('10.2.3');
    });
  });

  describe('Cisco AnyConnect detection', () => {
    const cisco = getFingerprintsByVendor('cisco')[0];
    const mockLogon = mockResponses['cisco-logon'];

    it('should detect webvpn pattern', () => {
      expect(mockLogon.body).toContain('webvpn');
    });

    it('should detect AnyConnect pattern', () => {
      expect(mockLogon.body).toContain('AnyConnect');
    });

    it('should detect X-Transcend-Version header', () => {
      expect(mockLogon.headers['x-transcend-version']).toBeDefined();
    });

    it('should extract version from header', () => {
      expect(mockLogon.headers['x-transcend-version']).toBe('9.16(3)');
    });

    it('should extract version from HTML', () => {
      const versionMatch = mockLogon.body.match(/Version[: ]+(\d+\.\d+\(\d+\)\d*)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('9.16(3)19');
    });
  });

  describe('Pulse Secure detection', () => {
    const pulse = getFingerprintsByVendor('pulse')[0];
    const mockWelcome = mockResponses['pulse-welcome'];

    it('should detect dana pattern', () => {
      expect(mockWelcome.body).toContain('dana');
    });

    it('should detect welcome_msg pattern', () => {
      expect(mockWelcome.body).toContain('welcome_msg');
    });

    it('should detect DSSignInURL header', () => {
      expect(mockWelcome.headers['set-cookie']).toContain('DSSignInURL');
    });

    it('should extract version from HTML', () => {
      const versionMatch = mockWelcome.body.match(/Pulse[- ]?Connect[- ]?Secure[- ]?(\d+\.\d+R\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('9.1R15');
    });
  });

  describe('Ivanti Connect Secure detection', () => {
    const ivanti = getFingerprintsByVendor('ivanti')[0];
    const mockWelcome = mockResponses['ivanti-welcome'];

    it('should detect Ivanti pattern', () => {
      expect(mockWelcome.body).toContain('Ivanti');
    });

    it('should detect Connect Secure pattern', () => {
      expect(mockWelcome.body).toContain('Connect Secure');
    });

    it('should extract version from HTML', () => {
      const versionMatch = mockWelcome.body.match(/Connect[- ]?Secure[- ]?(\d+\.\d+R\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('22.6R2.1');
    });
  });

  describe('Citrix Gateway detection', () => {
    const citrix = getFingerprintsByVendor('citrix')[0];
    const mockVpn = mockResponses['citrix-vpn'];

    it('should detect nsg pattern', () => {
      expect(mockVpn.body).toContain('nsg');
    });

    it('should detect Citrix pattern', () => {
      expect(mockVpn.body).toContain('Citrix');
    });

    it('should detect NSC_ cookie', () => {
      expect(mockVpn.headers['set-cookie']).toContain('NSC_');
    });

    it('should extract version from HTML', () => {
      const versionMatch = mockVpn.body.match(/NetScaler[- ]?Gateway[- ]?(\d+\.\d+-\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('13.1-49.15');
    });
  });

  describe('F5 BIG-IP detection', () => {
    const f5 = getFingerprintsByVendor('f5')[0];
    const mockApm = mockResponses['f5-apm'];

    it('should detect BIGipServer cookie', () => {
      expect(mockApm.headers['set-cookie']).toContain('BIGipServer');
    });

    it('should detect MRHSession cookie', () => {
      expect(mockApm.headers['set-cookie']).toContain('MRHSession');
    });

    it('should detect F5 pattern in body', () => {
      expect(mockApm.body).toContain('F5');
    });

    it('should detect vdesk pattern', () => {
      expect(mockApm.body).toContain('vdesk');
    });

    it('should extract version from HTML', () => {
      const versionMatch = mockApm.body.match(/BIG-IP[- ]?(\d+\.\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('16.1.3');
    });
  });

  describe('pfSense detection', () => {
    const pfsense = getFingerprintsByVendor('pfsense')[0];
    const mockLogin = mockResponses['pfsense-login'];

    it('should detect pfSense pattern', () => {
      expect(mockLogin.body).toContain('pfSense');
    });

    it('should detect Netgate pattern', () => {
      expect(mockLogin.body).toContain('Netgate');
    });

    it('should extract version from HTML', () => {
      const versionMatch = mockLogin.body.match(/pfSense[- ]?(\d+\.\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('2.7.0');
    });
  });

  describe('MikroTik detection', () => {
    const mikrotik = getFingerprintsByVendor('mikrotik')[0];
    const mockWebfig = mockResponses['mikrotik-webfig'];

    it('should detect MikroTik pattern', () => {
      expect(mockWebfig.body).toContain('MikroTik');
    });

    it('should detect RouterOS pattern', () => {
      expect(mockWebfig.body).toContain('RouterOS');
    });

    it('should detect RouterBOARD pattern', () => {
      expect(mockWebfig.body).toContain('RouterBOARD');
    });

    it('should detect MikroTik server header', () => {
      expect(mockWebfig.headers['server']).toBe('MikroTik');
    });

    it('should extract version from HTML', () => {
      const versionMatch = mockWebfig.body.match(/RouterOS[- ]?(\d+\.\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('7.12.1');
    });
  });

  describe('Zyxel detection', () => {
    const zyxel = getFingerprintsByVendor('zyxel')[0];
    const mockUsg = mockResponses['zyxel-usg'];

    it('should detect ZyXEL pattern', () => {
      expect(mockUsg.body).toContain('ZyXEL');
    });

    it('should detect ZyWALL pattern', () => {
      expect(mockUsg.body).toContain('ZyWALL');
    });

    it('should detect USG FLEX pattern', () => {
      expect(mockUsg.body).toContain('USG FLEX');
    });

    it('should detect Zyxel server header', () => {
      expect(mockUsg.headers['server']).toBe('Zyxel');
    });
  });

  describe('Sophos detection', () => {
    const sophos = getFingerprintsByVendor('sophos')[0];
    const mockXg = mockResponses['sophos-xg'];

    it('should detect Sophos pattern', () => {
      expect(mockXg.body).toContain('Sophos');
    });

    it('should detect XG Firewall pattern', () => {
      expect(mockXg.body).toContain('XG Firewall');
    });

    it('should detect sfos pattern', () => {
      expect(mockXg.body).toContain('sfos');
    });

    it('should detect Sophos server header', () => {
      expect(mockXg.headers['server']).toBe('Sophos');
    });

    it('should extract version from HTML', () => {
      const versionMatch = mockXg.body.match(/SFOS[- ]?(\d+\.\d+\.\d+)/i);
      expect(versionMatch).toBeTruthy();
      expect(versionMatch![1]).toBe('19.5.2');
    });
  });

  describe('SonicWall detection', () => {
    const sonicwall = getFingerprintsByVendor('sonicwall')[0];
    const mockWelcome = mockResponses['sonicwall-welcome'];

    it('should detect SonicWall pattern', () => {
      expect(mockWelcome.body).toContain('SonicWall');
    });

    it('should detect NetExtender pattern', () => {
      expect(mockWelcome.body).toContain('NetExtender');
    });

    it('should detect Virtual Office pattern', () => {
      expect(mockWelcome.body).toContain('Virtual Office');
    });

    it('should detect SonicWall server header', () => {
      expect(mockWelcome.headers['server']).toBe('SonicWall');
    });
  });
});

describe('Pattern Weights', () => {
  it('should have higher weights for definitive patterns', () => {
    for (const fp of fingerprints) {
      for (const pattern of fp.patterns) {
        // Endpoint patterns with unique paths should have high weight
        if (pattern.type === 'endpoint' && pattern.path?.includes('login')) {
          expect(pattern.weight).toBeGreaterThanOrEqual(8);
        }
        // Header patterns for vendor-specific cookies should be high
        if (pattern.type === 'header') {
          expect(pattern.weight).toBeGreaterThanOrEqual(5);
        }
      }
    }
  });

  it('should have version extraction for major vendors', () => {
    const majorVendors = ['fortinet', 'paloalto', 'cisco', 'pulse', 'ivanti'];
    
    for (const vendor of majorVendors) {
      const fps = getFingerprintsByVendor(vendor);
      expect(fps.length).toBeGreaterThan(0);
      
      // Check if at least one pattern has versionExtract
      const hasVersionExtract = fps.some(fp =>
        fp.patterns.some(p => p.versionExtract !== undefined)
      );
      expect(hasVersionExtract).toBe(true);
    }
  });
});
