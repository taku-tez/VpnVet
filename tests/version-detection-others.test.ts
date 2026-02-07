/**
 * Version Detection Tests for Asia, SMB-SOHO, and Cloud-ZTNA vendors
 *
 * Validates that versionExtract patterns correctly extract version strings
 * from realistic response bodies.
 */

import { asiaFingerprints } from '../src/fingerprints/asia.js';
import { smbsohoFingerprints } from '../src/fingerprints/smb-soho.js';
import { cloudztnaFingerprints } from '../src/fingerprints/cloud-ztna.js';

describe('Asia vendor version extraction', () => {
  it('Sangfor: extracts version from login page', () => {
    const sangfor = asiaFingerprints.find(f => f.vendor === 'sangfor')!;
    const pattern = sangfor.patterns.find(p => p.path === '/por/login_auth.csp' && p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<title>Sangfor SSL VPN</title><script>{"version": "8.0.85"}</script>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('8.0.85');
  });

  it('Sangfor: extracts version from body', () => {
    const sangfor = asiaFingerprints.find(f => f.vendor === 'sangfor')!;
    const pattern = sangfor.patterns.find(p => p.type === 'body' && p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<div>SANGFOR SSLVPN_7.6.9 powered</div>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('7.6.9');
  });

  it('Array Networks: extracts ArrayOS version', () => {
    const array = asiaFingerprints.find(f => f.vendor === 'array')!;
    const pattern = array.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<title>ArrayOS AG 9.4.0.212 Login</title>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('9.4.0');
  });

  it('Hillstone: extracts StoneOS version', () => {
    const hillstone = asiaFingerprints.find(f => f.vendor === 'hillstone')!;
    const pattern = hillstone.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<div>StoneOS: 5.5R9</div>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('5.5');
  });

  it('Huawei: extracts USG version', () => {
    const huawei = asiaFingerprints.find(f => f.vendor === 'huawei')!;
    const pattern = huawei.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<meta content="USG6000 V500R005C20SPC500">';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toMatch(/500/);
  });

  it('H3C: extracts SecPath version', () => {
    const h3c = asiaFingerprints.find(f => f.vendor === 'h3c')!;
    const pattern = h3c.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<div>SecPath Version: 7.1.064</div>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('7.1.064');
  });

  it('Ruijie: extracts RG version', () => {
    const ruijie = asiaFingerprints.find(f => f.vendor === 'ruijie')!;
    const pattern = ruijie.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<span>RG-EG3250 Version: 11.9(4)</span>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toMatch(/11\.9/);
  });

  it('all Asia vendors have at least one versionExtract', () => {
    for (const fp of asiaFingerprints) {
      const hasExtract = fp.patterns.some(p => p.versionExtract);
      expect({ vendor: fp.vendor, hasExtract }).toEqual({ vendor: fp.vendor, hasExtract: true });
    }
  });
});

describe('SMB-SOHO vendor version extraction', () => {
  it('DrayTek: extracts Vigor firmware version', () => {
    const draytek = smbsohoFingerprints.find(f => f.vendor === 'draytek')!;
    const pattern = draytek.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<title>Vigor 2927 - Firmware 4.4.3</title>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('4.4.3');
  });

  it('MikroTik: extracts RouterOS version from webfig', () => {
    const mikrotik = smbsohoFingerprints.find(f => f.vendor === 'mikrotik')!;
    const pattern = mikrotik.patterns.find(p => p.path === '/webfig/' && p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<title>RouterOS v7.14.3 - WebFig</title>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('7.14.3');
  });

  it('MikroTik: extracts RouterOS version from body', () => {
    const mikrotik = smbsohoFingerprints.find(f => f.vendor === 'mikrotik')!;
    const pattern = mikrotik.patterns.find(p => p.type === 'body' && p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<div>MikroTik RouterOS 6.49.14</div>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('6.49.14');
  });

  it('Ubiquiti: extracts UniFi version', () => {
    const ubiquiti = smbsohoFingerprints.find(f => f.vendor === 'ubiquiti')!;
    const pattern = ubiquiti.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '{"version":"8.1.113","name":"UniFi Network"}';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('8.1.113');
  });

  it('pfSense: extracts pfSense version', () => {
    const pfsense = smbsohoFingerprints.find(f => f.vendor === 'pfsense')!;
    const pattern = pfsense.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<title>pfSense - Login</title><meta name="description" content="pfSense 2.7.2-RELEASE">';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('2.7.2');
  });

  it('OPNsense: extracts version from login page', () => {
    const opnsense = smbsohoFingerprints.find(f => f.vendor === 'opnsense')!;
    const pattern = opnsense.patterns.find(p => p.path === '/ui/core/login' && p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<footer>OPNsense 24.7.4</footer>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('24.7.4');
  });

  it('OPNsense: extracts version from firmware API', () => {
    const opnsense = smbsohoFingerprints.find(f => f.vendor === 'opnsense')!;
    const pattern = opnsense.patterns.find(p => p.path === '/api/core/firmware/status' && p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '{"product_version":"24.7.4","product_name":"OPNsense"}';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('24.7.4');
  });

  it('Stormshield: extracts SNS version', () => {
    const stormshield = smbsohoFingerprints.find(f => f.vendor === 'stormshield')!;
    const pattern = stormshield.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<div>Stormshield SNS 4.7.5 Administration</div>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('4.7.5');
  });

  it('Kerio: extracts Kerio Control version', () => {
    const kerio = smbsohoFingerprints.find(f => f.vendor === 'kerio')!;
    const pattern = kerio.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<title>Kerio Control 9.4.4 - Administration</title>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('9.4.4');
  });

  it('key SMB-SOHO vendors have versionExtract', () => {
    const mustHave = ['draytek', 'mikrotik', 'ubiquiti', 'pfsense', 'opnsense'];
    for (const vendor of mustHave) {
      const fp = smbsohoFingerprints.find(f => f.vendor === vendor)!;
      const hasExtract = fp.patterns.some(p => p.versionExtract);
      expect({ vendor, hasExtract }).toEqual({ vendor, hasExtract: true });
    }
  });
});

describe('Cloud-ZTNA vendor version extraction', () => {
  it('Meraki: extracts firmware version', () => {
    const meraki = cloudztnaFingerprints.find(f => f.vendor === 'meraki')!;
    const pattern = meraki.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '{"firmware":"18.211.2","model":"MX64"}';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('18.211.2');
  });

  it('Aruba ClearPass: extracts version', () => {
    const aruba = cloudztnaFingerprints.find(f => f.vendor === 'aruba')!;
    const pattern = aruba.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<div>ClearPass Policy Manager 6.12.2</div>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('6.12.2');
  });

  it('Zscaler: extracts version from signin page', () => {
    const zscaler = cloudztnaFingerprints.find(f => f.vendor === 'zscaler')!;
    const pattern = zscaler.patterns.find(p => p.versionExtract);
    expect(pattern).toBeDefined();

    const body = '<script>window.ZPA_CONFIG={"build":"24.3.392.1"}</script>';
    const match = body.match(pattern!.versionExtract!);
    expect(match).toBeTruthy();
    expect(match![1]).toBe('24.3.392.1');
  });

  it('key Cloud-ZTNA vendors have versionExtract', () => {
    const mustHave = ['meraki', 'aruba', 'zscaler'];
    for (const vendor of mustHave) {
      const fp = cloudztnaFingerprints.find(f => f.vendor === vendor)!;
      const hasExtract = fp.patterns.some(p => p.versionExtract);
      expect({ vendor, hasExtract }).toEqual({ vendor, hasExtract: true });
    }
  });
});
