/**
 * CPE generation tests
 */
import { buildCpe, CPE_MAPPINGS } from '../src/cpe.js';

describe('buildCpe', () => {
  it('generates correct CPE for fortinet/FortiGate with version', () => {
    expect(buildCpe('fortinet', 'FortiGate', '7.4.1'))
      .toBe('cpe:2.3:o:fortinet:fortios:7.4.1:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for paloalto/GlobalProtect', () => {
    expect(buildCpe('paloalto', 'GlobalProtect', '10.2.3'))
      .toBe('cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for pulse/Pulse Connect Secure', () => {
    expect(buildCpe('pulse', 'Pulse Connect Secure', '9.1R11'))
      .toBe('cpe:2.3:a:ivanti:connect_secure:9.1R11:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for cisco/ASA', () => {
    expect(buildCpe('cisco', 'ASA', '9.16.2'))
      .toBe('cpe:2.3:o:cisco:adaptive_security_appliance_software:9.16.2:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for citrix/Citrix Gateway', () => {
    expect(buildCpe('citrix', 'Citrix Gateway', '13.1'))
      .toBe('cpe:2.3:a:citrix:netscaler_gateway:13.1:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for sonicwall/SMA', () => {
    expect(buildCpe('sonicwall', 'SMA', '10.2.1'))
      .toBe('cpe:2.3:o:sonicwall:sma_firmware:10.2.1:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for f5/BIG-IP APM', () => {
    expect(buildCpe('f5', 'BIG-IP APM', '16.1.0'))
      .toBe('cpe:2.3:a:f5:big-ip_access_policy_manager:16.1.0:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for openvpn/Access Server', () => {
    expect(buildCpe('openvpn', 'Access Server', '2.11.1'))
      .toBe('cpe:2.3:a:openvpn:openvpn_access_server:2.11.1:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for juniper/SRX SSL VPN', () => {
    expect(buildCpe('juniper', 'SRX SSL VPN', '23.4R1'))
      .toBe('cpe:2.3:o:juniper:junos:23.4R1:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for zyxel/USG/ZyWALL', () => {
    expect(buildCpe('zyxel', 'USG/ZyWALL', '5.37'))
      .toBe('cpe:2.3:o:zyxel:atp_firmware:5.37:*:*:*:*:*:*:*');
  });

  it('generates correct CPE for watchguard/Firebox', () => {
    expect(buildCpe('watchguard', 'Firebox', '12.10'))
      .toBe('cpe:2.3:o:watchguard:fireware:12.10:*:*:*:*:*:*:*');
  });

  it('uses wildcard when version is undefined', () => {
    expect(buildCpe('fortinet', 'FortiGate'))
      .toBe('cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*');
  });

  it('uses wildcard when version is empty string', () => {
    // empty string is falsy, should use wildcard
    expect(buildCpe('fortinet', 'FortiGate', ''))
      .toBe('cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*');
  });

  it('returns undefined for unknown vendor/product', () => {
    expect(buildCpe('unknown', 'Unknown Product')).toBeUndefined();
  });

  it('returns undefined for partial match', () => {
    expect(buildCpe('fortinet', 'NonExistent')).toBeUndefined();
  });

  it('escapes special characters in version', () => {
    expect(buildCpe('fortinet', 'FortiGate', '7.4.1*beta'))
      .toBe('cpe:2.3:o:fortinet:fortios:7.4.1\\*beta:*:*:*:*:*:*:*');
  });
});

describe('CPE_MAPPINGS coverage', () => {
  it('has mappings for all major vendors', () => {
    const expectedVendors = [
      'fortinet', 'paloalto', 'cisco', 'pulse', 'ivanti', 'citrix',
      'sonicwall', 'checkpoint', 'openvpn', 'f5', 'juniper', 'zyxel',
      'sophos', 'watchguard', 'barracuda', 'draytek', 'mikrotik',
      'ubiquiti', 'pfsense', 'opnsense', 'netgear', 'tplink',
      'sangfor', 'array', 'hillstone', 'huawei', 'h3c',
      'ahnlab', 'secui', 'meraki', 'aruba',
    ];
    for (const vendor of expectedVendors) {
      const hasMapping = Object.keys(CPE_MAPPINGS).some(k => k.startsWith(vendor + '/'));
      expect(hasMapping).toBe(true);
    }
  });

  it('all CPE mappings produce valid CPE 2.3 strings', () => {
    const cpe23Regex = /^cpe:2\.3:[oah]:[a-z0-9._-]+:[a-z0-9._-]+:\*:\*:\*:\*:\*:\*:\*:\*$/;
    for (const key of Object.keys(CPE_MAPPINGS)) {
      const slashIdx = key.indexOf('/');
      const vendor = key.slice(0, slashIdx);
      const product = key.slice(slashIdx + 1);
      const cpe = buildCpe(vendor, product);
      expect(cpe).toBeDefined();
      expect(cpe).toMatch(cpe23Regex);
    }
  });
});

describe('Output formats include CPE', () => {
  // Import formatters
  const { formatTable, formatJson, formatCsv, formatSarif } = require('../src/formatters.js');

  const mockResult = {
    target: 'https://vpn.example.com',
    timestamp: '2026-02-10T10:00:00Z',
    device: {
      vendor: 'fortinet',
      product: 'FortiGate',
      version: '7.4.1',
      confidence: 90,
      detectionMethod: ['endpoint'],
      endpoints: ['/remote/login'],
      cpe: 'cpe:2.3:o:fortinet:fortios:7.4.1:*:*:*:*:*:*:*',
    },
    vulnerabilities: [],
    errors: [],
  };

  it('table format includes CPE line', () => {
    const output = formatTable([mockResult]);
    expect(output).toContain('CPE: cpe:2.3:o:fortinet:fortios:7.4.1');
  });

  it('JSON format includes cpe field', () => {
    const output = formatJson([mockResult]);
    const parsed = JSON.parse(output);
    expect(parsed[0].device.cpe).toBe('cpe:2.3:o:fortinet:fortios:7.4.1:*:*:*:*:*:*:*');
  });

  it('CSV format includes cpe column', () => {
    const output = formatCsv([mockResult]);
    const lines = output.split('\n');
    const headers = lines[0].split(',');
    expect(headers).toContain('cpe');
    const cpeIdx = headers.indexOf('cpe');
    const dataFields = lines[1].split(',');
    expect(dataFields[cpeIdx]).toContain('cpe:2.3:o:fortinet:fortios');
  });

  it('SARIF format includes cpe in properties', () => {
    const vulnResult = {
      ...mockResult,
      vulnerabilities: [{
        vulnerability: {
          cve: 'CVE-2024-21762',
          severity: 'critical',
          cvss: 9.8,
          description: 'test',
          affected: [],
          references: ['https://example.com'],
          exploitAvailable: true,
          cisaKev: true,
        },
        confidence: 'confirmed',
        evidence: 'test evidence',
      }],
    };
    const output = formatSarif([vulnResult], '1.0.0');
    const parsed = JSON.parse(output);
    const result = parsed.runs[0].results[0];
    expect(result.properties.cpe).toBe('cpe:2.3:o:fortinet:fortios:7.4.1:*:*:*:*:*:*:*');
  });
});
