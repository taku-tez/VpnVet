/**
 * Tests for DetectionEvidence collection and output.
 */
import { testPattern, matchHeaders } from '../src/detector.js';
import { formatTable, formatCsv, formatJson, formatSarif } from '../src/formatters.js';
import type { ScanResult, DetectionEvidence } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helper: build a ScanResult with evidence
// ---------------------------------------------------------------------------

function makeScanResult(evidence: DetectionEvidence[]): ScanResult {
  return {
    target: 'https://example.com',
    timestamp: new Date().toISOString(),
    device: {
      vendor: 'fortinet',
      product: 'FortiGate',
      version: '7.0.1',
      confidence: 80,
      detectionMethod: ['endpoint', 'header'],
      endpoints: ['/remote/login'],
      evidence,
    },
    vulnerabilities: [],
    errors: [],
  };
}

// ---------------------------------------------------------------------------
// Evidence in outputs
// ---------------------------------------------------------------------------

describe('DetectionEvidence', () => {
  const sampleEvidence: DetectionEvidence[] = [
    {
      method: 'endpoint',
      url: 'https://example.com/remote/login',
      pattern: 'FortiGate',
      matchedValue: 'HTTP 200: <title>FortiGate</title>',
      description: 'Endpoint matched at https://example.com/remote/login (HTTP 200)',
    },
    {
      method: 'header',
      url: 'https://example.com',
      pattern: 'server:\\s*fortiweb',
      matchedValue: 'server: FortiWeb',
      description: 'Header matched: server: FortiWeb',
    },
  ];

  it('JSON output includes evidence array on device', () => {
    const result = makeScanResult(sampleEvidence);
    const json = JSON.parse(formatJson([result]));
    expect(json[0].device.evidence).toBeDefined();
    expect(json[0].device.evidence).toHaveLength(2);
    expect(json[0].device.evidence[0].method).toBe('endpoint');
    expect(json[0].device.evidence[1].matchedValue).toBe('server: FortiWeb');
  });

  it('table output includes Evidence section', () => {
    const result = makeScanResult(sampleEvidence);
    const table = formatTable([result]);
    expect(table).toContain('Evidence:');
    expect(table).toContain('[endpoint]');
    expect(table).toContain('[header]');
    expect(table).toContain('FortiWeb');
  });

  it('CSV output includes evidence_summary column', () => {
    const result = makeScanResult(sampleEvidence);
    const csv = formatCsv([result]);
    const header = csv.split('\n')[0];
    expect(header).toContain('evidence_summary');
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('endpoint');
  });

  it('SARIF output includes evidence in properties', () => {
    const result = makeScanResult(sampleEvidence);
    // Add a vulnerability so SARIF produces a result entry
    result.vulnerabilities = [{
      vulnerability: {
        cve: 'CVE-2023-27997',
        severity: 'critical',
        cvss: 9.8,
        description: 'Test vuln',
        affected: [{ vendor: 'fortinet', product: 'FortiGate' }],
        references: ['https://example.com'],
        exploitAvailable: true,
        cisaKev: true,
      },
      confidence: 'confirmed',
      evidence: 'Test evidence string',
    }];
    const sarif = JSON.parse(formatSarif([result], '1.0.0'));
    const sarifResult = sarif.runs[0].results[0];
    expect(sarifResult.properties.evidence).toBeDefined();
    expect(sarifResult.properties.evidence).toHaveLength(2);
  });

  it('handles empty evidence gracefully', () => {
    const result = makeScanResult([]);
    // Remove evidence since empty
    delete result.device!.evidence;
    const table = formatTable([result]);
    expect(table).not.toContain('Evidence:');

    const json = JSON.parse(formatJson([result]));
    expect(json[0].device.evidence).toBeUndefined();
  });
});
