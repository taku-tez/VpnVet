#!/usr/bin/env node
/**
 * check-kev-updates.mjs - Find VPN-related CISA KEV entries missing from VpnVet
 *
 * Usage: node scripts/check-kev-updates.mjs
 *
 * Designed for monthly CI/cron execution.
 * Exit code 0 = no new CVEs found, 1 = new CVEs found (or error).
 */

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vulnFile = resolve(__dirname, '..', 'src', 'vulnerabilities.ts');

// VPN-related keywords to match in KEV vendor/product fields
const VPN_KEYWORDS = [
  'fortinet', 'fortigate', 'fortios',
  'palo alto', 'pan-os', 'globalprotect',
  'cisco', 'asa', 'firepower', 'anyconnect', 'adaptive security',
  'check point', 'quantum',
  'f5', 'big-ip',
  'juniper', 'junos', 'srx',
  'pulse secure', 'pulse connect',
  'ivanti', 'connect secure', 'policy secure',
  'citrix', 'netscaler', 'adc',
  'sonicwall', 'sma',
  'sophos', 'watchguard', 'barracuda', 'zyxel',
  'array networks',
  'draytek', 'vigor',
  'mikrotik', 'routeros',
  'openvpn', 'wireguard',
  'vpn', 'ssl vpn', 'sslvpn',
];

async function main() {
  // 1. Extract existing CVE IDs from vulnerabilities.ts
  const vulnSrc = readFileSync(vulnFile, 'utf-8');
  const existingCVEs = new Set(
    [...vulnSrc.matchAll(/cve:\s*'(CVE-\d{4}-\d+)'/g)].map(m => m[1])
  );
  console.error(`📦 ${existingCVEs.size} CVEs currently in VpnVet`);

  // 2. Fetch CISA KEV
  console.error('🌐 Fetching CISA KEV catalog...');
  const res = await fetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const kev = await res.json();
  console.error(`📋 ${kev.vulnerabilities.length} total KEV entries`);

  // 3. Filter VPN-related, not already in VpnVet
  const missing = kev.vulnerabilities.filter(v => {
    if (existingCVEs.has(v.cveID)) return false;
    const text = `${v.vendorProject} ${v.product} ${v.shortDescription}`.toLowerCase();
    return VPN_KEYWORDS.some(kw => text.includes(kw));
  });

  if (missing.length === 0) {
    console.log('✅ No new VPN-related KEV entries found.');
    return;
  }

  console.log(`\n🔍 Found ${missing.length} VPN-related KEV entries not in VpnVet:\n`);
  for (const v of missing) {
    console.log(`  ${v.cveID} | ${v.vendorProject} - ${v.product}`);
    console.log(`    ${v.shortDescription.substring(0, 120)}`);
    console.log(`    Due: ${v.dueDate} | Added: ${v.dateAdded}`);
    console.log();
  }

  console.log(`\nTo add a CVE: node scripts/add-cve.mjs <CVE-ID>`);
  process.exit(1);
}

main().catch(e => {
  console.error(`Error: ${e.message}`);
  process.exit(1);
});
