#!/usr/bin/env node
/**
 * CVE Coverage Audit Script
 * 
 * Compares fingerprint vendors vs vulnerability vendors to find gaps.
 * Optionally checks CISA KEV for each uncovered vendor.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcDir = join(__dirname, '..', 'src');

function extractVendors(fileContent) {
  const vendors = new Set();
  const re = /vendor:\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = re.exec(fileContent)) !== null) {
    vendors.add(m[1]);
  }
  return vendors;
}

// Collect fingerprint vendors
const fpDir = join(srcDir, 'fingerprints');
const fpVendors = new Set();
for (const file of readdirSync(fpDir).filter(f => f.endsWith('.ts') && f !== 'index.ts')) {
  const content = readFileSync(join(fpDir, file), 'utf-8');
  for (const v of extractVendors(content)) fpVendors.add(v);
}

// Collect vulnerability vendors
const vulnContent = readFileSync(join(srcDir, 'vulnerabilities.ts'), 'utf-8');
const vulnVendors = extractVendors(vulnContent);

// Compute gap
const uncovered = [...fpVendors].filter(v => !vulnVendors.has(v)).sort();
const covered = [...fpVendors].filter(v => vulnVendors.has(v)).sort();

console.log(`=== VpnVet CVE Coverage Audit ===\n`);
console.log(`Fingerprint vendors: ${fpVendors.size}`);
console.log(`Vulnerability vendors: ${vulnVendors.size}`);
console.log(`Covered: ${covered.length}`);
console.log(`Uncovered: ${uncovered.length}\n`);

if (uncovered.length === 0) {
  console.log('✅ All fingerprinted vendors have CVE mappings.');
  process.exit(0);
}

console.log(`⚠️  Vendors with detection but NO CVE mappings:\n`);
for (const v of uncovered) {
  console.log(`  - ${v}`);
}

// Check CISA KEV for uncovered vendors
const CHECK_KEV = process.argv.includes('--kev');
if (CHECK_KEV) {
  console.log(`\n--- Checking CISA KEV catalog ---\n`);
  try {
    const resp = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    const data = await resp.json();
    const kevEntries = data.vulnerabilities || [];
    
    for (const vendor of uncovered) {
      const pattern = vendor.toLowerCase();
      const matches = kevEntries.filter(e => 
        e.vendorProject?.toLowerCase().includes(pattern) ||
        e.product?.toLowerCase().includes(pattern)
      );
      if (matches.length > 0) {
        console.log(`  🚨 ${vendor}: ${matches.length} KEV entries found`);
        for (const m of matches.slice(0, 3)) {
          console.log(`     ${m.cveID} - ${m.product} (${m.shortDescription?.slice(0, 80) || 'N/A'})`);
        }
        if (matches.length > 3) console.log(`     ... and ${matches.length - 3} more`);
      } else {
        console.log(`  ✅ ${vendor}: No KEV entries`);
      }
    }
  } catch (e) {
    console.error(`  Failed to fetch KEV catalog: ${e.message}`);
  }
}

console.log(`\nRun with --kev to check CISA KEV catalog for uncovered vendors.`);
