#!/usr/bin/env node
/**
 * count-stats.mjs - Count VpnVet fingerprint/vendor/CVE statistics from source.
 * Run: node scripts/count-stats.mjs
 */
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const root = new URL('..', import.meta.url).pathname;

// Count CVEs and CISA KEV from vulnerabilities.ts
const vulnSrc = readFileSync(join(root, 'src/vulnerabilities.ts'), 'utf8');
const cveCount = (vulnSrc.match(/\bcve:/g) || []).length;
const kevCount = (vulnSrc.match(/cisaKev:\s*true/g) || []).length;

// Count vendor fingerprints from fingerprint files
const fpDir = join(root, 'src/fingerprints');
const fpFiles = readdirSync(fpDir).filter(f => f.endsWith('.ts') && f !== 'index.ts');
let vendorCount = 0;
for (const f of fpFiles) {
  const src = readFileSync(join(fpDir, f), 'utf8');
  vendorCount += (src.match(/\bvendor:/g) || []).length;
}

console.log(`Vendors: ${vendorCount}, Fingerprints: ${fpFiles.length} files, CVEs: ${cveCount}, CISA KEV: ${kevCount}`);

// Count versionExtract entries
let versionExtractCount = 0;
for (const f of fpFiles) {
  const src = readFileSync(join(fpDir, f), 'utf8');
  versionExtractCount += (src.match(/\bversionExtract:/g) || []).length;
}
console.log(`Version extractors: ${versionExtractCount}`);

// Cross-check with README.md
const readme = readFileSync(join(root, 'README.md'), 'utf8');
const checks = [
  { label: 'Vendors', actual: vendorCount, pattern: /(\d+)\s*VPN Vendors/ },
  { label: 'CVEs', actual: cveCount, pattern: /(\d+)\s*Critical CVEs/ },
  { label: 'CISA KEV', actual: kevCount, pattern: /\((\d+)\s*KEV\)/ },
];

let mismatch = false;
for (const { label, actual, pattern } of checks) {
  const m = readme.match(pattern);
  if (m) {
    const readmeVal = parseInt(m[1], 10);
    if (readmeVal !== actual) {
      console.warn(`⚠️  WARNING: README says ${label}=${readmeVal}, actual=${actual}`);
      mismatch = true;
    }
  }
}
if (mismatch) {
  process.exit(1);
} else {
  console.log('✅ README stats match actual data.');
}
