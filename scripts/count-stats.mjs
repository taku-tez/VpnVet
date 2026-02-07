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
