#!/usr/bin/env node
/**
 * count-stats.mjs - Count VpnVet fingerprint/vendor/CVE/test statistics from source.
 * Run: node scripts/count-stats.mjs
 * Run with --check to verify README.md and CHANGELOG.md match actual data.
 */
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

const root = new URL('..', import.meta.url).pathname;
const checkMode = process.argv.includes('--check');

// ── Count CVEs and CISA KEV from vulnerabilities.ts ──
const vulnSrc = readFileSync(join(root, 'src/vulnerabilities.ts'), 'utf8');
const cveCount = (vulnSrc.match(/\bcve:/g) || []).length;
const kevCount = (vulnSrc.match(/cisaKev:\s*true/g) || []).length;

// ── Count vendor fingerprints from fingerprint files ──
const fpDir = join(root, 'src/fingerprints');
const fpFiles = readdirSync(fpDir).filter(f => f.endsWith('.ts') && f !== 'index.ts');
let vendorCount = 0;
for (const f of fpFiles) {
  const src = readFileSync(join(fpDir, f), 'utf8');
  vendorCount += (src.match(/\bvendor:/g) || []).length;
}

// ── Count versionExtract entries ──
let versionExtractCount = 0;
for (const f of fpFiles) {
  const src = readFileSync(join(fpDir, f), 'utf8');
  versionExtractCount += (src.match(/\bversionExtract:/g) || []).length;
}

// ── Count tests ──
const testsDir = join(root, 'tests');
const testFiles = readdirSync(testsDir).filter(f => f.endsWith('.test.ts'));
const testFileCount = testFiles.length;
let testCaseCount = 0;
for (const f of testFiles) {
  const src = readFileSync(join(testsDir, f), 'utf8');
  testCaseCount += (src.match(/\b(it|test)\s*\(/g) || []).length;
}

console.log(`Vendors: ${vendorCount}, Fingerprints: ${fpFiles.length} files, CVEs: ${cveCount}, CISA KEV: ${kevCount}`);
console.log(`Version extractors: ${versionExtractCount}`);
console.log(`Tests: ${testCaseCount} across ${testFileCount} files`);

// ── Document consistency check ──
const readme = readFileSync(join(root, 'README.md'), 'utf8');
const changelog = readFileSync(join(root, 'CHANGELOG.md'), 'utf8');

const checks = [
  { label: 'Vendors', actual: vendorCount, pattern: /(\d+)\s*VPN Vendors/ },
  { label: 'CVEs', actual: cveCount, pattern: /(\d+)\s*Critical CVEs/ },
  { label: 'CISA KEV', actual: kevCount, pattern: /\((\d+)\s*KEV\)/ },
];

// Extract 1.0.0 section from CHANGELOG
const v1Section = changelog.match(/## \[1\.0\.0\][\s\S]*?(?=\n## \[|$)/)?.[0] || '';

const changelogChecks = [
  { label: 'CHANGELOG vendors', actual: vendorCount, pattern: /\*\*(\d+) vendors\*\*/ },
  { label: 'CHANGELOG CVEs', actual: cveCount, pattern: /\*\*(\d+) CVEs\*\*/ },
  { label: 'CHANGELOG KEV', actual: kevCount, pattern: /\*\*(\d+) CISA KEV\*\*/ },
  { label: 'CHANGELOG tests', actual: testCaseCount, pattern: /\*\*(\d+) tests\*\*/ },
  { label: 'CHANGELOG test files', actual: testFileCount, pattern: /(\d+) test files/ },
];

let mismatch = false;

for (const { label, actual, pattern } of checks) {
  const m = readme.match(pattern);
  if (m) {
    const docVal = parseInt(m[1], 10);
    if (docVal !== actual) {
      console.warn(`⚠️  README ${label}: doc=${docVal}, actual=${actual}`);
      mismatch = true;
    }
  }
}

// README project structure checks
const readmeTestMatch = readme.match(/(\d+) tests across (\d+) files/);
if (readmeTestMatch) {
  const [, docTests, docFiles] = readmeTestMatch.map(Number);
  if (docTests !== testCaseCount) {
    console.warn(`⚠️  README tests: doc=${docTests}, actual=${testCaseCount}`);
    mismatch = true;
  }
  if (docFiles !== testFileCount) {
    console.warn(`⚠️  README test files: doc=${docFiles}, actual=${testFileCount}`);
    mismatch = true;
  }
}

// README vulnerabilities.ts line check
const readmeCveLineMatch = readme.match(/vulnerabilities\.ts\s*#\s*CVE database \((\d+) CVEs\)/);
if (readmeCveLineMatch) {
  const docCve = parseInt(readmeCveLineMatch[1], 10);
  if (docCve !== cveCount) {
    console.warn(`⚠️  README project structure CVEs: doc=${docCve}, actual=${cveCount}`);
    mismatch = true;
  }
}

for (const { label, actual, pattern } of changelogChecks) {
  const m = v1Section.match(pattern);
  if (m) {
    const docVal = parseInt(m[1], 10);
    if (docVal !== actual) {
      console.warn(`⚠️  ${label}: doc=${docVal}, actual=${actual}`);
      mismatch = true;
    }
  }
}

if (mismatch) {
  if (checkMode) {
    console.error('\n❌ Document stats mismatch! Run: node scripts/count-stats.mjs and update docs.');
    process.exit(1);
  } else {
    console.warn('\n⚠️  Some document stats are outdated. Update README.md and CHANGELOG.md.');
    process.exit(1);
  }
} else {
  console.log('✅ All document stats match actual data.');
}
