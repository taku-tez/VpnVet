import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fpDir = path.join(__dirname, '..', 'src', 'fingerprints');
const indexPath = path.join(fpDir, 'index.ts');
const content = fs.readFileSync(indexPath, 'utf-8');

// Categories with vendors
const categories = {
  'tier1-enterprise': {
    desc: 'Tier 1 Enterprise (16 CISA KEV CVEs)',
    vendors: ['fortinet', 'paloalto', 'cisco', 'pulse', 'ivanti', 'citrix']
  },
  'tier2-enterprise': {
    desc: 'Tier 2 Enterprise (10 CISA KEV CVEs)',
    vendors: ['sonicwall', 'checkpoint', 'openvpn', 'f5', 'juniper', 'zyxel', 'sophos', 'watchguard', 'barracuda']
  },
  'asia': {
    desc: 'Asia Regional (China, Korea, Japan)',
    vendors: ['sangfor', 'array', 'netmotion', 'hillstone', 'huawei', 'h3c', 'ruijie', 'nsfocus', 'venustech', 'topsec', 'dptech', 'ahnlab', 'secui']
  },
  'smb-soho': {
    desc: 'SMB/SOHO (Small/Medium Business)',
    vendors: ['draytek', 'mikrotik', 'ubiquiti', 'pfsense', 'opnsense', 'netgear', 'tplink', 'stormshield', 'lancom', 'kerio', 'untangle', 'endian']
  },
  'cloud-ztna': {
    desc: 'Cloud/ZTNA (Zero Trust Network Access)',
    vendors: ['meraki', 'aruba', 'zscaler', 'cloudflare']
  },
};

// Find vendor blocks using regex
function extractVendorBlocks(content) {
  const blocks = {};
  const lines = content.split('\n');
  
  let currentVendor = null;
  let blockStart = -1;
  let braceCount = 0;
  let inBlock = false;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Check for vendor line
    const vendorMatch = line.match(/^\s*vendor:\s*'(\w+)'/);
    if (vendorMatch) {
      currentVendor = vendorMatch[1];
      // Find block start (look back for comment or opening brace)
      for (let j = i - 1; j >= 0; j--) {
        if (lines[j].includes('// ===')) {
          blockStart = j;
          break;
        }
        if (lines[j].trim() === '{') {
          blockStart = j;
          break;
        }
      }
      braceCount = 1;
      inBlock = true;
    }
    
    if (inBlock && currentVendor) {
      // Count braces
      for (const char of line) {
        if (char === '{') braceCount++;
        if (char === '}') braceCount--;
      }
      
      // Check if block ends
      if (braceCount === 0 && line.trim().startsWith('},')) {
        const block = lines.slice(blockStart, i + 1).join('\n');
        blocks[currentVendor] = block;
        currentVendor = null;
        inBlock = false;
      }
    }
  }
  
  return blocks;
}

const vendorBlocks = extractVendorBlocks(content);
console.log('Found vendors:', Object.keys(vendorBlocks).join(', '));

// Write category files
for (const [catName, catInfo] of Object.entries(categories)) {
  const exportName = catName.replace(/-/g, '').replace(/^\w/, c => c.toLowerCase()) + 'Fingerprints';
  const blocks = catInfo.vendors.map(v => vendorBlocks[v]).filter(Boolean);
  
  if (blocks.length === 0) {
    console.log(`Warning: No blocks found for ${catName}`);
    continue;
  }
  
  const catContent = `/**
 * ${catInfo.desc}
 */

import type { Fingerprint } from '../types.js';

export const ${exportName}: Fingerprint[] = [
${blocks.join('\n')}
];
`;
  
  fs.writeFileSync(path.join(fpDir, `${catName}.ts`), catContent);
  console.log(`Created ${catName}.ts with ${catInfo.vendors.length} vendors (${blocks.length} found)`);
}

console.log('Done!');
