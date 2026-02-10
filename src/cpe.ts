/**
 * CPE (Common Platform Enumeration) 2.3 string generation
 *
 * Maps VpnVet vendor/product combinations to NVD-compatible CPE 2.3 URIs.
 * Reference: https://nvd.nist.gov/products/cpe
 */

import type { VpnVendor } from './types.js';

/**
 * CPE mapping entry.
 * part: 'o' = OS, 'a' = application, 'h' = hardware
 */
export interface CpeMapping {
  part: 'o' | 'a' | 'h';
  cpeVendor: string;
  cpeProduct: string;
}

/**
 * Mapping table: key = `${vendor}/${product}` (product as used in fingerprints/vulns).
 * Values use NVD CPE dictionary vendor/product names.
 */
export const CPE_MAPPINGS: Record<string, CpeMapping> = {
  // Tier 1 Enterprise
  'fortinet/FortiGate':           { part: 'o', cpeVendor: 'fortinet', cpeProduct: 'fortios' },
  'fortinet/FortiProxy':          { part: 'o', cpeVendor: 'fortinet', cpeProduct: 'fortiproxy' },
  'fortinet/FortiManager':        { part: 'o', cpeVendor: 'fortinet', cpeProduct: 'fortimanager' },
  'fortinet/FortiWeb':            { part: 'o', cpeVendor: 'fortinet', cpeProduct: 'fortiweb' },
  'fortinet/FortiSIEM':           { part: 'a', cpeVendor: 'fortinet', cpeProduct: 'fortisiem' },
  'paloalto/GlobalProtect':       { part: 'o', cpeVendor: 'paloaltonetworks', cpeProduct: 'pan-os' },
  'cisco/AnyConnect':             { part: 'a', cpeVendor: 'cisco', cpeProduct: 'anyconnect_secure_mobility_client' },
  'cisco/ASA':                    { part: 'o', cpeVendor: 'cisco', cpeProduct: 'adaptive_security_appliance_software' },
  'cisco/FTD':                    { part: 'a', cpeVendor: 'cisco', cpeProduct: 'firepower_threat_defense' },
  'pulse/Pulse Connect Secure':   { part: 'a', cpeVendor: 'ivanti', cpeProduct: 'connect_secure' },
  'ivanti/Connect Secure':        { part: 'a', cpeVendor: 'ivanti', cpeProduct: 'connect_secure' },
  'ivanti/EPMM':                  { part: 'a', cpeVendor: 'ivanti', cpeProduct: 'endpoint_manager_mobile' },
  'citrix/Citrix Gateway':        { part: 'a', cpeVendor: 'citrix', cpeProduct: 'netscaler_gateway' },

  // Tier 2 Enterprise
  'sonicwall/SMA':                { part: 'o', cpeVendor: 'sonicwall', cpeProduct: 'sma_firmware' },
  'checkpoint/Mobile Access':     { part: 'o', cpeVendor: 'checkpoint', cpeProduct: 'quantum_security_gateway' },
  'openvpn/Access Server':        { part: 'a', cpeVendor: 'openvpn', cpeProduct: 'openvpn_access_server' },
  'f5/BIG-IP APM':                { part: 'a', cpeVendor: 'f5', cpeProduct: 'big-ip_access_policy_manager' },
  'juniper/SRX SSL VPN':          { part: 'o', cpeVendor: 'juniper', cpeProduct: 'junos' },
  'zyxel/USG/ZyWALL':             { part: 'o', cpeVendor: 'zyxel', cpeProduct: 'atp_firmware' },
  'sophos/XG Firewall':           { part: 'o', cpeVendor: 'sophos', cpeProduct: 'sfos' },
  'watchguard/Firebox':           { part: 'o', cpeVendor: 'watchguard', cpeProduct: 'fireware' },
  'barracuda/CloudGen Firewall':  { part: 'o', cpeVendor: 'barracuda', cpeProduct: 'cloudgen_firewall_firmware' },

  // SMB / SOHO
  'draytek/Vigor':                { part: 'o', cpeVendor: 'draytek', cpeProduct: 'vigor_firmware' },
  'mikrotik/RouterOS':            { part: 'o', cpeVendor: 'mikrotik', cpeProduct: 'routeros' },
  'ubiquiti/UniFi':               { part: 'o', cpeVendor: 'ui', cpeProduct: 'unifi_security_gateway_firmware' },
  'pfsense/pfSense':              { part: 'a', cpeVendor: 'pfsense', cpeProduct: 'pfsense' },
  'opnsense/OPNsense':            { part: 'a', cpeVendor: 'opnsense', cpeProduct: 'opnsense' },
  'netgear/ProSAFE':              { part: 'o', cpeVendor: 'netgear', cpeProduct: 'prosafe_firmware' },
  'tplink/Omada':                 { part: 'o', cpeVendor: 'tp-link', cpeProduct: 'omada_software_controller' },
  'stormshield/SNS':              { part: 'o', cpeVendor: 'stormshield', cpeProduct: 'stormshield_network_security' },
  'lancom/LANCOM':                { part: 'o', cpeVendor: 'lancom', cpeProduct: 'lcos' },
  'kerio/Kerio Control':          { part: 'a', cpeVendor: 'gfi', cpeProduct: 'kerio_control' },
  'untangle/NG Firewall':         { part: 'a', cpeVendor: 'untangle', cpeProduct: 'ng_firewall' },
  'endian/Endian UTM':            { part: 'o', cpeVendor: 'endian', cpeProduct: 'endian_firewall' },

  // Asia / China
  'sangfor/SSL VPN':              { part: 'a', cpeVendor: 'sangfor', cpeProduct: 'ssl_vpn' },
  'array/AG Series':              { part: 'a', cpeVendor: 'arraynetworks', cpeProduct: 'arrayos_ag' },
  'netmotion/Mobility':           { part: 'a', cpeVendor: 'netmotion', cpeProduct: 'mobility' },
  'hillstone/NGFW':               { part: 'o', cpeVendor: 'hillstonenet', cpeProduct: 'stoneos' },
  'huawei/USG':                   { part: 'o', cpeVendor: 'huawei', cpeProduct: 'usg_firmware' },
  'h3c/SecPath':                  { part: 'o', cpeVendor: 'h3c', cpeProduct: 'secpath_firmware' },
  'ruijie/RG Series':             { part: 'o', cpeVendor: 'ruijie', cpeProduct: 'rg_firmware' },
  'nsfocus/NSFOCUS':              { part: 'a', cpeVendor: 'nsfocus', cpeProduct: 'nsfocus_firewall' },
  'venustech/Venusense':          { part: 'a', cpeVendor: 'venustech', cpeProduct: 'venusense' },
  'topsec/TopSec':                { part: 'a', cpeVendor: 'topsec', cpeProduct: 'topsec_firewall' },
  'dptech/DPtech':                { part: 'a', cpeVendor: 'dptech', cpeProduct: 'dptech_firewall' },

  // Korea
  'ahnlab/TrusGuard':             { part: 'o', cpeVendor: 'ahnlab', cpeProduct: 'trusguard_firmware' },
  'secui/MF2':                    { part: 'o', cpeVendor: 'secui', cpeProduct: 'mf2_firmware' },

  // Open Source
  'wireguard/WireGuard':          { part: 'a', cpeVendor: 'wireguard', cpeProduct: 'wireguard' },

  // Enterprise Mobility
  'mobileiron/MobileIron':        { part: 'a', cpeVendor: 'ivanti', cpeProduct: 'mobileiron' },

  // Cloud / ZTNA
  'meraki/MX':                    { part: 'o', cpeVendor: 'cisco', cpeProduct: 'meraki_mx_firmware' },
  'aruba/ClearPass':              { part: 'a', cpeVendor: 'arubanetworks', cpeProduct: 'clearpass_policy_manager' },
  'zscaler/ZPA':                  { part: 'a', cpeVendor: 'zscaler', cpeProduct: 'zscaler_private_access' },
  'cloudflare/Access':            { part: 'a', cpeVendor: 'cloudflare', cpeProduct: 'access' },
  'netskope/Netskope':            { part: 'a', cpeVendor: 'netskope', cpeProduct: 'netskope' },
  'cato/Cato':                    { part: 'a', cpeVendor: 'catonetworks', cpeProduct: 'cato_networks' },
};

/**
 * Build a CPE 2.3 formatted string for a given vendor/product/version.
 *
 * @returns CPE 2.3 string, or undefined if no mapping exists.
 */
export function buildCpe(vendor: string, product: string, version?: string): string | undefined {
  const key = `${vendor}/${product}`;
  const mapping = CPE_MAPPINGS[key];
  if (!mapping) return undefined;

  const ver = version ? escapeCpeComponent(version) : '*';
  return `cpe:2.3:${mapping.part}:${mapping.cpeVendor}:${mapping.cpeProduct}:${ver}:*:*:*:*:*:*:*`;
}

/**
 * Look up the CPE mapping for a vendor/product key.
 */
export function getCpeMapping(vendor: string, product: string): CpeMapping | undefined {
  return CPE_MAPPINGS[`${vendor}/${product}`];
}

/**
 * Escape special characters in CPE 2.3 component values.
 * Per CPE spec, special chars (? * \ ! " #) are escaped with backslash.
 */
function escapeCpeComponent(value: string): string {
  return value.replace(/([\\*?!"#])/g, '\\$1');
}
