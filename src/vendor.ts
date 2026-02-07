/**
 * Vendor normalization — shared between CLI and API (Scanner).
 */

/** Vendor alias map: common alternative spellings → canonical vendor id */
export const VENDOR_ALIASES: Record<string, string> = {
  'palo-alto': 'paloalto',
  'palo_alto': 'paloalto',
  'paloaltonetworks': 'paloalto',
  'sonic-wall': 'sonicwall',
  'sonic_wall': 'sonicwall',
  'check-point': 'checkpoint',
  'check_point': 'checkpoint',
  'pulse-secure': 'pulse',
  'pulsesecure': 'pulse',
};

/**
 * Resolve a user-provided vendor string to its canonical vendor id.
 * Returns the canonical id or null if not found.
 */
export function resolveVendor(input: string, knownVendors: string[]): string | null {
  const normalized = input.trim().toLowerCase();
  // Direct match
  if (knownVendors.includes(normalized)) return normalized;
  // Alias match
  const aliased = VENDOR_ALIASES[normalized];
  if (aliased && knownVendors.includes(aliased)) return aliased;
  return null;
}
