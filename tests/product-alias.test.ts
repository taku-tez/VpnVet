/**
 * Tests for product alias resolution (#2)
 */
import { resolveProductAlias, resolveProductAndVendor, PRODUCT_ALIASES } from '../src/product.js';

describe('resolveProductAlias', () => {
  it('resolves "Pulse Connect Secure" → "Connect Secure"', () => {
    expect(resolveProductAlias('Pulse Connect Secure')).toBe('Connect Secure');
  });

  it('resolves "NetScaler Gateway" → "Citrix Gateway"', () => {
    expect(resolveProductAlias('NetScaler Gateway')).toBe('Citrix Gateway');
  });

  it('resolves "FortiOS" → "FortiGate"', () => {
    expect(resolveProductAlias('FortiOS')).toBe('FortiGate');
  });

  it('resolves "BIG-IP" → "BIG-IP APM"', () => {
    expect(resolveProductAlias('BIG-IP')).toBe('BIG-IP APM');
  });

  it('resolves "Cyberoam" → "XG Firewall"', () => {
    expect(resolveProductAlias('Cyberoam')).toBe('XG Firewall');
  });

  it('resolves "PAN-OS" → "GlobalProtect"', () => {
    expect(resolveProductAlias('PAN-OS')).toBe('GlobalProtect');
  });

  it('resolves "Cisco ASA" → "AnyConnect"', () => {
    expect(resolveProductAlias('Cisco ASA')).toBe('AnyConnect');
  });

  it('returns original product name when no alias matches', () => {
    expect(resolveProductAlias('UnknownProduct')).toBe('UnknownProduct');
  });

  it('is case-insensitive', () => {
    expect(resolveProductAlias('pulse connect secure')).toBe('Connect Secure');
    expect(resolveProductAlias('PULSE CONNECT SECURE')).toBe('Connect Secure');
    expect(resolveProductAlias('Pulse  Connect  Secure')).toBe('Connect Secure');
  });
});

describe('resolveProductAndVendor', () => {
  it('resolves Pulse → Ivanti vendor + product', () => {
    const result = resolveProductAndVendor('Pulse Connect Secure');
    expect(result).toEqual({ vendor: 'ivanti', product: 'Connect Secure' });
  });

  it('resolves NetScaler → Citrix vendor + product', () => {
    const result = resolveProductAndVendor('NetScaler Gateway');
    expect(result).toEqual({ vendor: 'citrix', product: 'Citrix Gateway' });
  });

  it('returns null for unknown products', () => {
    expect(resolveProductAndVendor('SomeRandomProduct')).toBeNull();
  });
});

describe('PRODUCT_ALIASES dictionary', () => {
  it('has at least 20 entries', () => {
    expect(Object.keys(PRODUCT_ALIASES).length).toBeGreaterThanOrEqual(20);
  });

  it('all keys are lowercase', () => {
    for (const key of Object.keys(PRODUCT_ALIASES)) {
      expect(key).toBe(key.toLowerCase());
    }
  });

  it('all entries have vendor and canonical fields', () => {
    for (const [key, alias] of Object.entries(PRODUCT_ALIASES)) {
      expect(alias.vendor).toBeTruthy();
      expect(alias.canonical).toBeTruthy();
    }
  });
});
