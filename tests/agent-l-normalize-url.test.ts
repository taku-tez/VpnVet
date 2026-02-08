/**
 * Agent L: normalizeUrl scheme strictness (#3)
 */
import { normalizeUrl } from '../src/utils.js';

describe('normalizeUrl scheme strictness (#3)', () => {
  it('should accept uppercase HTTP scheme', () => {
    expect(normalizeUrl('HTTP://example.com')).toBe('HTTP://example.com');
  });

  it('should accept uppercase HTTPS scheme', () => {
    expect(normalizeUrl('HTTPS://example.com')).toBe('HTTPS://example.com');
  });

  it('should accept mixed case scheme', () => {
    expect(normalizeUrl('HtTpS://example.com')).toBe('HtTpS://example.com');
  });

  it('should reject ftp:// scheme', () => {
    expect(() => normalizeUrl('ftp://example.com')).toThrow('unsupported scheme');
  });

  it('should reject FTP:// (uppercase) scheme', () => {
    expect(() => normalizeUrl('FTP://example.com')).toThrow('unsupported scheme');
  });

  it('should reject ssh:// scheme', () => {
    expect(() => normalizeUrl('ssh://example.com')).toThrow('unsupported scheme');
  });

  it('should reject file:// scheme', () => {
    expect(() => normalizeUrl('file:///etc/passwd')).toThrow('unsupported scheme');
  });

  it('should prepend https:// for bare hostnames', () => {
    expect(normalizeUrl('example.com')).toBe('https://example.com');
  });

  it('should reject empty target', () => {
    expect(() => normalizeUrl('')).toThrow('empty target');
  });
});
