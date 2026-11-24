import dns from 'node:dns/promises';
import net from 'node:net';

export const MAX_URL_LENGTH = 2048;
export const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1024; // 512 KB

export function isPublicDeployment(env = process.env) {
  return env.VERCEL === '1' || String(env.KALASAG_PUBLIC_MODE || '').toLowerCase() === 'true';
}

function parseIpv4(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(p => (/^\d+$/.test(p) ? Number(p) : NaN));
  if (nums.some(n => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return nums;
}

/**
 * Returns true if an IPv4 or IPv6 address belongs to a non-public range
 * (loopback, RFC 1918 private, link-local / cloud metadata 169.254.x.x,
 * CGNAT 100.64.0.0/10, multicast, ULA fc00::/7, fe80::/10, or IPv4-mapped IPv6).
 */
export function isNonPublicIp(rawIp) {
  const ip = String(rawIp || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (!ip) return true;

  // Strip IPv6 zone identifier if present (e.g. fe80::1%eth0)
  const cleanIp = ip.split('%')[0];

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (cleanIp.startsWith('::ffff:')) {
    const mapped = cleanIp.slice(7);
    if (mapped.includes('.')) return isNonPublicIp(mapped);
    const hexParts = mapped.split(':');
    if (hexParts.length === 2) {
      const hi = parseInt(hexParts[0], 16);
      const lo = parseInt(hexParts[1], 16);
      if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
        const ipv4 = `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
        return isNonPublicIp(ipv4);
      }
    }
    return true;
  }

  const ipv4 = parseIpv4(cleanIp);
  if (ipv4) {
    const [a, b, c] = ipv4;
    if (a === 0) return true;                           // 0.0.0.0/8 ("this network")
    if (a === 10) return true;                          // 10.0.0.0/8 (RFC 1918)
    if (a === 100 && b >= 64 && b <= 127) return true;  // 100.64.0.0/10 (CGNAT)
    if (a === 127) return true;                         // 127.0.0.0/8 (loopback)
    if (a === 169 && b === 254) return true;            // 169.254.0.0/16 (link-local / cloud metadata)
    if (a === 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12 (RFC 1918)
    if (a === 192 && b === 0 && c === 0) return true;   // 192.0.0.0/24
    if (a === 192 && b === 0 && c === 2) return true;   // TEST-NET-1
    if (a === 192 && b === 168) return true;            // 192.168.0.0/16 (RFC 1918)
    if (a === 198 && (b === 18 || b === 19)) return true; // Benchmarking
    if (a === 198 && b === 51 && c === 100) return true;  // TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return true;   // TEST-NET-3
    if (a >= 224) return true;                          // Multicast & reserved (224.0.0.0+)
    return false;
  }

  if (net.isIP(cleanIp) === 6) {
    if (cleanIp === '::' || cleanIp === '::1') return true;
    // Expand or check first hextet
    const first = cleanIp.split(':')[0] || '0';
    const val = parseInt(first, 16);
    if (Number.isNaN(val)) return true;
    if ((val & 0xfe00) === 0xfc00) return true; // fc00::/7 Unique Local Address
    if ((val & 0xffc0) === 0xfe80) return true; // fe80::/10 Link-Local
    if ((val & 0xff00) === 0xff00) return true; // ff00::/8 Multicast
    return false;
  }

  return true; // Unrecognized IP format: fail closed
}

export function isPrivateHostnameLiteral(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan') || h.endsWith('.home.arpa')) {
    return true;
  }
  if (net.isIP(h)) {
    return isNonPublicIp(h);
  }
  return false;
}

/**
 * Validates target URL syntax, scheme, and — when publicMode is enabled —
 * resolves DNS to ensure every target IP is strictly public (prevents SSRF).
 */
export async function validateTargetUrl(rawUrl, options = {}) {
  const publicMode = Boolean(options.publicMode);
  const lookupFn = options.dnsLookup || ((host) => dns.lookup(host, { all: true }));

  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { ok: false, code: 'VALIDATION_ERROR', error: 'A target URL is required (e.g., https://example.com).' };
  }

  const trimmed = rawUrl.trim();
  if (trimmed.length > MAX_URL_LENGTH) {
    return { ok: false, code: 'VALIDATION_ERROR', error: `Target URL must be under ${MAX_URL_LENGTH} characters.` };
  }
  if (/[\s\r\n]/.test(trimmed)) {
    return { ok: false, code: 'VALIDATION_ERROR', error: 'Target URL cannot contain spaces or line breaks.' };
  }

  // Reject explicit non-http(s) schemes (ftp:, file:, javascript:, data:, etc.)
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed) && !/^https?:\/\//i.test(trimmed)) {
    if (!/^[a-zA-Z0-9.-]+:\d+(?:\/|$)/.test(trimmed)) {
      return { ok: false, code: 'VALIDATION_ERROR', error: 'Only http:// and https:// targets are supported.' };
    }
  }

  const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    return { ok: false, code: 'VALIDATION_ERROR', error: 'Enter a valid http:// or https:// URL or hostname.' };
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, code: 'VALIDATION_ERROR', error: 'Only http:// and https:// targets are supported.' };
  }
  if (!parsed.hostname) {
    return { ok: false, code: 'VALIDATION_ERROR', error: 'Target URL is missing a hostname.' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, code: 'VALIDATION_ERROR', error: 'URLs containing embedded credentials are not allowed.' };
  }

  if (publicMode) {
    if (isPrivateHostnameLiteral(parsed.hostname)) {
      return {
        ok: false,
        code: 'SSRF_BLOCKED',
        error: 'Private, localhost, and cloud metadata addresses cannot be audited from the public web deployment. Run Kalasag Audit locally to scan internal hosts.'
      };
    }

    try {
      const addresses = await lookupFn(parsed.hostname);
      if (!Array.isArray(addresses) || addresses.length === 0) {
        return { ok: false, code: 'DNS_UNRESOLVED', error: `Could not resolve hostname "${parsed.hostname}".` };
      }
      for (const entry of addresses) {
        const ip = typeof entry === 'string' ? entry : entry.address;
        if (isNonPublicIp(ip)) {
          return {
            ok: false,
            code: 'SSRF_BLOCKED',
            error: 'Target resolved to a private or reserved IP address and was blocked for security.'
          };
        }
      }
    } catch {
      return { ok: false, code: 'DNS_UNRESOLVED', error: `Could not resolve hostname "${parsed.hostname}".` };
    }
  }

  return { ok: true, target: trimmed, normalized, parsed };
}

/**
 * Fetches a URL while manually following up to `maxRedirects` redirects and
 * re-validating every redirect destination against SSRF rules in publicMode.
 */
export async function safeFetch(url, fetchOptions = {}, guardOptions = {}) {
  const publicMode = Boolean(guardOptions.publicMode);
  const maxRedirects = guardOptions.maxRedirects ?? 4;
  let currentUrl = url;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (publicMode) {
      const check = await validateTargetUrl(currentUrl, guardOptions);
      if (!check.ok) {
        const err = new Error(check.error);
        err.code = check.code;
        throw err;
      }
    }

    const res = await fetch(currentUrl, {
      ...fetchOptions,
      redirect: 'manual'
    });

    const isRedirect = [301, 302, 303, 307, 308].includes(res.status);
    const location = res.headers.get('location');
    if (isRedirect && location && hop < maxRedirects) {
      // Cancel body before following next hop
      try { await res.body?.cancel(); } catch { /* ignore */ }
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    return { res, finalUrl: res.url || currentUrl };
  }

  throw new Error('Too many redirects while connecting to target.');
}

/**
 * Reads an HTTP response body up to `maxBytes`, then cancels the stream so a
 * malicious target cannot exhaust server memory.
 */
export async function readTextBounded(res, maxBytes = DEFAULT_MAX_RESPONSE_BYTES) {
  if (!res || !res.body || typeof res.body.getReader !== 'function') {
    const fallback = res && typeof res.text === 'function' ? await res.text() : '';
    return fallback.length > maxBytes ? fallback.slice(0, maxBytes) : fallback;
  }

  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      const remaining = maxBytes - total;
      if (value.byteLength >= remaining) {
        chunks.push(value.subarray(0, remaining));
        total += remaining;
        await reader.cancel().catch(() => {});
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(combined);
}

/**
 * Sliding-window in-memory IP rate limiter.
 */
export class InMemoryRateLimiter {
  constructor({ maxRequests = 8, windowMs = 60_000, maxKeys = 2000 } = {}) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
    this.buckets = new Map();
  }

  check(key, now = Date.now()) {
    const id = String(key || 'unknown');
    const cutoff = now - this.windowMs;

    let timestamps = this.buckets.get(id) || [];
    timestamps = timestamps.filter(ts => ts > cutoff);

    if (timestamps.length >= this.maxRequests) {
      const oldest = timestamps[0];
      const retryAfterSec = Math.max(1, Math.ceil((oldest + this.windowMs - now) / 1000));
      this.buckets.set(id, timestamps);
      return { allowed: false, remaining: 0, retryAfterSec };
    }

    timestamps.push(now);
    if (!this.buckets.has(id) && this.buckets.size >= this.maxKeys) {
      // Evict oldest key to keep memory strictly bounded
      const firstKey = this.buckets.keys().next().value;
      this.buckets.delete(firstKey);
    }
    this.buckets.set(id, timestamps);

    return {
      allowed: true,
      remaining: Math.max(0, this.maxRequests - timestamps.length),
      retryAfterSec: 0
    };
  }
}

export function extractClientIp(req) {
  const forwarded = req.headers?.['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '127.0.0.1';
}

export function isAllowedSameOrigin(req, { publicMode = false } = {}) {
  if (!publicMode) return true;
  const fetchSite = String(req.headers?.['sec-fetch-site'] || '').toLowerCase();
  if (fetchSite && !['same-origin', 'same-site', 'none'].includes(fetchSite)) {
    return false;
  }
  const origin = req.headers?.origin;
  const host = req.headers?.host;
  if (origin && host) {
    try {
      const originHost = new URL(origin).host.toLowerCase();
      if (originHost !== host.toLowerCase()) return false;
    } catch {
      return false;
    }
  }
  return true;
}
