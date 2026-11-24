import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { createAppServer } from '../src/server.js';
import {
  isNonPublicIp,
  validateTargetUrl,
  safeFetch,
  readTextBounded,
  InMemoryRateLimiter
} from '../src/securityGuard.js';
import { LocalHistoryStore } from '../src/apiHandlers.js';
import vercelHealthHandler from '../api/health.js';

function startServer(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

function stopServer(server) {
  server.closeAllConnections?.();
  return new Promise((resolve) => server.close(resolve));
}

// =========================================================================
// 1. SSRF IP & URL Guard Unit Tests (FS-01)
// =========================================================================
test('isNonPublicIp blocks loopback, RFC 1918, cloud metadata, CGNAT, IPv6 ULA & IPv4-mapped IPv6', () => {
  const blocked = [
    '127.0.0.1',
    '127.255.255.254',
    '10.0.0.1',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '::1',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'fe80::1%eth0',
    '::ffff:127.0.0.1',
    '::ffff:169.254.169.254',
    '::ffff:7f00:1'
  ];
  for (const ip of blocked) {
    assert.equal(isNonPublicIp(ip), true, `Expected ${ip} to be blocked`);
  }

  const allowed = ['93.184.216.34', '1.1.1.1', '8.8.8.8', '172.32.0.1', '2606:2800:220:1::248'];
  for (const ip of allowed) {
    assert.equal(isNonPublicIp(ip), false, `Expected ${ip} to be allowed`);
  }
});

test('validateTargetUrl blocks private hosts, metadata IPs, embedded credentials, and DNS rebinding to private IPs in publicMode', async () => {
  const blockedUrls = [
    'http://169.254.169.254/latest/meta-data/',
    'http://127.0.0.1:3847',
    'http://localhost/app/',
    'http://sub.localhost/',
    'http://172.16.0.1/',
    'http://[::1]/',
    'https://admin:secret@example.com/'
  ];

  for (const url of blockedUrls) {
    const res = await validateTargetUrl(url, { publicMode: true });
    assert.equal(res.ok, false, `Expected ${url} to be rejected`);
  }

  // Simulated DNS resolving an innocent-looking public domain to an internal IP
  const rebindRes = await validateTargetUrl('https://rebind.attacker.example', {
    publicMode: true,
    dnsLookup: async () => [{ address: '10.0.0.5', family: 4 }]
  });
  assert.equal(rebindRes.ok, false);
  assert.equal(rebindRes.code, 'SSRF_BLOCKED');

  // Public DNS resolution succeeds
  const okRes = await validateTargetUrl('https://example.com', {
    publicMode: true,
    dnsLookup: async () => [{ address: '93.184.216.34', family: 4 }]
  });
  assert.equal(okRes.ok, true);
});

test('safeFetch blocks SSRF redirect hops from a public host to 127.0.0.1 in publicMode', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).startsWith('https://public.example')) {
      return new Response('', {
        status: 302,
        headers: { Location: 'http://127.0.0.1:8080/internal-admin' }
      });
    }
    throw new Error('Should never fetch redirected internal URL');
  };

  try {
    await assert.rejects(
      () => safeFetch('https://public.example/', {}, {
        publicMode: true,
        dnsLookup: async () => [{ address: '93.184.216.34', family: 4 }]
      }),
      (err) => err.code === 'SSRF_BLOCKED'
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// =========================================================================
// 2. Bounded Response Stream Reader (FS-06)
// =========================================================================
test('readTextBounded caps large response streams cleanly at maxBytes', async () => {
  const chunk = new Uint8Array(4096).fill(65); // 'AAAA...'
  let chunksEmitted = 0;
  const stream = new ReadableStream({
    pull(controller) {
      chunksEmitted += 1;
      if (chunksEmitted > 50) {
        controller.close();
      } else {
        controller.enqueue(chunk);
      }
    }
  });
  const res = new Response(stream);
  const text = await readTextBounded(res, 1024);
  assert.equal(text.length, 1024);
  assert.ok(chunksEmitted <= 2, 'Stream should be cancelled early without reading all chunks');
});

// =========================================================================
// 3. Public / Vercel Mode API Security & Contract Tests (FS-01..FS-07, QA-01..QA-06)
// =========================================================================
test('Public mode API enforces SSRF, disables OTP & server history, sets HSTS, rate limits, and supports stateless HTML preview', async () => {
  const server = createAppServer({
    publicMode: true,
    rateLimitMax: 2,
    rateLimitWindowMs: 60_000,
    dnsLookup: async () => [{ address: '93.184.216.34', family: 4 }]
  });
  const baseUrl = await startServer(server);

  try {
    // Health reports public mode, feature flags, and HSTS header
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    assert.match(healthRes.headers.get('strict-transport-security') || '', /max-age=31536000/);
    const healthJson = await healthRes.json();
    assert.equal(healthJson.data.mode, 'public');
    assert.equal(healthJson.data.features.otpTest, false);
    assert.equal(healthJson.data.features.serverHistory, false);
    assert.equal(healthJson.data.features.pdfDirect, false);

    // Server-side history is disabled in public mode (FS-05)
    const histRes = await fetch(`${baseUrl}/api/history`);
    assert.equal(histRes.status, 403);
    assert.equal((await histRes.json()).error.code, 'HISTORY_LOCAL_ONLY');

    // Direct binary PDF endpoint cleanly reports unavailable in public mode (QA-02)
    const pdfRes = await fetch(`${baseUrl}/api/export/pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ report: { hostname: 'example.com', findings: [] } })
    });
    assert.equal(pdfRes.status, 503);
    assert.equal((await pdfRes.json()).error.code, 'PDF_ENGINE_UNAVAILABLE');

    // Cross-origin POST /api/audit is blocked (FS-03)
    const crossOriginRes = await fetch(`${baseUrl}/api/audit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://evil-attacker.example'
      },
      body: JSON.stringify({ url: 'https://example.com' })
    });
    assert.equal(crossOriginRes.status, 403);
    assert.equal((await crossOriginRes.json()).error.code, 'CROSS_ORIGIN_FORBIDDEN');

    // SSRF cloud metadata blocked (FS-01) — counts as request #1 against rate limiter
    const ssrfRes = await fetch(`${baseUrl}/api/audit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/' })
    });
    assert.equal(ssrfRes.status, 422);
    assert.equal((await ssrfRes.json()).error.code, 'SSRF_BLOCKED');

    // OTP active probe hard-blocked in public mode even with confirmOtp: true (FS-02) — request #2
    const otpRes = await fetch(`${baseUrl}/api/audit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: 'https://example.com',
        confirmOtp: true,
        otpTest: {
          url: 'https://example.com/api/otp',
          recipient: '09171234567'
        }
      })
    });
    assert.equal(otpRes.status, 403);
    assert.equal((await otpRes.json()).error.code, 'OTP_DISABLED_IN_PUBLIC_MODE');

    // Rate limit triggered on 3rd request (FS-03)
    const limitedRes = await fetch(`${baseUrl}/api/audit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com' })
    });
    assert.equal(limitedRes.status, 429);
    assert.ok(Number(limitedRes.headers.get('retry-after')) >= 1);
    assert.equal((await limitedRes.json()).error.code, 'RATE_LIMIT_EXCEEDED');

    // Stateless HTML preview via form POST with autoPrint=1 (QA-02, QA-03)
    const sampleReport = {
      targetUrl: 'https://example.com',
      hostname: 'example.com',
      isInternalHost: false,
      scanTime: '2026-11-23T00:00:00.000Z',
      score: 95,
      grade: 'A+',
      findings: [{ severity: 'PASS', category: 'Security Headers', title: 'HSTS Active', description: 'OK', remediation: '' }]
    };
    const formBody = new URLSearchParams({
      report: JSON.stringify(sampleReport),
      autoPrint: '1'
    }).toString();

    const htmlRes = await fetch(`${baseUrl}/api/export/html`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody
    });
    assert.equal(htmlRes.status, 200);
    const html = await htmlRes.text();
    assert.match(html, /href="\/report\.css"/);
    assert.match(html, /data-auto-print="true"/);
    assert.match(html, /example\.com/);
  } finally {
    await stopServer(server);
  }
});

// =========================================================================
// 4. LocalHistoryStore removeById integrity & Vercel Handler smoke test
// =========================================================================
test('LocalHistoryStore removeById deletes only the targeted record', async () => {
  const tmpFile = path.join(os.tmpdir(), `kalasag-store-${Date.now()}.json`);
  const store = new LocalHistoryStore(tmpFile);
  try {
    const a = await store.add({ targetUrl: 'https://a.example', hostname: 'a.example', score: 90, grade: 'A', findings: [] }, 100);
    const b = await store.add({ targetUrl: 'https://b.example', hostname: 'b.example', score: 85, grade: 'A', findings: [] }, 120);

    const removed = await store.removeById(a.id);
    assert.equal(removed, true);
    const remaining = await store.listSummaries();
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0].id, b.id);
  } finally {
    await fs.rm(tmpFile, { force: true }).catch(() => {});
  }
});

test('Vercel serverless api/health.js handler responds 200 on GET and 405 on POST', async () => {
  const makeMockRes = () => {
    const headers = new Map();
    return {
      statusCode: 0,
      body: '',
      setHeader(k, v) { headers.set(k.toLowerCase(), v); },
      getHeader(k) { return headers.get(k.toLowerCase()); },
      end(data) { this.body = String(data || ''); }
    };
  };

  const getRes = makeMockRes();
  await vercelHealthHandler({ method: 'GET', headers: {} }, getRes);
  assert.equal(getRes.statusCode, 200);
  const payload = JSON.parse(getRes.body);
  assert.equal(payload.status, 'success');
  assert.equal(payload.data.app, 'Kalasag Audit');

  const postRes = makeMockRes();
  await vercelHealthHandler({ method: 'POST', headers: {} }, postRes);
  assert.equal(postRes.statusCode, 405);
  assert.equal(postRes.getHeader('allow'), 'GET');
});

test('InMemoryRateLimiter enforces sliding window and resets cleanly', () => {
  const limiter = new InMemoryRateLimiter({ maxRequests: 2, windowMs: 1000 });
  assert.equal(limiter.check('1.2.3.4', 1000).allowed, true);
  assert.equal(limiter.check('1.2.3.4', 1100).allowed, true);
  const blocked = limiter.check('1.2.3.4', 1200);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSec, 1);
  // After window passes, allowed again
  assert.equal(limiter.check('1.2.3.4', 2001).allowed, true);
});
