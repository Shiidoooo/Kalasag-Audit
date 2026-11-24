// Regression tests for Kalasag Audit false alarms (2026-11-23). Every case checks both sides:
// the harmless configuration is no longer reported, and a really weak one still is.
// Network and DNS are faked, so the tests never contact a real host.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import { SecurityAuditor } from '../src/auditor.js';

const realFetch = globalThis.fetch;
const realDns = { ...dnsPromises };
afterEach(() => {
  globalThis.fetch = realFetch;
  Object.assign(dnsPromises, realDns);
});

const titles = (auditor) => auditor.findings.map(f => `${f.severity}: ${f.title}`);
const has = (auditor, pattern) => auditor.findings.some(f => pattern.test(`${f.severity}: ${f.title}`));
const page = (headers = {}, body = '<html></html>') => async () => new Response(body, { status: 200, headers });
const dnsError = (code) => Object.assign(new Error(code), { code });

async function headersFor(url, headers, body) {
  globalThis.fetch = page(headers, body);
  const auditor = new SecurityAuditor(url);
  await auditor.checkHeadersAndCookies();
  return auditor;
}

// --- CSP ------------------------------------------------------------------------------
test("CSP: 'unsafe-inline' only in style-src is not reported as unsafe scripts", async () => {
  const a = await headersFor('https://example.com', {
    'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
  });
  assert.ok(!has(a, /unsafe-inline/i), titles(a).join('\n'));
  assert.ok(has(a, /PASS: Robust Content Security Policy/));
});

test("CSP: 'unsafe-inline' in script-src (or default-src fallback) is still reported", async () => {
  const viaScript = await headersFor('https://example.com', {
    'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
  });
  assert.ok(has(viaScript, /LOW: Content Security Policy Permits 'unsafe-inline'/));
  const viaDefault = await headersFor('https://example.com', {
    'content-security-policy': "default-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
  });
  assert.ok(has(viaDefault, /unsafe-inline/));
});

test('CSP: sha384/sha512 hashes and nonces neutralise unsafe-inline', async () => {
  for (const source of ["'sha384-abc'", "'sha512-abc'", "'nonce-xyz'"]) {
    const a = await headersFor('https://example.com', {
      'content-security-policy': `default-src 'self'; script-src 'self' 'unsafe-inline' ${source}; object-src 'none'; base-uri 'self'`
    });
    assert.ok(!has(a, /unsafe-inline/i), `${source}: ${titles(a).join(' | ')}`);
  }
});

// --- HSTS -----------------------------------------------------------------------------
test('HSTS: not judged on plain-HTTP pages (browsers ignore it there)', async () => {
  const a = await headersFor('http://intranet.local', {});
  assert.ok(!has(a, /Missing HTTP Strict Transport Security/), titles(a).join('\n'));
  assert.ok(has(a, /INFO: HSTS Not Applicable Over Plain HTTP/));
});

test('HSTS: still required on HTTPS, and a quoted max-age is read correctly', async () => {
  const missing = await headersFor('https://example.com', {});
  assert.ok(has(missing, /MEDIUM: Missing HTTP Strict Transport Security/));
  const quoted = await headersFor('https://example.com', { 'strict-transport-security': 'max-age="31536000"' });
  assert.ok(has(quoted, /PASS: Strong HSTS Policy/), titles(quoted).join('\n'));
  assert.ok(!has(quoted, /Too Short/));
});

// --- Cookies --------------------------------------------------------------------------
test('Cookies: deletion headers are skipped, real insecure cookies are still reported', async () => {
  globalThis.fetch = async () => new Response('<html></html>', {
    status: 200,
    headers: [
      ['set-cookie', 'old_session=; Max-Age=0; Path=/'],
      ['set-cookie', 'remember=; Expires=Thu, 01 Jan 1970 00:00:00 GMT'],
      ['set-cookie', 'session=abc123; Path=/']
    ]
  });
  const a = new SecurityAuditor('https://example.com');
  await a.checkHeadersAndCookies();
  assert.ok(!has(a, /"old_session"|"remember"/), titles(a).join('\n'));
  assert.ok(has(a, /MEDIUM: Insecure Cookie Attributes on "session"/));
});

// --- PUT / DELETE ---------------------------------------------------------------------
test('PUT/DELETE: a catch-all 200 that stores nothing is not CRITICAL', async () => {
  globalThis.fetch = async (url, opts = {}) => new Response('<html>Welcome</html>', {
    status: (opts.method || 'GET') === 'TRACE' ? 405 : 200
  });
  const a = new SecurityAuditor('https://example.com');
  await a.checkHttpMethods();
  assert.ok(!has(a, /CRITICAL/), titles(a).join('\n'));
  assert.ok(has(a, /INFO: PUT Answered 200 but Stored Nothing/));
  assert.ok(has(a, /PASS: HTTP Methods Hardened/));
});

test('PUT/DELETE: a server that really stores and deletes files is CRITICAL, with no PASS', async () => {
  const files = new Map();
  globalThis.fetch = async (url, opts = {}) => {
    const method = opts.method || 'GET';
    const path = new URL(url).pathname;
    if (method === 'PUT') { files.set(path, String(opts.body)); return new Response(null, { status: 201 }); }
    if (method === 'DELETE') { files.delete(path); return new Response(null, { status: 204 }); }
    if (method === 'GET' && files.has(path)) return new Response(files.get(path), { status: 200 });
    return new Response('not found', { status: method === 'GET' ? 404 : 405 });
  };
  const a = new SecurityAuditor('https://example.com');
  await a.checkHttpMethods();
  assert.ok(has(a, /CRITICAL: Unauthenticated PUT Writes Files/));
  assert.ok(has(a, /CRITICAL: Unauthenticated DELETE Removes Files/));
  assert.ok(!has(a, /PASS: HTTP Methods Hardened/));
  assert.equal(files.size, 0, 'the test file must be cleaned up');
});

// --- Mixed content, SRI, library detection -------------------------------------------
async function frontendFor(html) {
  const a = new SecurityAuditor('https://example.com');
  a.cachedHtml = html;
  globalThis.fetch = async () => new Response('', { status: 404 });
  await a.checkFrontendSecretsAndScripts();
  return a;
}

test('Mixed content: canonical/alternate links and commented-out tags are ignored', async () => {
  const a = await frontendFor(`
    <link rel="canonical" href="http://example.com/page">
    <link rel="alternate" hreflang="fil" href="http://example.com/fil/">
    <!-- <script src="http://old.example.com/legacy.js"></script> -->`);
  assert.ok(!has(a, /Mixed Content/), titles(a).join('\n'));
});

test('Mixed content: a real http:// script or stylesheet is still reported', async () => {
  const a = await frontendFor('<script src="http://cdn.example.net/app.js"></script>');
  assert.ok(has(a, /MEDIUM: Active Mixed Content/));
  const css = await frontendFor('<link rel="stylesheet" href="http://cdn.example.net/site.css">');
  assert.ok(has(css, /MEDIUM: Active Mixed Content/));
});

test('SRI: services that cannot support SRI are skipped, ordinary CDNs are not', async () => {
  const fonts = await frontendFor('<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">');
  assert.ok(!has(fonts, /Subresource Integrity/), titles(fonts).join('\n'));
  const cdn = await frontendFor('<script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/lib.min.js"></script>');
  assert.ok(has(cdn, /MEDIUM: Third-Party Resources Without Subresource Integrity/));
});

test('Libraries: only licence banners count, mentions of other versions do not', () => {
  const a = new SecurityAuditor('https://example.com');
  a.scanCodeForLibraries('/*! Bootstrap v4.6.2 */ throw new Error("requires at least jQuery v1.9.1");');
  a.scanCodeForLibraries('// The unquoted-hash was removed in jQuery 1.12.0');
  assert.ok(!has(a, /Outdated Library/), titles(a).join('\n'));
  a.scanCodeForLibraries('/*! jQuery v1.9.1 | (c) 2005, 2012 jQuery Foundation */');
  assert.ok(has(a, /MEDIUM: Outdated Library: jQuery 1\.9\.1/));
});

// --- Exposed .env (missed detection fixed) -------------------------------------------
test('.env: a plain PASSWORD= line is detected; an HTML 404 page is not', async () => {
  const run = async (envBody, envType) => {
    globalThis.fetch = async (url) => new URL(url).pathname.endsWith('/.env')
      ? new Response(envBody, { status: 200, headers: { 'content-type': envType } })
      : new Response('nope', { status: 404 });
    const a = new SecurityAuditor('https://example.com');
    await a.checkExtendedArtifactsAndApis();
    return a;
  };
  assert.ok(has(await run('PASSWORD=hunter2\n', 'text/plain'), /CRITICAL: Exposed Environment File/));
  assert.ok(!has(await run('<html>404 DB_HOST=x</html>', 'text/html'), /Exposed Environment File/));
});

// --- DNS: SPF / DMARC / CAA ----------------------------------------------------------
function fakeTxt(records) {
  dnsPromises.resolveTxt = async (name) => {
    if (records[name]) return records[name].map(r => [r]);
    throw dnsError('ENODATA');
  };
  dnsPromises.resolveCaa = async () => { throw dnsError('ENODATA'); };
  dnsPromises.resolveMx = async () => { throw dnsError('ENODATA'); };
}

test('organizationalDomain handles .com.ph and other two-level suffixes', () => {
  const a = new SecurityAuditor('https://example.com');
  assert.equal(a.organizationalDomain('www.example.com.ph'), 'example.com.ph');
  assert.equal(a.organizationalDomain('app.shop.co.uk'), 'shop.co.uk');
  assert.equal(a.organizationalDomain('www.example.com'), 'example.com');
  assert.equal(a.organizationalDomain('example.com'), 'example.com');
});

test('DMARC/SPF: records on the organizational domain cover www', async () => {
  fakeTxt({
    'example.com.ph': ['v=spf1 include:spf.protection.outlook.com -all'],
    '_dmarc.example.com.ph': ['v=DMARC1; p=reject']
  });
  const a = new SecurityAuditor('https://www.example.com.ph');
  await a.checkDnsAndEmailSecurity();
  assert.ok(!has(a, /Missing (SPF|DMARC)/), titles(a).join('\n'));
  assert.ok(has(a, /PASS: SPF Record Configured/));
  assert.ok(has(a, /PASS: Enforced DMARC Policy Active/));
});

test('DMARC: sp=none is not misread as p=none, but applies to subdomains', async () => {
  fakeTxt({ 'example.com': ['v=spf1 -all'], '_dmarc.example.com': ['v=DMARC1; p=reject; sp=none'] });
  const apex = new SecurityAuditor('https://example.com');
  await apex.checkDnsAndEmailSecurity();
  assert.ok(has(apex, /PASS: Enforced DMARC Policy Active/), titles(apex).join('\n'));
  const sub = new SecurityAuditor('https://www.example.com');
  await sub.checkDnsAndEmailSecurity();
  assert.ok(has(sub, /LOW: DMARC Policy is Set to "sp=none"/), titles(sub).join('\n'));
});

test('DMARC/SPF: a domain with no records at all is still reported', async () => {
  fakeTxt({});
  const a = new SecurityAuditor('https://www.example.com');
  await a.checkDnsAndEmailSecurity();
  assert.ok(has(a, /MEDIUM: Missing DMARC Record/));
  assert.ok(has(a, /LOW: Missing SPF Record/));
});

test('CAA: a record on the parent domain counts; an unsupported resolver is not a finding', async () => {
  fakeTxt({});
  dnsPromises.resolveCaa = async (name) => {
    if (name === 'example.com') return [{ critical: 0, issue: 'letsencrypt.org' }];
    throw dnsError('ENODATA');
  };
  const covered = new SecurityAuditor('https://www.example.com');
  await covered.checkDnsRecordsExtended();
  assert.ok(has(covered, /PASS: CAA Record Published/), titles(covered).join('\n'));

  dnsPromises.resolveCaa = async () => { throw dnsError('ENOTIMP'); };
  const unsupported = new SecurityAuditor('https://www.example.com');
  await unsupported.checkDnsRecordsExtended();
  assert.ok(!has(unsupported, /CAA/), titles(unsupported).join('\n'));

  dnsPromises.resolveCaa = async () => { throw dnsError('ENODATA'); };
  const none = new SecurityAuditor('https://www.example.com');
  await none.checkDnsRecordsExtended();
  assert.ok(has(none, /LOW: No CAA Record/));
});

// --- Active injection (SQLi / XSS) ----------------------------------------------------
test('Injection: error-based SQLi and reflected XSS are detected on a vulnerable GET param', async () => {
  globalThis.fetch = async (url) => {
    const s = decodeURIComponent(String(url));
    if (s.includes("'")) {
      return new Response('<html>You have an error in your SQL syntax; near "x"</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    }
    const m = s.match(/[?&]q=([^&]+)/);
    const val = m ? m[1] : '';
    return new Response(`<html>searched: ${val}</html>`, { status: 200, headers: { 'content-type': 'text/html' } });
  };
  const a = new SecurityAuditor('http://127.0.0.1:9999/p?q=hello');
  a.cachedHtml = '<html>home</html>';
  await a.checkInjectionVulns();
  assert.ok(has(a, /CRITICAL: Error-Based SQL Injection/), titles(a).join('\n'));
  assert.ok(has(a, /HIGH: Reflected Cross-Site Scripting/), titles(a).join('\n'));
});

test('Injection: properly-encoded, non-erroring param is NOT flagged (no false alarm)', async () => {
  globalThis.fetch = async (url) => {
    const s = decodeURIComponent(String(url));
    const m = s.match(/[?&]q=([^&]+)/);
    const val = (m ? m[1] : '').replace(/</g, '&lt;').replace(/'/g, '&#39;');
    return new Response(`<html>safe: ${val}</html>`, { status: 200, headers: { 'content-type': 'text/html' } });
  };
  const a = new SecurityAuditor('http://127.0.0.1:9999/p?q=hello');
  a.cachedHtml = '<html>home</html>';
  await a.checkInjectionVulns();
  assert.ok(!has(a, /Error-Based SQL Injection|Reflected Cross-Site Scripting/), titles(a).join('\n'));
  assert.ok(has(a, /PASS: No Injection Flaws Detected/), titles(a).join('\n'));
});

test('Injection: disabled in public mode', async () => {
  const a = new SecurityAuditor('http://127.0.0.1:9999/p?q=hello', { publicMode: true });
  a.cachedHtml = '<html>home</html>';
  await a.checkInjectionVulns();
  assert.equal(a.findings.length, 0);
});

// --- Expanded exposed-artifact probes -------------------------------------------------
function mockPaths(map) {
  globalThis.fetch = async (url) => {
    const s = String(url);
    for (const [frag, resp] of Object.entries(map)) {
      if (s.includes(frag)) {
        return new Response(resp.body, { status: resp.status || 200, headers: { 'content-type': resp.contentType || 'text/html' } });
      }
    }
    return new Response('<!doctype html><html>not found</html>', { status: 200, headers: { 'content-type': 'text/html' } });
  };
}

test('Artifacts: exposed SQL dump served as a file is CRITICAL', async () => {
  mockPaths({ '/backup.sql': { contentType: 'application/octet-stream', body: '-- MySQL dump 10.13\nCREATE TABLE `users` (id int);\nINSERT INTO `users` VALUES (1);' } });
  const a = new SecurityAuditor('http://127.0.0.1/app/');
  await a.checkExtendedArtifactsAndApis();
  assert.ok(has(a, /CRITICAL: Exposed SQL Database Dump/), titles(a).join('\n'));
});

test('Artifacts: SQL keywords inside an HTML page are NOT a false SQL-dump positive', async () => {
  mockPaths({ '/backup.sql': { contentType: 'text/html', body: '<html><body>CREATE TABLE tutorial example INSERT INTO</body></html>' } });
  const a = new SecurityAuditor('http://127.0.0.1/app/');
  await a.checkExtendedArtifactsAndApis();
  assert.ok(!has(a, /SQL Database Dump/), titles(a).join('\n'));
});

test('Artifacts: exposed phpMyAdmin console is HIGH', async () => {
  mockPaths({ '/phpmyadmin/': { contentType: 'text/html', body: '<html><head><title>phpMyAdmin</title></head><body>pma_</body></html>' } });
  const a = new SecurityAuditor('http://127.0.0.1/');
  await a.checkExtendedArtifactsAndApis();
  assert.ok(has(a, /HIGH: Exposed phpMyAdmin Console/), titles(a).join('\n'));
});

// --- Exposed services guardrail -------------------------------------------------------
test('Services: port probe is skipped entirely in public mode', async () => {
  const a = new SecurityAuditor('http://10.0.0.5', { publicMode: true });
  await a.checkExposedServices();
  assert.equal(a.findings.filter(f => f.category === 'Exposed Services').length, 0);
});

test('Services: port probe is skipped when explicitly disabled', async () => {
  const a = new SecurityAuditor('http://10.0.0.5', { probeServices: false });
  await a.checkExposedServices();
  assert.equal(a.findings.filter(f => f.category === 'Exposed Services').length, 0);
});
