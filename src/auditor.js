import dns from 'node:dns/promises';
import tls from 'node:tls';
import net from 'node:net';
import crypto from 'node:crypto';
import { URL } from 'node:url';
import { runOtpRateLimitTest } from './otpTester.js';
import { readTextBounded, safeFetch } from './securityGuard.js';
import { crawlSameOriginSite } from './siteCrawler.js';

/**
 * Kalasag Audit — Security Auditor Engine (v2)
 * Engineered with high-precision validation to eliminate false positives:
 * - Content-aware artifact verification (prevents SPA / custom 404 soft-positives)
 * - W3C CSP Level 3 spec compliant parsing (recognizes default-src fallback & strict-dynamic)
 * - Context-aware API vs Webpage isolation
 * - Private / Local IP detection (skips public DNS/DMARC penalties on internal IPs)
 * - Intelligent cookie classification (recognizes client-side analytics cookies)
 * - Granular server version disclosure (ignores generic CDN edge banners)
 * - Clean TLS socket lifecycle management
 */
export class SecurityAuditor {
  constructor(targetInput, options = {}) {
    this.originalInput = targetInput.trim();
    this.targetUrl = this.normalizeUrl(this.originalInput);
    this.parsedUrl = new URL(this.targetUrl);
    this.hostname = this.parsedUrl.hostname;
    this.port = this.parsedUrl.port || (this.parsedUrl.protocol === 'https:' ? 443 : 80);
    this.isInternalHost = this.isPrivateOrLocalHost(this.hostname);

    // options.otpTest: opt-in config for the active OTP rate-limit probe.
    // options.publicMode: true when running on a public/Vercel deployment (enforces
    //   SSRF redirect re-validation, read-only probes, and tighter timeouts).
    // options.log: optional progress logger for active sub-tests.
    this.options = options || {};
    this.publicMode = Boolean(this.options.publicMode);
    this.dnsLookup = this.options.dnsLookup;
    this.otpConfig = this.publicMode ? null : (this.options.otpTest || null);
    // Active TCP service-exposure probe (DB/admin ports). Runs automatically on
    // every local-mode scan (set options.probeServices === false to opt out).
    // Always disabled in public/Vercel mode so the hosted scanner can never be
    // used to port-scan arbitrary third parties.
    this.probeServices = this.publicMode ? false : (this.options.probeServices !== false);
    // Active app-layer injection testing (error-based SQLi + reflected XSS on GET
    // parameters). Runs automatically in local mode; always off in public mode so
    // the hosted scanner can never inject into third parties. Opt out with
    // options.activeInjection === false (CLI --no-injection).
    this.activeInjection = this.publicMode ? false : (this.options.activeInjection !== false);
    this.crawlEnabled = this.options.crawl !== false;
    this.maxPages = this.options.maxPages;
    this.log = typeof this.options.log === 'function' ? this.options.log : () => {};

    this.findings = [];
    this.discoveredPages = [];
    this.discoveredApiRoutes = [];
    this.crawlStats = null;
    this.crawledGetTargets = [];
  }

  normalizeUrl(rawUrl) {
    if (rawUrl.startsWith('http://') || rawUrl.startsWith('https://')) {
      return rawUrl;
    }
    // When no scheme is given, default local/private hosts (localhost, 127.x,
    // 10.x, 192.168.x, 172.16-31.x, *.local) to HTTP — dev servers rarely speak
    // TLS — and public hosts to HTTPS. Users can always type the scheme to override.
    let host;
    try {
      host = new URL(`http://${rawUrl}`).hostname;
    } catch {
      host = rawUrl.split('/')[0].split(':')[0];
    }
    const scheme = this.isPrivateOrLocalHost(host) ? 'http' : 'https';
    return `${scheme}://${rawUrl}`;
  }

  isPrivateOrLocalHost(host) {
    if (!host) return false;
    if (['localhost', '127.0.0.1', '::1'].includes(host)) return true;
    if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.test') || host.endsWith('.lan')) return true;
    
    const parts = host.split('.').map(Number);
    if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
      if (parts[0] === 10) return true;
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
      if (parts[0] === 192 && parts[1] === 168) return true;
      if (parts[0] === 127) return true;
    }
    return false;
  }

  addFinding({ severity, category, title, description, remediation, scoreImpact = 0 }) {
    this.findings.push({
      severity, // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS'
      category,
      title,
      description,
      remediation: remediation || 'No specific fix needed.',
      scoreImpact
    });
  }

  async runAllChecks() {
    // Phase 1: fetch the root document first so HTML-dependent modules
    // (frontend secrets, SRI, mixed content, site crawler) have this.cachedHtml available.
    const rootResult = await Promise.allSettled([this.checkHeadersAndCookies()]);

    // Phase 1.5: bounded same-origin discovery crawl (HTML links, robots.txt,
    // sitemap.xml, JS bundle API routes, and multi-page form/header hygiene).
    // Runs before Phase 2 so local injection checks also test discovered subpage GET params.
    const crawlResult = this.crawlEnabled
      ? await Promise.allSettled([this.checkSiteDiscoveryAndForms()])
      : [];

    // Phase 2: the remaining passive/light-active modules run in parallel.
    const checks = [
      this.checkTransportAndRedirects(),
      this.checkTlsCertificate(),
      this.checkHttpMethods(),
      this.checkCorsPolicy(),
      this.checkExtendedArtifactsAndApis(),
      this.checkFrontendSecretsAndScripts(),
      this.checkOpenRedirect(),
      this.checkSubdomainTakeover(),
      this.checkExposedServices(),
      this.checkInjectionVulns(),
      this.checkDnsAndEmailSecurity()
    ];

    const results = [...rootResult, ...crawlResult, ...(await Promise.allSettled(checks))];

    for (const res of results) {
      if (res.status === 'rejected') {
        this.addFinding({
          severity: 'INFO',
          category: 'Diagnostics',
          title: 'Sub-check Diagnostic Notice',
          description: `Diagnostic: ${res.reason?.message || res.reason}`,
          remediation: 'Ensure host allows standard inbound HTTP/DNS inspection.',
          scoreImpact: 0
        });
      }
    }

    // Phase 3: OPT-IN active OTP rate-limit test. Runs only when the operator
    // supplied an otpTest config (their own endpoint + their own recipient).
    if (this.otpConfig) {
      try {
        await this.checkOtpRateLimiting();
      } catch (err) {
        this.addFinding({
          severity: 'INFO',
          category: 'OTP / Rate Limiting',
          title: 'OTP Rate-Limit Test Errored',
          description: `The OTP test did not complete: ${err.message}`,
          remediation: 'Check the otpTest config (url, headers, recipient).',
          scoreImpact: 0
        });
      }
    }

    const { score, grade, gradeCappedBy } = this.computeScoreAndGrade();
    const coverage = this.buildCoverageSummary();
    const totalProbesExecuted = coverage.reduce((acc, item) => acc + item.probesRun, 0);

    return {
      targetUrl: this.targetUrl,
      hostname: this.hostname,
      isInternalHost: this.isInternalHost,
      scanTime: new Date().toISOString(),
      score,
      grade,
      gradeCappedBy,
      totalProbesExecuted,
      coverage,
      crawlStats: this.crawlStats,
      discoveredPages: this.discoveredPages,
      discoveredApiRoutes: this.discoveredApiRoutes,
      findings: this.findings
    };
  }

  /**
   * Builds a complete 12-domain coverage manifest showing every audit module and
   * how many individual probes were executed, so both the UI and Enterprise PDF
   * clearly prove full scope coverage even when clean modules pass silently.
   */
  buildCoverageSummary() {
    const modules = [
      {
        id: 'transport',
        name: 'Transport Security',
        category: 'Transport Security',
        probesRun: 1,
        checks: 'HTTP → HTTPS redirect enforcement & local-network awareness',
        standard: 'OWASP A02:2021 • RFC 9110'
      },
      {
        id: 'tls',
        name: 'TLS / SSL Cryptography',
        category: 'TLS / SSL Certificate',
        probesRun: this.parsedUrl.protocol === 'https:' || this.port === 443 ? 5 : 0,
        checks: 'Certificate expiry, CA issuer, TLS 1.0/1.1 detection, cipher strength, trust chain & RSA key size',
        standard: 'PCI-DSS 4.0 • RFC 8446',
        skippedReason: this.parsedUrl.protocol !== 'https:' && this.port !== 443 ? 'Target served over plain HTTP' : null
      },
      {
        id: 'headers',
        name: 'Security Headers & Isolation',
        category: 'Security Headers',
        probesRun: 8,
        checks: 'HSTS, W3C CSP L3, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP & duplicate headers',
        standard: 'OWASP A05:2021 • W3C CSP3 • RFC 6797'
      },
      {
        id: 'leakage',
        name: 'Server Fingerprinting',
        category: 'Information Leakage',
        probesRun: 5,
        checks: 'Server, X-Powered-By, X-AspNet-Version, X-Runtime & X-Generator banner inspection',
        standard: 'OWASP A05:2021 • CIS Benchmark'
      },
      {
        id: 'cookies',
        name: 'Session & Cookie Security',
        category: 'Cookie Security',
        probesRun: 4,
        checks: 'Secure, HttpOnly, SameSite attributes & __Host- / __Secure- prefix rules',
        standard: 'OWASP A07:2021 • RFC 6265bis'
      },
      {
        id: 'methods',
        name: 'HTTP Methods & Verbs',
        category: 'HTTP Method Tampering',
        probesRun: this.publicMode ? 2 : 4,
        checks: this.publicMode
          ? 'OPTIONS Allow inspection & read-only TRACE (XST) probe (active PUT/DELETE write canaries disabled in public mode)'
          : 'OPTIONS Allow inspection, active TRACE (XST) probe, canary-verified PUT & DELETE',
        standard: 'OWASP WSTG-CONF-06 • CWE-749'
      },
      {
        id: 'cors',
        name: 'Cross-Origin Policy (CORS)',
        category: 'Access Control (CORS)',
        probesRun: 1,
        checks: 'Arbitrary Origin reflection with credentials & wildcard exposure check',
        standard: 'OWASP A01:2021 • CWE-942'
      },
      {
        id: 'artifacts',
        name: 'Exposed Files & API Schemas',
        category: 'Exposed Artifacts & APIs',
        probesRun: 25,
        checks: '.git, .env (+ .local/.production/.bak variants), SQL dumps, config/source backups, phpMyAdmin & Adminer, phpinfo, actuator, swagger, GraphQL introspection, directory listing & security.txt',
        standard: 'OWASP A05:2021 • CWE-538 • RFC 9116'
      },
      {
        id: 'frontend',
        name: 'Frontend & Supply Chain',
        category: 'Frontend & Secrets',
        probesRun: 5,
        checks: 'Active/passive mixed content, Subresource Integrity (SRI), outdated JS libraries & client bundle secrets',
        standard: 'OWASP A06:2021 • W3C SRI'
      },
      {
        id: 'crawl',
        name: 'Site Discovery & Route Mapping',
        category: 'Site Discovery & Crawl',
        probesRun: Math.max(1, this.discoveredPages.length + (this.discoveredApiRoutes.length > 0 ? 1 : 0)),
        checks: 'Bounded same-origin crawl (HTML links, robots.txt, sitemap.xml), JS bundle API route extraction & subpage header drift',
        standard: 'OWASP WSTG-INFO-03 • Multi-Page Scope'
      },
      {
        id: 'forms',
        name: 'Form & Auth Hygiene',
        category: 'Form & Auth Security',
        probesRun: Math.max(1, this.discoveredPages.reduce((sum, p) => sum + (p.formsCount || 0), 0)),
        checks: 'POST anti-CSRF token presence, plain-HTTP password inputs & cleartext form action downgrade across discovered pages',
        standard: 'OWASP A01 / A02 / A07 • CWE-352'
      },
      {
        id: 'redirect',
        name: 'Open Redirect Protection',
        category: 'Open Redirect',
        probesRun: 13,
        checks: '11 redirect query parameters + protocol-relative // bypass probes with non-resolving canary',
        standard: 'OWASP A01:2021 • CWE-601'
      },
      {
        id: 'services',
        name: 'Exposed Database & Admin Services',
        category: 'Exposed Services',
        probesRun: this.probeServices ? 10 : 0,
        checks: 'TCP reachability of MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, MSSQL, Memcached, CouchDB, RDP & admin ports',
        standard: 'OWASP A05:2021 • CWE-1327',
        skippedReason: this.probeServices ? null : 'Disabled in public deployment mode'
      },
      {
        id: 'injection',
        name: 'Injection (SQLi / XSS)',
        category: 'Injection',
        probesRun: this.activeInjection ? (this._injectionParamsTested || 0) : 0,
        checks: 'Error-based SQL injection & reflected XSS on GET parameters (query string + GET forms)',
        standard: 'OWASP A03:2021 • CWE-89 • CWE-79',
        skippedReason: this.activeInjection ? (this._injectionParamsTested ? null : 'No testable GET parameters found') : 'Disabled in public deployment mode'
      },
      {
        id: 'takeover',
        name: 'Subdomain Takeover (CNAME)',
        category: 'Subdomain Takeover',
        probesRun: this.isInternalHost ? 0 : 1,
        checks: 'Dangling CNAME resolution across 11 cloud/hosting unclaimed fingerprints',
        standard: 'OWASP WSTG-CONF-10',
        skippedReason: this.isInternalHost ? 'Internal / private host' : null
      },
      {
        id: 'dns',
        name: 'DNS & Email Authentication',
        category: 'Email & DNS Security',
        probesRun: this.isInternalHost ? 0 : 5,
        checks: 'Organizational-domain SPF, DMARC (p= & sp=), parent-climbing CAA, MX & DKIM selectors',
        standard: 'RFC 7208 • RFC 7489 • RFC 8659',
        skippedReason: this.isInternalHost ? 'Internal / private host' : null
      }
    ];

    if (this.otpConfig) {
      modules.push({
        id: 'otp',
        name: 'OTP / Verification Rate Limiting',
        category: 'OTP / Rate Limiting',
        probesRun: Math.min(6, Math.max(2, Number(this.otpConfig.maxRequests) || 4)),
        checks: 'Bounded sequential self-test checking 429 / Retry-After / cooldown throttling',
        standard: 'OWASP API4:2023 • OAT-019'
      });
    }

    const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, PASS: 5 };
    return modules.map((mod) => {
      const matched = this.findings.filter((f) => {
        if (mod.id === 'frontend') {
          return f.category === 'Frontend & Secrets' || f.category === 'Outdated Components';
        }
        if (mod.id === 'headers') {
          return f.category === 'Security Headers' || f.category === 'Configuration Hygiene';
        }
        return f.category === mod.category;
      });

      const issues = matched.filter((f) => f.severity !== 'PASS' && f.severity !== 'INFO');
      const infos = matched.filter((f) => f.severity === 'INFO');
      const passes = matched.filter((f) => f.severity === 'PASS');

      let status = 'PASS';
      if (mod.skippedReason) {
        status = 'SKIPPED';
      } else if (issues.length > 0) {
        const worst = issues.reduce((best, cur) => ((sevRank[cur.severity] ?? 9) < (sevRank[best.severity] ?? 9) ? cur : best), issues[0]);
        status = worst.severity;
      } else if (infos.length > 0 && passes.length === 0) {
        status = 'INFO';
      }

      return {
        ...mod,
        status,
        issueCount: issues.length,
        infoCount: infos.length,
        passCount: passes.length
      };
    });
  }

  calculateGrade(score) {
    if (score >= 95) return 'A+';
    if (score >= 85) return 'A';
    if (score >= 70) return 'B';
    if (score >= 50) return 'C';
    if (score >= 35) return 'D';
    return 'F';
  }

  /**
   * Fair scoring model.
   *
   * Rather than a flat "100 - sum(all penalties)" (which over-punishes a pile of
   * minor header gaps and under-punishes a single breach-class finding), this:
   *
   *   1. Applies CRITICAL/HIGH penalties in full (depth matters).
   *   2. Applies MEDIUM/LOW penalties with DIMINISHING RETURNS and a per-bucket
   *      cap, so breadth of trivia can't sink an otherwise-fine site.
   *   3. Caps the GRADE by the single worst severity present, so a site with an
   *      exposed .env can never score a passing grade on the strength of good
   *      headers, and a site with a MEDIUM issue can never claim a perfect A+.
   *
   * The thresholds below are deliberately simple to tune.
   */
  computeScoreAndGrade() {
    const buckets = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    for (const f of this.findings) {
      if (f.scoreImpact > 0 && buckets[f.severity]) buckets[f.severity].push(f.scoreImpact);
    }

    const sum = (arr) => arr.reduce((a, b) => a + b, 0);
    // First issue in a bucket costs full price; each subsequent one costs less.
    const diminish = (arr) => {
      const sorted = [...arr].sort((a, b) => b - a);
      const factors = [1, 0.6, 0.45, 0.35, 0.25];
      return sorted.reduce((acc, v, i) => acc + v * (factors[i] ?? 0.15), 0);
    };
    const cap = (v, max) => Math.min(v, max);

    const critPenalty = sum(buckets.CRITICAL);            // full, uncapped — depth
    const highPenalty = sum(buckets.HIGH);                // full, uncapped
    const medPenalty = cap(diminish(buckets.MEDIUM), 30); // diminishing + capped
    const lowPenalty = cap(diminish(buckets.LOW), 15);    // diminishing + capped

    let score = Math.max(0, 100 - critPenalty - highPenalty - medPenalty - lowPenalty);

    // Grade cap by worst severity present.
    let ceiling = 100;
    let gradeCappedBy = null;
    if (buckets.CRITICAL.length) { ceiling = 40; gradeCappedBy = 'CRITICAL'; }      // -> max D
    else if (buckets.HIGH.length) { ceiling = 84; gradeCappedBy = 'HIGH'; }         // -> max B
    else if (buckets.MEDIUM.length) { ceiling = 94; gradeCappedBy = 'MEDIUM'; }     // -> max A

    if (score > ceiling) score = ceiling;
    score = Math.round(score);

    return { score, grade: this.calculateGrade(score), gradeCappedBy };
  }

  /**
   * Parses a CSP header into Map<directive, sources[]> (lower-cased). Per the CSP spec
   * only the first occurrence of a directive counts; later duplicates are ignored.
   * Multiple policies (comma-separated) are merged by first occurrence, which is the
   * permissive reading and so never invents a weakness that is not there.
   */
  parseCspDirectives(csp) {
    const directives = new Map();
    for (const policy of String(csp).toLowerCase().split(',')) {
      for (const part of policy.split(';')) {
        const [name, ...sources] = part.trim().split(/\s+/).filter(Boolean);
        if (name && !directives.has(name)) directives.set(name, sources);
      }
    }
    return directives;
  }

  /**
   * Organizational ("registrable") domain used for mail/DNS policy lookups, e.g.
   * www.example.com.ph -> example.com.ph, app.example.com -> example.com.
   * A small built-in list covers common two-level public suffixes (com.ph, co.uk, ...);
   * it is not the full Public Suffix List, so unusual suffixes may resolve one level too high.
   */
  organizationalDomain(host) {
    const labels = String(host).toLowerCase().replace(/\.$/, '').split('.');
    if (labels.length <= 2) return labels.join('.');
    const secondLevel = labels[labels.length - 2];
    const topLevel = labels[labels.length - 1];
    const isTwoLevelSuffix = topLevel.length === 2
      && ['com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'mil', 'or', 'ne', 'go', 'gob', 'nic'].includes(secondLevel);
    return labels.slice(isTwoLevelSuffix ? -3 : -2).join('.');
  }

  resolveAppUrl(relativePath) {
    const basePath = this.parsedUrl.pathname.endsWith('/') 
      ? this.parsedUrl.pathname 
      : this.parsedUrl.pathname + '/';
    const cleanRel = relativePath.replace(/^\//, '');
    return new URL(basePath + cleanRel, this.targetUrl).toString();
  }

  // -------------------------------------------------------------
  // MODULE 1: Transport & HTTPS Enforcement
  // -------------------------------------------------------------
  async checkTransportAndRedirects() {
    if (this.isInternalHost) {
      this.addFinding({
        severity: 'PASS',
        category: 'Transport Security',
        title: 'Local / Private Environment Transport',
        description: `Host "${this.hostname}" is a private/local network address. HTTP to HTTPS redirection is not enforced for local environments.`
      });
      return;
    }

    const isExplicitHttp = this.originalInput.startsWith('http://');
    const testHttpUrl = `http://${this.hostname}`;

    try {
      const res = await fetch(testHttpUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(4000),
        headers: { 'User-Agent': 'KalasagAudit/2.0' }
      });

      const isRedirect = [301, 302, 307, 308].includes(res.status);
      const location = res.headers.get('location') || '';

      if (isRedirect && (location.startsWith('https://') || location.startsWith('//'))) {
        this.addFinding({
          severity: 'PASS',
          category: 'Transport Security',
          title: 'Automatic HTTP to HTTPS Redirection Active',
          description: `HTTP requests are automatically upgraded to HTTPS via HTTP ${res.status}.`
        });
      } else if (isExplicitHttp && !isRedirect) {
        this.addFinding({
          severity: 'HIGH',
          category: 'Transport Security',
          title: 'Missing Automatic HTTPS Redirection',
          description: `The website serves content over unencrypted HTTP (status ${res.status}) without redirecting to HTTPS.`,
          remediation: 'Configure web server (Nginx/Cloudflare/Apache) to issue a 301 Permanent Redirect to https://.',
          scoreImpact: 20
        });
      }
    } catch {
      // Host may strictly refuse port 80 connections (HTTPS-only)
    }
  }

  // -------------------------------------------------------------
  // MODULE 2: Deep SSL/TLS Certificate Analysis
  // -------------------------------------------------------------
  async checkTlsCertificate() {
    if (this.parsedUrl.protocol !== 'https:' && this.port !== 443) return;

    return new Promise((resolve) => {
      let handshakeComplete = false;

      const socket = tls.connect(
        {
          host: this.hostname,
          port: this.port || 443,
          servername: this.hostname,
          // Deliberate inspection invariant: we accept untrusted certs during handshake
          // solely to read cert metadata and evaluate socket.authorizationError below.
          // No HTTP request or sensitive payload is transmitted over this socket.
          rejectUnauthorized: false,
          timeout: 6000
        },
        () => {
          handshakeComplete = true;
          const cert = socket.getPeerCertificate(true);

          if (!cert || !cert.valid_to) {
            socket.destroy();
            this.addFinding({
              severity: 'HIGH',
              category: 'TLS / SSL Certificate',
              title: 'Unable to Retrieve TLS Certificate Details',
              description: 'The server completed TLS handshake but returned an empty certificate chain.',
              scoreImpact: 10
            });
            return resolve();
          }

          const expiryDate = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
          const issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown CA';

          if (daysRemaining < 0) {
            this.addFinding({
              severity: 'CRITICAL',
              category: 'TLS / SSL Certificate',
              title: 'Expired SSL/TLS Certificate',
              description: `Certificate expired ${Math.abs(daysRemaining)} days ago on ${expiryDate.toISOString()}. Browsers will show security warnings.`,
              remediation: 'Renew the SSL/TLS certificate immediately via your CA or Let\'s Encrypt.',
              scoreImpact: 40
            });
          } else if (daysRemaining < 21) {
            this.addFinding({
              severity: 'HIGH',
              category: 'TLS / SSL Certificate',
              title: `SSL Certificate Expiring Soon (${daysRemaining} Days Remaining)`,
              description: `Certificate issued by ${issuer} expires on ${expiryDate.toLocaleDateString()}.`,
              remediation: 'Trigger certificate auto-renewal before expiration to prevent downtime.',
              scoreImpact: 12
            });
          } else {
            this.addFinding({
              severity: 'PASS',
              category: 'TLS / SSL Certificate',
              title: 'Valid SSL/TLS Certificate Active',
              description: `Certificate issued by "${issuer}" is valid for ${daysRemaining} more days (expires ${expiryDate.toLocaleDateString()}).`
            });
          }

          // --- Negotiated protocol version ---
          const protocol = (typeof socket.getProtocol === 'function' && socket.getProtocol()) || '';
          if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
            this.addFinding({
              severity: 'HIGH',
              category: 'TLS / SSL Certificate',
              title: `Deprecated TLS Protocol Negotiated (${protocol})`,
              description: `The server negotiated ${protocol}, which is deprecated and disallowed by PCI-DSS and all modern browsers. It is vulnerable to downgrade and padding-oracle attacks (BEAST/POODLE).`,
              remediation: 'Disable TLS 1.0 and 1.1 at the web server / load balancer; allow only TLS 1.2 and 1.3.',
              scoreImpact: protocol === 'TLSv1' ? 18 : 14
            });
          } else if (protocol === 'TLSv1.2' || protocol === 'TLSv1.3') {
            this.addFinding({
              severity: 'PASS',
              category: 'TLS / SSL Certificate',
              title: `Modern TLS Protocol (${protocol})`,
              description: `The connection negotiated ${protocol}.`
            });
          }

          // --- Cipher suite strength ---
          const cipher = (typeof socket.getCipher === 'function' && socket.getCipher()) || {};
          const cipherName = cipher.name || '';
          if (cipherName && /RC4|3DES|_DES_|NULL|EXPORT|_MD5/i.test(cipherName)) {
            this.addFinding({
              severity: 'HIGH',
              category: 'TLS / SSL Certificate',
              title: `Weak Cipher Suite Negotiated (${cipherName})`,
              description: `The server negotiated a cryptographically weak cipher (${cipherName}). Ciphers using RC4, 3DES, DES, NULL, EXPORT or MD5 are broken or deprecated.`,
              remediation: 'Restrict the cipher list to modern AEAD suites (AES-GCM, ChaCha20-Poly1305) on TLS 1.2+/1.3.',
              scoreImpact: 12
            });
          }

          // --- Certificate trust / hostname validation ---
          const authError = socket.authorizationError ? String(socket.authorizationError) : '';
          if (authError) {
            const isHostMismatch = /altnames|hostname|ALTNAME|common name|does not match/i.test(authError);
            const isSelfSigned = /self.signed|SELF_SIGNED/i.test(authError);
            if (this.isInternalHost) {
              this.addFinding({
                severity: 'INFO',
                category: 'TLS / SSL Certificate',
                title: 'Untrusted Certificate on Internal Host (expected)',
                description: `Certificate chain is not publicly trusted (${authError}). On a private/internal host this is common (self-signed or internal CA) and not penalized.`,
                remediation: 'For internal zero-trust, consider an internal CA trusted by your fleet rather than per-host self-signed certs.',
                scoreImpact: 0
              });
            } else if (isHostMismatch) {
              this.addFinding({
                severity: 'HIGH',
                category: 'TLS / SSL Certificate',
                title: 'Certificate Hostname Mismatch',
                description: `The certificate is not valid for "${this.hostname}" (${authError}). Browsers will show a security warning and the identity cannot be trusted.`,
                remediation: 'Issue a certificate whose SAN list includes this exact hostname.',
                scoreImpact: 20
              });
            } else if (isSelfSigned) {
              this.addFinding({
                severity: 'HIGH',
                category: 'TLS / SSL Certificate',
                title: 'Self-Signed Certificate on Public Host',
                description: `The certificate is self-signed (${authError}). Public clients cannot verify the server identity, enabling trivial man-in-the-middle.`,
                remediation: 'Install a certificate from a publicly trusted CA (e.g. Let\'s Encrypt).',
                scoreImpact: 20
              });
            } else {
              this.addFinding({
                severity: 'MEDIUM',
                category: 'TLS / SSL Certificate',
                title: 'Untrusted Certificate Chain',
                description: `The certificate chain failed validation: ${authError}. Often a missing intermediate certificate.`,
                remediation: 'Serve the full chain (leaf + intermediates) in the correct order.',
                scoreImpact: 10
              });
            }
          }

          // --- Weak RSA key size (EC keys are strong at small bit sizes) ---
          const isEcKey = Boolean(cert.asn1Curve || cert.nistCurve);
          if (!isEcKey && cert.bits && cert.bits < 2048) {
            this.addFinding({
              severity: 'HIGH',
              category: 'TLS / SSL Certificate',
              title: `Weak RSA Key Size (${cert.bits}-bit)`,
              description: `The certificate uses a ${cert.bits}-bit RSA key. Keys under 2048 bits are considered breakable.`,
              remediation: 'Reissue the certificate with at least a 2048-bit RSA key or an ECDSA P-256 key.',
              scoreImpact: 15
            });
          }

          socket.removeAllListeners('error');
          socket.destroy();
          resolve();
        }
      );

      socket.on('error', (err) => {
        if (handshakeComplete) return;
        socket.destroy();
        this.addFinding({
          severity: 'HIGH',
          category: 'TLS / SSL Certificate',
          title: 'TLS Handshake Failed',
          description: `Failed to establish secure TLS connection: ${err.message}`,
          remediation: 'Ensure SSL certificates and cipher suites are properly installed.',
          scoreImpact: 15
        });
        resolve();
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve();
      });
    });
  }

  // -------------------------------------------------------------
  // MODULE 3: Security Headers, Modern Isolation & Cookies
  // -------------------------------------------------------------
  async checkHeadersAndCookies() {
    let res;
    let finalUrl = this.targetUrl;
    let body = '';
    // Generous 10s root timeout + 1 retry so slightly slow servers from cloud
    // regions never falsely fail Phase 1 and skip headers/crawler/frontend checks.
    const fetchRootOnce = () => safeFetch(
      this.targetUrl,
      {
        method: 'GET',
        signal: AbortSignal.timeout(10_000),
        headers: { 'User-Agent': 'KalasagAudit/2.0' }
      },
      { publicMode: this.publicMode, dnsLookup: this.dnsLookup }
    );

    try {
      let fetched;
      try {
        fetched = await fetchRootOnce();
      } catch (firstErr) {
        if (firstErr?.code === 'SSRF_BLOCKED' || firstErr?.code === 'DNS_UNRESOLVED') {
          throw firstErr;
        }
        fetched = await fetchRootOnce();
      }
      res = fetched.res;
      finalUrl = fetched.finalUrl || res.url || this.targetUrl;
      body = await readTextBounded(res);
    } catch (err) {
      this.addFinding({
        severity: 'CRITICAL',
        category: 'Connectivity',
        title: 'Unable to connect to target via HTTPS',
        description: `Connection failed: ${err.message}`,
        remediation: 'Verify that the domain resolves and web server is accepting connections.',
        scoreImpact: 50
      });
      return;
    }

    const headers = res.headers;
    const contentType = (headers.get('content-type') || '').toLowerCase();
    const isJsonApi = contentType.includes('application/json') || contentType.includes('application/problem+json');

    // 1. Strict-Transport-Security (HSTS)
    // Browsers ignore HSTS received over plain HTTP (RFC 6797 §8.1), so it is only judged
    // on an HTTPS response. A plain-HTTP public site is penalised by the transport module.
    const hsts = headers.get('strict-transport-security');
    const servedOverHttps = (finalUrl || res.url || this.targetUrl).startsWith('https://');
    if (!servedOverHttps) {
      this.addFinding({
        severity: 'INFO',
        category: 'Security Headers',
        title: 'HSTS Not Applicable Over Plain HTTP',
        description: 'The page was served over HTTP. Browsers only honour Strict-Transport-Security on HTTPS responses, so HSTS was not evaluated.',
        remediation: 'Serve the site over HTTPS, then add: Strict-Transport-Security: max-age=31536000',
        scoreImpact: 0
      });
    } else if (!hsts) {
      this.addFinding({
        severity: 'MEDIUM',
        category: 'Security Headers',
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        description: 'HSTS instructs browsers to strictly communicate over HTTPS, mitigating SSL-stripping attacks.',
        remediation: 'Set header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        scoreImpact: 10
      });
    } else {
      const hasSubdomains = /includesubdomains/i.test(hsts);
      // RFC 6797 allows the value to be quoted: max-age="31536000".
      const maxAgeMatch = hsts.match(/max-age\s*=\s*"?(\d+)"?/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

      if (maxAge < 10368000) {
        this.addFinding({
          severity: 'LOW',
          category: 'Security Headers',
          title: 'HSTS max-age is Too Short',
          description: `Current max-age is ${maxAge}s. Recommended minimum is 1 year (31536000s).`,
          remediation: 'Update HSTS header to: max-age=31536000; includeSubDomains',
          scoreImpact: 3
        });
      } else {
        this.addFinding({
          severity: 'PASS',
          category: 'Security Headers',
          title: 'Strong HSTS Policy Configured',
          description: `HSTS is active with valid max-age (${maxAge}s)${hasSubdomains ? ' and subdomains covered.' : '.'}`
        });
      }
    }

    // 2. Content-Security-Policy (CSP)
    const csp = headers.get('content-security-policy');
    if (!csp) {
      this.addFinding({
        severity: 'HIGH',
        category: 'Security Headers',
        title: 'Missing Content Security Policy (CSP)',
        description: 'CSP protects modern web applications from Cross-Site Scripting (XSS) and malicious data injection.',
        remediation: 'Implement Content-Security-Policy defining trusted script-src, style-src, and default-src.',
        scoreImpact: 15
      });
    } else {
      const cspIssues = [];
      const directives = this.parseCspDirectives(csp);

      // Judge scripts by the directive that actually governs them: script-src, or
      // default-src when script-src is absent. A keyword in style-src (e.g. the common
      // style-src 'unsafe-inline') says nothing about scripts.
      const scriptSources = directives.get('script-src') || directives.get('default-src') || [];
      const hasNonceOrHash = scriptSources.some(s => /^'(?:nonce-|sha(?:256|384|512)-)/.test(s));
      const hasStrictDynamic = scriptSources.includes("'strict-dynamic'") && hasNonceOrHash;
      const hasDefaultSrcNone = (directives.get('default-src') || []).includes("'none'");
      const objectSources = directives.get('object-src');
      const hasObjectSrcNone = objectSources ? objectSources.includes("'none'") : hasDefaultSrcNone;

      // CSP2+ browsers ignore 'unsafe-inline' when a nonce or hash is present, and CSP3
      // browsers also ignore it under 'strict-dynamic'.
      if (scriptSources.includes("'unsafe-inline'") && !hasNonceOrHash && !hasStrictDynamic) {
        cspIssues.push("Allows 'unsafe-inline' scripts without cryptographic nonces or hashes");
      }
      if (scriptSources.includes("'unsafe-eval'")) {
        cspIssues.push("Allows 'unsafe-eval' (execution of strings as code via eval)");
      }
      if (!directives.has('base-uri') && !isJsonApi) {
        cspIssues.push("Missing 'base-uri' directive (potential <base> tag hijacking in HTML pages)");
      }
      if (!hasObjectSrcNone) {
        cspIssues.push("Missing 'object-src \\'none\\'' and no 'default-src \\'none\\'' fallback (allows legacy plugin execution)");
      }

      if (cspIssues.length > 0) {
        // If the only issue is 'unsafe-inline' in an otherwise locked-down CSP, treat as minor
        const isOnlyUnsafeInline = cspIssues.length === 1 && cspIssues[0].includes('unsafe-inline');
        this.addFinding({
          severity: isOnlyUnsafeInline ? 'LOW' : 'MEDIUM',
          category: 'Security Headers',
          title: isOnlyUnsafeInline ? "Content Security Policy Permits 'unsafe-inline'" : 'Weak / Permissive Content Security Policy Directives',
          description: `CSP was found, but contains weaknesses: ${cspIssues.join('; ')}.`,
          remediation: isOnlyUnsafeInline ? "Consider migrating inline scripts to external files with cryptographic nonces or hashes." : 'Harden your CSP policy by removing unsafe-inline/unsafe-eval and ensuring object-src or default-src is \'none\'.',
          scoreImpact: isOnlyUnsafeInline ? 3 : 8
        });
      } else {
        this.addFinding({
          severity: 'PASS',
          category: 'Security Headers',
          title: 'Robust Content Security Policy (CSP)',
          description: `A strict CSP was detected${hasDefaultSrcNone ? ' with default-src \'none\' fallback' : ''}.`
        });
      }
    }

    // 3. X-Frame-Options (Clickjacking)
    const rawXfo = headers.get('x-frame-options') || '';
    const xfoParts = rawXfo.toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
    const hasValidXfo = xfoParts.some(p => ['deny', 'sameorigin'].includes(p));

    const frameAncestors = csp ? this.parseCspDirectives(csp).get('frame-ancestors') : null;
    const hasFrameAncestors = Boolean(frameAncestors && frameAncestors.length && !frameAncestors.includes('*'));
    if (!hasValidXfo && !hasFrameAncestors) {
      if (!isJsonApi) {
        this.addFinding({
          severity: 'MEDIUM',
          category: 'Security Headers',
          title: 'Missing Clickjacking Defense (X-Frame-Options)',
          description: 'Without X-Frame-Options or CSP frame-ancestors, attackers can embed your site inside an invisible iframe to hijack user clicks.',
          remediation: 'Set header: X-Frame-Options: DENY (or SAMEORIGIN), or CSP: frame-ancestors \'none\';',
          scoreImpact: 10
        });
      }
    } else {
      this.addFinding({
        severity: 'PASS',
        category: 'Security Headers',
        title: 'Clickjacking Protection Active',
        description: `Protected via ${rawXfo ? `X-Frame-Options: ${rawXfo}` : 'CSP frame-ancestors'}.`
      });
    }

    // 4. X-Content-Type-Options (MIME Sniffing & Duplicate handling)
    const rawXcto = headers.get('x-content-type-options') || '';
    const xctoParts = rawXcto.toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
    const hasNosniff = xctoParts.includes('nosniff');

    if (!hasNosniff) {
      this.addFinding({
        severity: 'LOW',
        category: 'Security Headers',
        title: 'Missing X-Content-Type-Options: nosniff',
        description: 'Prevents browsers from interpreting file contents as a different MIME type than declared.',
        remediation: 'Set header: X-Content-Type-Options: nosniff',
        scoreImpact: 5
      });
    } else {
      this.addFinding({
        severity: 'PASS',
        category: 'Security Headers',
        title: 'MIME-Sniffing Defense Active',
        description: 'X-Content-Type-Options is set to nosniff.'
      });
    }

    if (xctoParts.length > 1 || xfoParts.length > 1) {
      this.addFinding({
        severity: 'INFO',
        category: 'Configuration Hygiene',
        title: 'Duplicate Security Headers Detected',
        description: `Security headers are being duplicated by both web server and application middleware (${rawXcto ? `nosniff: "${rawXcto}"` : ''} ${rawXfo ? `xfo: "${rawXfo}"` : ''}).`,
        remediation: 'Remove duplicate header definitions from web.config/reverse proxy to keep headers tidy.',
        scoreImpact: 0
      });
    }

    // 5. Modern Browser Isolation Headers (Permissions-Policy)
    const permPolicy = headers.get('permissions-policy');
    if (!permPolicy) {
      if (!isJsonApi) {
        this.addFinding({
          severity: 'INFO',
          category: 'Security Headers',
          title: 'Missing Permissions-Policy Header',
          description: 'Permissions-Policy allows developers to explicitly disable unused browser features (camera, microphone, geolocation, usb).',
          remediation: 'Set header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
          scoreImpact: 0
        });
      }
    } else {
      this.addFinding({
        severity: 'PASS',
        category: 'Security Headers',
        title: 'Permissions-Policy Configured',
        description: 'Permissions-Policy explicitly manages client hardware feature access.'
      });
    }

    // 5b. Referrer-Policy (prevents leaking full URLs — tokens, IDs — to third parties)
    if (!isJsonApi) {
      const referrerPolicy = (headers.get('referrer-policy') || '').toLowerCase().trim();
      const leakyReferrer = ['', 'unsafe-url', 'no-referrer-when-downgrade', 'origin-when-cross-origin'];
      if (!referrerPolicy) {
        this.addFinding({
          severity: 'LOW',
          category: 'Security Headers',
          title: 'Missing Referrer-Policy Header',
          description: 'Without Referrer-Policy, the browser may send the full URL (including path, query strings, session tokens or IDs) to third-party sites in the Referer header.',
          remediation: 'Set header: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).',
          scoreImpact: 3
        });
      } else if (leakyReferrer.includes(referrerPolicy)) {
        this.addFinding({
          severity: 'LOW',
          category: 'Security Headers',
          title: `Weak Referrer-Policy (${referrerPolicy})`,
          description: `The policy "${referrerPolicy}" can still leak full URLs cross-origin, exposing anything embedded in your URLs.`,
          remediation: 'Use Referrer-Policy: strict-origin-when-cross-origin or no-referrer.',
          scoreImpact: 2
        });
      } else {
        this.addFinding({
          severity: 'PASS',
          category: 'Security Headers',
          title: 'Referrer-Policy Configured',
          description: `Referrer-Policy is set to "${referrerPolicy}".`
        });
      }
    }

    // 5c. Cross-Origin-Opener-Policy (isolates the browsing context; mitigates XS-Leaks / Spectre)
    if (!isJsonApi) {
      const coop = (headers.get('cross-origin-opener-policy') || '').toLowerCase().trim();
      if (!coop) {
        this.addFinding({
          severity: 'INFO',
          category: 'Security Headers',
          title: 'Missing Cross-Origin-Opener-Policy (COOP)',
          description: 'COOP isolates your top-level window from cross-origin openers, mitigating cross-window attacks and some side-channel (Spectre-class) leaks.',
          remediation: 'Set header: Cross-Origin-Opener-Policy: same-origin',
          scoreImpact: 0
        });
      } else {
        this.addFinding({
          severity: 'PASS',
          category: 'Security Headers',
          title: 'Cross-Origin-Opener-Policy Configured',
          description: `COOP is set to "${coop}".`
        });
      }
    }

    // 6. Information Disclosure in Headers (Distinguish CDN vs Granular Version)
    const leakyHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime', 'x-generator'];
    const genericCdns = ['cloudflare', 'vercel', 'netlify', 'github.com', 'fastly', 'akamai', 'gws'];
    const leaks = [];

    for (const h of leakyHeaders) {
      const val = headers.get(h);
      if (!val) continue;

      const lowerVal = val.toLowerCase().trim();
      // If it's just 'Server: Apache' (ServerTokens Prod) or 'Server: nginx' (server_tokens off) or generic CDN, that is compliant
      if (h === 'server') {
        const hasVersionNumber = /\d+(\.\d+)+/.test(val);
        if (!hasVersionNumber) {
          continue; // Safe! Version numbers are properly suppressed
        }
      }

      leaks.push(`${h}: ${val}`);
    }

    if (leaks.length > 0) {
      this.addFinding({
        severity: 'LOW',
        category: 'Information Leakage',
        title: 'Software Version & Framework Disclosure',
        description: `Headers reveal granular server or software details: ${leaks.join(', ')}.`,
        remediation: 'Suppress version headers in reverse proxy (e.g. "server_tokens off;" in Nginx or "app.disable(\'x-powered-by\')" in Express).',
        scoreImpact: 4
      });
    } else {
      this.addFinding({
        severity: 'PASS',
        category: 'Information Leakage',
        title: 'Server Version Banners Minimized',
        description: 'No granular web server or framework version numbers were exposed in HTTP response headers.'
      });
    }

    // 7. Cookie Security Flags (Distinguish Analytics vs Session Cookies)
    const cookiesList = typeof res.headers.getSetCookie === 'function'
      ? res.headers.getSetCookie()
      : (headers.get('set-cookie') ? [headers.get('set-cookie')] : []);

    if (cookiesList.length > 0) {
      let activeCookiesChecked = 0;
      let cookieIssueCount = 0;

      for (const cookieStr of cookiesList) {
        const parts = cookieStr.split(';').map(p => p.trim());
        const nameVal = parts[0] || 'UnknownCookie';
        const cookieName = nameVal.split('=')[0];

        if (!cookieName || cookieName.includes(' ') || cookieName.toLowerCase().startsWith('expires=')) continue;

        // A Set-Cookie that deletes a cookie (logout, consent reset) stores nothing,
        // so its missing flags are not a weakness.
        const maxAgePart = parts.find(p => /^max-age=/i.test(p));
        const expiresPart = parts.find(p => /^expires=/i.test(p));
        const isDeletion = (maxAgePart && parseInt(maxAgePart.split('=')[1], 10) <= 0)
          || (expiresPart && Date.parse(expiresPart.slice(8)) < Date.now());
        if (isDeletion) continue;

        activeCookiesChecked += 1;
        const isClientAnalyticsCookie = /^_ga|^_gid|^_gat|^_cl|^mp_|^amplitude/i.test(cookieName);

        const hasSecure = parts.some(p => p.toLowerCase() === 'secure');
        const hasHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
        const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));

        // Cookie name prefixes carry browser-enforced security guarantees.
        // If a cookie claims a prefix but violates its rules, browsers reject it.
        const lowerName = cookieName.toLowerCase();
        const hasPathRoot = parts.some(p => /^path=\/$/i.test(p));
        const hasDomainAttr = parts.some(p => /^domain=/i.test(p));
        if (lowerName.startsWith('__host-')) {
          const hostViolations = [];
          if (!hasSecure) hostViolations.push('missing Secure');
          if (hasDomainAttr) hostViolations.push('has a Domain attribute (forbidden)');
          if (!hasPathRoot) hostViolations.push('Path is not "/"');
          if (hostViolations.length > 0) {
            cookieIssueCount += 1;
            this.addFinding({
              severity: 'MEDIUM',
              category: 'Cookie Security',
              title: `__Host- Prefixed Cookie "${cookieName}" Violates Prefix Rules`,
              description: `The cookie uses the "__Host-" prefix but ${hostViolations.join(', ')}. Browsers will REJECT this cookie, likely breaking sessions or silently dropping the protection.`,
              remediation: 'A __Host- cookie must be: Secure, no Domain attribute, and Path=/.',
              scoreImpact: 6
            });
          }
        } else if (lowerName.startsWith('__secure-') && !hasSecure) {
          cookieIssueCount += 1;
          this.addFinding({
            severity: 'MEDIUM',
            category: 'Cookie Security',
            title: `__Secure- Prefixed Cookie "${cookieName}" Missing Secure Flag`,
            description: 'The cookie uses the "__Secure-" prefix but lacks the Secure flag. Browsers will reject it.',
            remediation: 'Add the Secure flag to any __Secure- prefixed cookie.',
            scoreImpact: 6
          });
        }

        const cookieFlaws = [];
        if (!hasSecure) cookieFlaws.push("Missing 'Secure' flag");
        if (!hasHttpOnly && !isClientAnalyticsCookie) cookieFlaws.push("Missing 'HttpOnly' flag");
        if (!sameSitePart) cookieFlaws.push("Missing 'SameSite' attribute (modern browsers default to Lax)");

        if (cookieFlaws.length > 0) {
          cookieIssueCount += 1;
          const impact = !hasSecure ? 8 : (cookieFlaws.includes("Missing 'HttpOnly' flag") ? 6 : 2);
          this.addFinding({
            severity: !hasSecure ? 'MEDIUM' : 'LOW',
            category: 'Cookie Security',
            title: `Insecure Cookie Attributes on "${cookieName}"`,
            description: `Cookie lacks defensive attributes: ${cookieFlaws.join(', ')}.`,
            remediation: 'Always set: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Lax (or Strict)',
            scoreImpact: impact
          });
        }
      }

      if (activeCookiesChecked > 0 && cookieIssueCount === 0) {
        this.addFinding({
          severity: 'PASS',
          category: 'Cookie Security',
          title: 'Session Cookies Properly Hardened',
          description: `All ${activeCookiesChecked} active cookie(s) enforce Secure, HttpOnly, SameSite, and valid prefix attributes.`
        });
      }
    }

    this.cachedHtml = body;
  }

  // -------------------------------------------------------------
  // MODULE 4: HTTP Methods & Verb Tampering (OPTIONS, TRACE, PUT, DELETE)
  // -------------------------------------------------------------
  async checkHttpMethods() {
    try {
      let traceActive = false;
      let traceStatus = null;

      try {
        const traceRes = await fetch(this.targetUrl, {
          method: 'TRACE',
          signal: AbortSignal.timeout(3000),
          headers: {
            'User-Agent': 'KalasagAudit/2.0',
            'X-Kalasag-Probe': 'test-trace'
          }
        });
        traceStatus = traceRes.status;

        if (traceRes.status === 200) {
          const traceBody = await readTextBounded(traceRes, 65536);
          if (traceBody.includes('test-trace')) {
            traceActive = true;
            this.addFinding({
              severity: 'CRITICAL',
              category: 'HTTP Method Tampering',
              title: 'Active Cross-Site Tracing (XST) Vulnerability',
              description: 'The server actively executes TRACE requests and reflects back headers. Attackers can bypass HttpOnly cookie protections using XST.',
              remediation: 'Disable TRACE on web server (Nginx rejects it by default; set TraceEnable Off in Apache or Request Filtering in IIS).',
              scoreImpact: 35
            });
          }
        }
      } catch {
        // TRACE method connection refused or blocked
      }

      const optionsRes = await fetch(this.targetUrl, {
        method: 'OPTIONS',
        signal: AbortSignal.timeout(4000),
        headers: { 'User-Agent': 'KalasagAudit/2.0' }
      });

      const allowHeader = optionsRes.headers.get('allow') || optionsRes.headers.get('access-control-allow-methods');
      if (allowHeader) {
        const methods = allowHeader.split(',').map(m => m.trim().toUpperCase());
        const advertisedDangerous = methods.filter(m => ['TRACE', 'TRACK'].includes(m));

        if (advertisedDangerous.length > 0 && !traceActive) {
          this.addFinding({
            severity: 'INFO',
            category: 'HTTP Method Tampering',
            title: `TRACE Advertised in OPTIONS (Inert / Blocked)`,
            description: `The server lists ${advertisedDangerous.join(', ')} in the OPTIONS Allow header, but active TRACE execution is blocked or rejected (HTTP ${traceStatus || 'refused'}). This is a cosmetic web.config artifact and not exploitable.`,
            remediation: 'Filter TRACE in IIS Request Filtering to prevent advertising it in OPTIONS responses.',
            scoreImpact: 0
          });
        }
      }

      // In public/cloud mode, keep HTTP method inspection strictly read-only
      // (skip active PUT/DELETE write canaries against external hosts).
      let verbVulnerable = false;
      if (!this.publicMode) {
        // A 2xx status alone proves nothing: front controllers, SPAs and catch-all routers
        // answer every path and method with 200. So PUT is reported only when the body was
        // really stored (read back with GET), and DELETE only when it really removed that
        // same test file. Nothing else on the server is touched.
        const token = `${Date.now().toString(36)}${crypto.randomBytes(6).toString('hex')}`;
        const probeUrl = this.resolveAppUrl(`/.kalasag-method-test-${token}.txt`);
        const canary = `kalasag-put-canary-${token}`;
        const probeHeaders = { 'User-Agent': 'KalasagAudit/2.0' };
        const readsCanary = async () => {
          try {
            const res = await fetch(probeUrl, { method: 'GET', signal: AbortSignal.timeout(3000), headers: probeHeaders });
            return res.status === 200 && (await readTextBounded(res, 65536)).includes(canary);
          } catch {
            return false;
          }
        };

        try {
          const putRes = await fetch(probeUrl, {
            method: 'PUT',
            body: canary,
            signal: AbortSignal.timeout(3000),
            headers: { ...probeHeaders, 'Content-Type': 'text/plain' }
          });
          if ([200, 201, 204].includes(putRes.status)) {
            if (await readsCanary()) {
              verbVulnerable = true;
              this.addFinding({
                severity: 'CRITICAL',
                category: 'HTTP Method Tampering',
                title: 'Unauthenticated PUT Writes Files to the Web Root',
                description: `An unauthenticated PUT stored a file that was then served back at ${probeUrl}. Attackers can upload arbitrary content (including web shells).`,
                remediation: 'Disable PUT (WebDAV) on the web server, or restrict it to authenticated API routes with strict authorization.',
                scoreImpact: 35
              });

              // DELETE is verified against the file we just created, and also cleans it up.
              const deleteRes = await fetch(probeUrl, { method: 'DELETE', signal: AbortSignal.timeout(3000), headers: probeHeaders });
              if ([200, 202, 204].includes(deleteRes.status) && !(await readsCanary())) {
                this.addFinding({
                  severity: 'CRITICAL',
                  category: 'HTTP Method Tampering',
                  title: 'Unauthenticated DELETE Removes Files from the Web Root',
                  description: 'An unauthenticated DELETE removed the test file Kalasag Audit had just uploaded. Attackers can delete site content.',
                  remediation: 'Disable DELETE (WebDAV) on the web server, or restrict it to authenticated API routes with strict authorization.',
                  scoreImpact: 35
                });
              } else {
                this.addFinding({
                  severity: 'INFO',
                  category: 'HTTP Method Tampering',
                  title: 'Kalasag Audit Test File Left on Server',
                  description: `The PUT test file could not be removed. Delete it manually: ${probeUrl}`,
                  remediation: 'Remove the file, then disable PUT on the web server.',
                  scoreImpact: 0
                });
              }
            } else {
              this.addFinding({
                severity: 'INFO',
                category: 'HTTP Method Tampering',
                title: `PUT Answered ${putRes.status} but Stored Nothing`,
                description: 'The server replied with a success status to an unauthenticated PUT, but the content was not stored (typical of a catch-all router or framework error page). Not exploitable as tested.',
                remediation: 'Optionally return 405 Method Not Allowed for unsupported methods to keep responses unambiguous.',
                scoreImpact: 0
              });
            }
          }
        } catch {
          // Connection safely closed or refused
        }
      }

      if (!traceActive && !verbVulnerable) {
        this.addFinding({
          severity: 'PASS',
          category: 'HTTP Method Tampering',
          title: 'HTTP Methods Hardened',
          description: this.publicMode
            ? 'No active TRACE execution or dangerous method exposure was accepted (read-only public scan).'
            : 'No unauthenticated PUT, DELETE, or active TRACE execution was accepted on root endpoints.'
        });
      }
    } catch {
      // Host may not support OPTIONS
    }
  }

  // -------------------------------------------------------------
  // MODULE 5: CORS Policy Prober
  // -------------------------------------------------------------
  async checkCorsPolicy() {
    const maliciousTestOrigin = 'https://evil-security-test.com';

    try {
      const res = await fetch(this.targetUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(4000),
        headers: {
          'Origin': maliciousTestOrigin,
          'User-Agent': 'KalasagAudit/2.0'
        }
      });

      const acao = res.headers.get('access-control-allow-origin');
      const acac = res.headers.get('access-control-allow-credentials');

      if (acao === maliciousTestOrigin && acac?.toLowerCase() === 'true') {
        this.addFinding({
          severity: 'CRITICAL',
          category: 'Access Control (CORS)',
          title: 'Dangerous CORS Misconfiguration (Reflected Origin with Credentials)',
          description: 'The server naively echoes back arbitrary Origin headers and enables credentials. An external site can steal private user data or perform authenticated actions on user behalf.',
          remediation: 'Never blindly reflect request Origin with Access-Control-Allow-Credentials: true. Implement a strict whitelist of trusted origins.',
          scoreImpact: 35
        });
      } else if (acao === '*') {
        this.addFinding({
          severity: 'INFO',
          category: 'Access Control (CORS)',
          title: 'Wildcard CORS Header Detected (*)',
          description: 'The server returns "Access-Control-Allow-Origin: *". Normal for public content, but dangerous if applied to private/authenticated user endpoints.',
          remediation: 'Ensure authenticated API endpoints do not use wildcard CORS headers.',
          scoreImpact: 0
        });
      } else {
        this.addFinding({
          severity: 'PASS',
          category: 'Access Control (CORS)',
          title: 'CORS Origin Isolation Configured',
          description: 'Server does not reflect arbitrary untrusted origins with credentials.'
        });
      }
    } catch {
      // CORS probe failed
    }
  }

  // -------------------------------------------------------------
  // MODULE 6: Extended Sensitive File, Framework & API Exposure
  // Strict content-type & regex validation to eliminate SPA / custom-404 false positives
  // -------------------------------------------------------------
  async checkExtendedArtifactsAndApis() {
    // Shared validators (content-aware, to avoid SPA / soft-404 false positives).
    const isServed = (status, type, text) =>
      status === 200 && !type.includes('text/html') && !text.includes('<!doctype') && !text.includes('<html');
    const isEnvBody = (text) =>
      /(?:^|\n)\s*(?:(?:DB|API|AWS|APP_KEY|SECRET|SMTP|MAIL|REDIS|STRIPE|JWT)[A-Z0-9_]*|[A-Z0-9_]*(?:PASSWORD|SECRET))\s*=\s*[^\s<>"']+/m.test(text);
    const isSqlDump = (text) =>
      /(--\s*(?:MySQL|MariaDB|phpMyAdmin|PostgreSQL)\s+dump|CREATE\s+TABLE\s+[`"']?\w|INSERT\s+INTO\s+[`"']?\w|DROP\s+TABLE\s+IF\s+EXISTS)/i.test(text);
    const isPhpSource = (text) =>
      text.includes('<?php') && /(DB_PASSWORD|DB_USER|DB_HOST|define\s*\(\s*['"]DB_|mysqli?_connect|new\s+PDO)/i.test(text);

    const probes = [
      {
        path: '/.git/HEAD',
        validate: (status, type, text) => {
          if (status !== 200 || type.includes('text/html') || text.includes('<!doctype') || text.includes('<html')) return false;
          return /^ref:\s*refs\/heads\/[a-zA-Z0-9_\-\.\/]+/m.test(text) || /^[0-9a-f]{40}\s*$/.test(text);
        },
        severity: 'CRITICAL',
        title: 'Exposed Git Repository (/.git/HEAD)',
        description: 'The .git repository is publicly accessible. Attackers can clone the complete source code repository and history.',
        remediation: 'Configure your web server to deny access to all hidden folders starting with "." (e.g. location ~ /\\. { deny all; }).',
        scoreImpact: 40
      },
      {
        path: '/.git/config',
        validate: (status, type, text) => {
          if (status !== 200 || type.includes('text/html') || text.includes('<!doctype') || text.includes('<html')) return false;
          return /\[core\][\s\S]*repositoryformatversion/i.test(text);
        },
        severity: 'CRITICAL',
        title: 'Exposed Git Configuration (/.git/config)',
        description: 'Git config is publicly readable, exposing internal repository URLs, remotes, and user details.',
        remediation: 'Block access to .git directories immediately.',
        scoreImpact: 35
      },
      {
        path: '/.env',
        validate: (status, type, text) => {
          if (status !== 200 || type.includes('text/html') || text.includes('<!doctype') || text.includes('<html')) return false;
          // Must match actual environment variables (e.g. DB_HOST=..., APP_KEY=..., SECRET=...)
          // KEY=value lines whose key starts with a typical secret prefix or is/ends in
          // PASSWORD/SECRET (e.g. DB_PASSWORD=..., PASSWORD=..., APP_KEY=...).
          return /(?:^|\n)\s*(?:(?:DB|API|AWS|APP_KEY|SECRET|SMTP|MAIL|REDIS|STRIPE|JWT)[A-Z0-9_]*|[A-Z0-9_]*(?:PASSWORD|SECRET))\s*=\s*[^\s<>"']+/m.test(text);
        },
        severity: 'CRITICAL',
        title: 'Exposed Environment File (/.env)',
        description: 'Environment file is publicly downloadable. Frequently contains database credentials, API secrets, and encryption keys.',
        remediation: 'Store .env files outside public web root, and block web access.',
        scoreImpact: 45
      },
      {
        path: '/phpinfo.php',
        validate: (status, type, text) => {
          if (status !== 200) return false;
          return text.includes('<title>phpinfo()</title>') || (text.includes('PHP Version') && text.includes('Zend Engine'));
        },
        severity: 'HIGH',
        title: 'Exposed phpinfo() Diagnostic Page',
        description: 'A diagnostic script revealing detailed PHP compilation flags, server paths, loaded extensions, and environment variables is public.',
        remediation: 'Delete phpinfo.php from production servers immediately.',
        scoreImpact: 20
      },
      {
        path: '/actuator/health',
        validate: (status, type, text) => {
          if (status !== 200 || !type.includes('json')) return false;
          try {
            const data = JSON.parse(text);
            return data && typeof data.status === 'string' && ['UP', 'DOWN', 'OUT_OF_SERVICE', 'UNKNOWN'].includes(data.status);
          } catch {
            return false;
          }
        },
        severity: 'MEDIUM',
        title: 'Exposed Spring Boot Actuator Endpoint (/actuator/health)',
        description: 'Spring Boot administrative actuator endpoints are exposed to the internet.',
        remediation: 'Restrict management.endpoints.web.exposure.include to authenticated internal networks only.',
        scoreImpact: 10
      },
      {
        path: '/swagger.json',
        validate: (status, type, text) => {
          if (status !== 200 || type.includes('text/html')) return false;
          try {
            const data = JSON.parse(text);
            return Boolean(data.swagger || data.openapi);
          } catch {
            return false;
          }
        },
        severity: 'LOW',
        title: 'Publicly Exposed Swagger / OpenAPI Specification',
        description: 'API documentation schema is accessible publicly. It details internal endpoints, parameters, and models.',
        remediation: 'Restrict access to API documentation in production environments.',
        scoreImpact: 5
      },
      {
        path: '/.well-known/security.txt',
        validate: (status, type, text) => {
          if (status !== 200 || type.includes('text/html') || text.includes('<!doctype') || text.includes('<html')) return false;
          return /Contact:\s*(?:mailto:|https:)/i.test(text);
        },
        severity: 'PASS',
        title: 'Coordinated Vulnerability Disclosure (RFC 9116 security.txt)',
        description: 'A valid security.txt file exists to assist ethical researchers in reporting vulnerabilities responsibly.',
        remediation: 'Good practice maintained.'
      },
      // --- Exposed database dumps ---
      ...['/backup.sql', '/dump.sql', '/database.sql', '/db.sql'].map((p) => ({
        path: p,
        validate: (status, type, text) => isServed(status, type, text) && isSqlDump(text),
        severity: 'CRITICAL',
        title: `Exposed SQL Database Dump (${p})`,
        description: 'A raw SQL database dump is publicly downloadable. It can contain the entire database — users, password hashes, and personal data.',
        remediation: 'Remove database dumps from the web root immediately and store backups outside any public directory.',
        scoreImpact: 45
      })),
      // --- .env variants ---
      ...['/.env.local', '/.env.production', '/.env.dev', '/.env.bak', '/.env.save'].map((p) => ({
        path: p,
        validate: (status, type, text) => isServed(status, type, text) && isEnvBody(text),
        severity: 'CRITICAL',
        title: `Exposed Environment File (${p})`,
        description: 'An environment file variant is publicly downloadable, frequently containing database credentials, API secrets, and encryption keys.',
        remediation: 'Store environment files outside the public web root and block web access to dot-files.',
        scoreImpact: 45
      })),
      // --- Source / config backups served as text (reveal credentials) ---
      ...['/config.php.bak', '/wp-config.php.bak', '/wp-config.php~', '/config.php~', '/configuration.php.bak'].map((p) => ({
        path: p,
        validate: (status, type, text) => status === 200 && isPhpSource(text),
        severity: 'CRITICAL',
        title: `Exposed Source/Config Backup (${p})`,
        description: 'A backup of a server-side config file is served as plain text, exposing its PHP source — including hard-coded database credentials and secrets.',
        remediation: 'Delete editor/backup files (*.bak, *~, *.swp) from the web root and block them at the web server.',
        scoreImpact: 42
      })),
      // --- Database admin panels ---
      {
        path: '/adminer.php',
        validate: (status, type, text) => status === 200 && /Adminer|adminer\.org|Login\s*-\s*Adminer/i.test(text),
        severity: 'HIGH',
        title: 'Exposed Adminer Database Console (/adminer.php)',
        description: 'Adminer, a full web-based database administration tool, is publicly reachable. If credentials are weak or default, it grants direct database access.',
        remediation: 'Remove adminer.php from production or restrict it to an authenticated internal network / VPN.',
        scoreImpact: 22
      },
      {
        path: '/phpmyadmin/',
        validate: (status, type, text) => status === 200 && /phpMyAdmin|pma_|pmaversion/i.test(text),
        severity: 'HIGH',
        title: 'Exposed phpMyAdmin Console (/phpmyadmin/)',
        description: 'phpMyAdmin is publicly reachable. It is a top brute-force and exploitation target for direct database compromise.',
        remediation: 'Restrict phpMyAdmin to an internal network / VPN, enforce strong auth, and keep it patched.',
        scoreImpact: 22
      },
      // --- Apache mod_status ---
      {
        path: '/server-status',
        validate: (status, type, text) => status === 200 && /Apache Server Status|<title>Apache Status/i.test(text),
        severity: 'MEDIUM',
        title: 'Exposed Apache Server Status (/server-status)',
        description: 'Apache mod_status is public, revealing live request URLs, client IPs, and server internals useful for reconnaissance.',
        remediation: 'Restrict /server-status to localhost (Require local) or disable mod_status in production.',
        scoreImpact: 10
      }
    ];

    let exposedArtifactCount = 0;

    const probeTimeout = 4500;
    await Promise.all(probes.map(async (probe) => {
      try {
        const probeUrl = this.resolveAppUrl(probe.path);
        const res = await fetch(probeUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(probeTimeout),
          headers: { 'User-Agent': 'KalasagAudit/2.0' }
        });

        const contentType = (res.headers.get('content-type') || '').toLowerCase();
        const text = await readTextBounded(res, 131072);

        if (probe.validate(res.status, contentType, text)) {
          if (probe.severity !== 'PASS') exposedArtifactCount += 1;
          this.addFinding({
            severity: probe.severity,
            category: 'Exposed Artifacts & APIs',
            title: probe.title,
            description: probe.description,
            remediation: probe.remediation,
            scoreImpact: probe.scoreImpact || 0
          });
        }
      } catch {
        // Probe ignored on timeout
      }
    }));

    // GraphQL Introspection Probe (Strict JSON Response Validation)
    try {
      const gqlUrl = this.resolveAppUrl('/graphql');
      const gqlRes = await fetch(gqlUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'KalasagAudit/2.0'
        },
        body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
        signal: AbortSignal.timeout(3000)
      });

      const gqlType = (gqlRes.headers.get('content-type') || '').toLowerCase();
      if (gqlRes.status === 200 && gqlType.includes('json')) {
        const data = await gqlRes.json();
        if (Array.isArray(data?.data?.__schema?.types) && data.data.__schema.types.length > 0) {
          exposedArtifactCount += 1;
          this.addFinding({
            severity: 'MEDIUM',
            category: 'Exposed Artifacts & APIs',
            title: 'GraphQL Schema Introspection Enabled in Production',
            description: 'GraphQL introspection is active. Anyone can query the server to extract the entire database schema, queries, and mutations.',
            remediation: 'Disable introspection in production (e.g. "introspection: false" in Apollo Server).',
            scoreImpact: 12
          });
        }
      }
    } catch {
      // No GraphQL endpoint active
    }

    // --- Directory listing / autoindex detection ---
    const dirCandidates = ['/uploads/', '/files/', '/images/', '/backups/', '/assets/', '/documents/'];
    const listedDirs = [];
    await Promise.all(dirCandidates.map(async (dir) => {
      try {
        const res = await fetch(this.resolveAppUrl(dir), {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(this.publicMode ? 2500 : 3000),
          headers: { 'User-Agent': 'KalasagAudit/2.0' }
        });
        if (res.status !== 200) return;
        const text = await readTextBounded(res, 32768);
        if (/<title>\s*Index of \//i.test(text) || (/Index of \//i.test(text) && /Parent Directory|Last modified|\[DIR\]/i.test(text))) {
          listedDirs.push(dir);
        }
      } catch {
        // not listable / not present
      }
    }));

    if (listedDirs.length > 0) {
      exposedArtifactCount += 1;
      this.addFinding({
        severity: 'MEDIUM',
        category: 'Exposed Artifacts & APIs',
        title: 'Directory Listing Enabled',
        description: `Automatic directory indexing is enabled on: ${listedDirs.join(', ')}. This lets anyone browse and download files that were not meant to be discoverable.`,
        remediation: 'Disable autoindex (Nginx "autoindex off;", Apache "Options -Indexes") and add an index file to each directory.',
        scoreImpact: 10
      });
    }

    if (exposedArtifactCount === 0) {
      this.addFinding({
        severity: 'PASS',
        category: 'Exposed Artifacts & APIs',
        title: 'Sensitive Files & Admin Endpoints Protected',
        description: `Probed ${probes.length + dirCandidates.length + 1} high-risk paths (.git, .env & variants, SQL dumps, config backups, phpMyAdmin/Adminer, actuator, swagger, GraphQL, directory listing) — none are publicly exposed.`
      });
    }
  }

  // -------------------------------------------------------------
  // MODULE 7: Frontend JavaScript Asset & Secret Harvester
  // -------------------------------------------------------------
  async checkFrontendSecretsAndScripts() {
    if (!this.cachedHtml) return;

    // Commented-out markup (<!-- <script src="http://..."> -->) is never loaded by the
    // browser, so every tag-based check below works on the live HTML only.
    this.liveHtml = this.cachedHtml.replace(/<!--[\s\S]*?-->/g, '');

    // --- 7a. Mixed content (HTTPS page pulling http:// subresources) ---
    this.checkMixedContent();
    // --- 7b. Subresource Integrity on third-party scripts/styles ---
    this.checkSubresourceIntegrity();

    const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    const scriptUrls = [];
    let match;

    while ((match = scriptRegex.exec(this.liveHtml)) !== null) {
      let src = match[1];
      if (src.startsWith('//')) {
        src = `${this.parsedUrl.protocol}${src}`;
      } else if (src.startsWith('/')) {
        src = new URL(src, this.targetUrl).toString();
      } else if (!src.startsWith('http')) {
        src = new URL(src, this.targetUrl).toString();
      }
      scriptUrls.push(src);
    }

    // --- 7c. Outdated JS libraries detectable from script filenames ---
    this.checkOutdatedLibraries(scriptUrls, this.liveHtml);

    if (scriptUrls.length === 0) return;

    const targets = scriptUrls
      .filter(url => url.includes(this.hostname) || url.startsWith('/'))
      .slice(0, 4);

    const secretPatterns = [
      {
        name: 'Google Maps / API Key',
        // Require string quotation or assignment context to avoid matching random base64 webpack chunks
        regex: /['"`](AIza[0-9A-Za-z-_]{35})['"`]/g,
        severity: 'LOW',
        description: 'Exposed Google API key found in public script bundle. If quota restrictions are missing, this can incur financial billing abuse.',
        remediation: 'Restrict this key in Google Cloud Console by HTTP referrer and specific enabled APIs.',
        scoreImpact: 5
      },
      {
        name: 'Firebase Configuration URL',
        regex: /https:\/\/[a-zA-Z0-9-]+\.firebaseio\.com/g,
        severity: 'LOW',
        description: 'Firebase database URL exposed in client bundle. Ensure Firebase Realtime Database Security Rules are strictly enforced.',
        remediation: 'Audit Firebase Security Rules to ensure unauthenticated read/write is denied.',
        scoreImpact: 4
      }
    ];

    const detectedSecrets = new Set();

    await Promise.all(targets.map(async (url) => {
      try {
        const { res } = await safeFetch(
          url,
          {
            signal: AbortSignal.timeout(5000),
            headers: { 'User-Agent': 'KalasagAudit/2.0' }
          },
          { publicMode: this.publicMode, dnsLookup: this.dnsLookup }
        );
        if (res.status === 200) {
          const code = await readTextBounded(res);
          // Detect library version banners embedded in the fetched bundle.
          this.scanCodeForLibraries(code);
          for (const pattern of secretPatterns) {
            // The patterns carry the /g flag, so .test() resumes from the previous
            // lastIndex; reset it or later files are scanned from the wrong offset.
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(code) && !detectedSecrets.has(pattern.name)) {
              detectedSecrets.add(pattern.name);
              this.addFinding({
                severity: pattern.severity,
                category: 'Frontend & Secrets',
                title: `Client-Side Disclosure: ${pattern.name}`,
                description: `${pattern.description} (Found in ${url.split('/').pop().split('?')[0]}).`,
                remediation: pattern.remediation,
                scoreImpact: pattern.scoreImpact
              });
            }
          }
        }
      } catch {
        // Safe to ignore script fetch errors
      }
    }));

    if (detectedSecrets.size === 0) {
      this.addFinding({
        severity: 'PASS',
        category: 'Frontend & Secrets',
        title: 'No Common API Keys or Sensitive Tokens Leaked in JavaScript',
        description: `Audited ${targets.length} frontend script bundles without finding exposed keys.`
      });
    }
  }

  // -------------------------------------------------------------
  // Frontend helpers: mixed content, SRI, outdated libraries
  // -------------------------------------------------------------
  checkMixedContent() {
    if (this.parsedUrl.protocol !== 'https:') return;
    const html = this.liveHtml ?? this.cachedHtml ?? '';
    const activeRe = /<(?:script|link|iframe|object|embed)\b[^>]*?\b(?:src|href|data)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
    const passiveRe = /<(?:img|audio|video|source)\b[^>]*?\b(?:src|srcset)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
    // <link> tags only load something for these rel values; rel="canonical",
    // "alternate", "preconnect", "dns-prefetch" etc. are plain references, not mixed content.
    const isLoadingTag = (tag) => !/^<link\b/i.test(tag)
      || /\brel\s*=\s*["']?[^"'>]*\b(?:stylesheet|icon|preload|modulepreload|manifest)\b/i.test(tag);

    const active = [...html.matchAll(activeRe)].filter(m => isLoadingTag(m[0])).map(m => m[1]);
    const passive = [...html.matchAll(passiveRe)].map(m => m[1]);

    if (active.length > 0) {
      this.addFinding({
        severity: 'MEDIUM',
        category: 'Frontend & Secrets',
        title: 'Active Mixed Content on HTTPS Page',
        description: `The HTTPS page loads ${active.length} active resource(s) (script/style/iframe) over plaintext HTTP, e.g. ${active.slice(0, 3).join(', ')}. These are blocked by modern browsers and, if loaded, allow full page compromise via MITM.`,
        remediation: 'Serve all scripts, stylesheets and iframes over HTTPS (or protocol-relative // URLs on an HTTPS origin).',
        scoreImpact: 10
      });
    } else if (passive.length > 0) {
      this.addFinding({
        severity: 'LOW',
        category: 'Frontend & Secrets',
        title: 'Passive Mixed Content on HTTPS Page',
        description: `The HTTPS page references ${passive.length} image/media resource(s) over HTTP, e.g. ${passive.slice(0, 3).join(', ')}.`,
        remediation: 'Load all images and media over HTTPS to avoid browser warnings and MITM tampering.',
        scoreImpact: 3
      });
    }
  }

  checkSubresourceIntegrity() {
    const html = this.liveHtml ?? this.cachedHtml ?? '';
    const tagRe = /<(script|link)\b[^>]*>/gi;
    const missing = new Set();
    // These services change their files continuously or per browser, so an integrity
    // hash cannot be pinned (Google documents that Fonts CSS and gtag do not support SRI).
    // Flagging them only produces findings nobody can fix.
    const sriImpossibleHosts = [
      'fonts.googleapis.com', 'www.googletagmanager.com', 'www.google-analytics.com',
      'ssl.google-analytics.com', 'www.google.com', 'www.gstatic.com', 'maps.googleapis.com',
      'js.stripe.com', 'connect.facebook.net', 'challenges.cloudflare.com', 'static.cloudflareinsights.com'
    ];
    let m;
    while ((m = tagRe.exec(html)) !== null) {
      const tag = m[0];
      const isScript = m[1].toLowerCase() === 'script';
      const srcMatch = tag.match(/\b(?:src|href)\s*=\s*["']([^"']+)["']/i);
      if (!srcMatch) continue;

      let src = srcMatch[1];
      if (!/^https?:\/\//i.test(src) && !src.startsWith('//')) continue; // relative = same origin
      if (src.startsWith('//')) src = this.parsedUrl.protocol + src;

      let host;
      try { host = new URL(src).hostname; } catch { continue; }
      if (host === this.hostname) continue; // same-origin does not require SRI
      if (sriImpossibleHosts.includes(host)) continue;
      if (!isScript && !/\brel\s*=\s*["']?stylesheet/i.test(tag)) continue; // only stylesheet links

      if (!/\bintegrity\s*=/i.test(tag)) missing.add(src);
    }

    if (missing.size > 0) {
      const list = [...missing].slice(0, 6);
      const hasScript = [...missing].some(u => /\.js(\?|$)/i.test(u));
      this.addFinding({
        severity: hasScript ? 'MEDIUM' : 'LOW',
        category: 'Frontend & Secrets',
        title: 'Third-Party Resources Without Subresource Integrity (SRI)',
        description: `${missing.size} cross-origin script/style resource(s) are loaded without an integrity hash, e.g. ${list.join(', ')}. If the CDN or third party is compromised, malicious code runs with your origin's privileges (supply-chain attack).`,
        remediation: 'Pin third-party CDN assets to an exact version and add integrity="sha384-..." crossorigin="anonymous" attributes.',
        scoreImpact: hasScript ? 7 : 3
      });
    }
  }

  compareSemver(a, b) {
    const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
    const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
    for (let i = 0; i < 3; i++) {
      if ((pa[i] || 0) > (pb[i] || 0)) return 1;
      if ((pa[i] || 0) < (pb[i] || 0)) return -1;
    }
    return 0;
  }

  reportLibraryVersion(key, version) {
    if (!this._detectedLibraries) this._detectedLibraries = new Set();
    const rules = {
      jquery: { name: 'jQuery', safeAtLeast: '3.5.0', issue: 'XSS via jQuery.htmlPrefilter (CVE-2020-11022 / CVE-2020-11023)', sev: 'MEDIUM', impact: 10 },
      bootstrap: { name: 'Bootstrap', safeAtLeast: '4.3.1', issue: 'XSS in data-* attributes (CVE-2019-8331 and related)', sev: 'MEDIUM', impact: 8 },
      angularjs: { name: 'AngularJS (1.x)', eol: true, issue: 'AngularJS 1.x is End-of-Life (no security patches since January 2022)', sev: 'MEDIUM', impact: 10 }
    };
    const rule = rules[key];
    if (!rule || !version) return;

    const id = `${key}@${version}`;
    if (this._detectedLibraries.has(id)) return;
    this._detectedLibraries.add(id);

    if (rule.eol) {
      this.addFinding({
        severity: rule.sev,
        category: 'Outdated Components',
        title: `End-of-Life Library: ${rule.name} ${version}`,
        description: `${rule.name} ${version} is detected. ${rule.issue}. EOL libraries accumulate unpatched vulnerabilities.`,
        remediation: 'Migrate off AngularJS to a supported framework (Angular 2+, React, Vue) or an actively maintained fork.',
        scoreImpact: rule.impact
      });
      return;
    }

    if (this.compareSemver(version, rule.safeAtLeast) < 0) {
      this.addFinding({
        severity: rule.sev,
        category: 'Outdated Components',
        title: `Outdated Library: ${rule.name} ${version}`,
        description: `${rule.name} ${version} is older than the first patched release ${rule.safeAtLeast}. Known issue: ${rule.issue}.`,
        remediation: `Upgrade ${rule.name} to ${rule.safeAtLeast} or later.`,
        scoreImpact: rule.impact
      });
    }
  }

  checkOutdatedLibraries(scriptUrls, html) {
    for (const url of scriptUrls || []) {
      const file = url.toLowerCase();
      let mm;
      if ((mm = file.match(/jquery[-.](\d+\.\d+\.\d+)/))) this.reportLibraryVersion('jquery', mm[1]);
      if ((mm = file.match(/bootstrap[-.](\d+\.\d+\.\d+)/))) this.reportLibraryVersion('bootstrap', mm[1]);
      if ((mm = file.match(/angular[-.](1\.\d+\.\d+)/))) this.reportLibraryVersion('angularjs', mm[1]);
    }
    // Inline banners in the HTML itself (e.g. inlined vendor bundles).
    if (html) this.scanCodeForLibraries(html);
  }

  scanCodeForLibraries(code) {
    if (!code) return;
    const sample = code.length > 300000 ? code.slice(0, 300000) : code;
    let mm;
    // Trust only a library's own licence banner, the "/*! ... */" comment that releases
    // start with (e.g. "/*! jQuery v3.7.1 | ..." or "/*!\n * Bootstrap v4.6.2 ...").
    // Text elsewhere that merely mentions a version is not that library: Bootstrap 4
    // says "requires at least jQuery v1.9.1" and jQuery Migrate notes "removed in
    // jQuery 1.12.0", which used to be reported as outdated jQuery.
    for (const banner of sample.match(/\/\*![\s\S]{0,400}?\*\//g) || []) {
      if ((mm = banner.match(/^\/\*!\s*\**\s*jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)/i))) this.reportLibraryVersion('jquery', mm[1]);
      if ((mm = banner.match(/^\/\*!\s*\**\s*Bootstrap v(\d+\.\d+\.\d+)/i))) this.reportLibraryVersion('bootstrap', mm[1]);
    }
    if ((mm = sample.match(/full\s*:\s*["'](1\.\d+\.\d+)["']/i)) && /angular/i.test(sample)) this.reportLibraryVersion('angularjs', mm[1]);
  }

  // -------------------------------------------------------------
  // MODULE: Open Redirect Prober (safe, non-following, benign canary)
  // -------------------------------------------------------------
  async checkOpenRedirect() {
    // ".example" is a reserved TLD that never resolves — even if a redirect
    // were followed it would go nowhere. We never follow it; we only inspect
    // the Location header the server returns.
    const canaryHost = 'kalasag-canary.example';
    const params = ['next', 'url', 'redirect', 'redirect_uri', 'return', 'returnUrl', 'dest', 'destination', 'continue', 'goto', 'u'];

    const probeOne = async (param, payload) => {
      try {
        const u = new URL(this.targetUrl);
        u.searchParams.set(param, payload);
        const res = await fetch(u.toString(), {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(4000),
          headers: { 'User-Agent': 'KalasagAudit/2.0' }
        });
        if (![301, 302, 303, 307, 308].includes(res.status)) return null;
        const loc = res.headers.get('location');
        if (!loc) return null;
        let destHost;
        try { destHost = new URL(loc, this.targetUrl).hostname; } catch { return null; }
        return destHost === canaryHost ? { param, payload, loc } : null;
      } catch {
        return null;
      }
    };

    const jobs = [];
    for (const p of params) {
      jobs.push(probeOne(p, `https://${canaryHost}/`));
    }
    // Protocol-relative bypass, tested only on the two most common params.
    jobs.push(probeOne('next', `//${canaryHost}/`));
    jobs.push(probeOne('url', `//${canaryHost}/`));

    const results = (await Promise.all(jobs)).filter(Boolean);

    if (results.length > 0) {
      const hit = results[0];
      this.addFinding({
        severity: 'MEDIUM',
        category: 'Open Redirect',
        title: 'Open Redirect Vulnerability',
        description: `The parameter "${hit.param}" is reflected into a redirect to an attacker-controlled external host (Location: ${hit.loc}). Attackers use this for convincing phishing links and OAuth token theft. Affected parameter(s): ${[...new Set(results.map(r => r.param))].join(', ')}.`,
        remediation: 'Do not redirect to user-supplied URLs. Allowlist internal paths, or validate the destination host against a strict allowlist. Reject absolute and protocol-relative (//) targets.',
        scoreImpact: 12
      });
    } else {
      this.addFinding({
        severity: 'PASS',
        category: 'Open Redirect',
        title: 'Redirect Parameters Properly Guarded',
        description: 'Tested 13 common redirect parameters and protocol-relative (//) bypasses — none redirected to an external host.'
      });
    }
  }

  // -------------------------------------------------------------
  // MODULE: Dangling CNAME / Subdomain Takeover
  // -------------------------------------------------------------
  async checkSubdomainTakeover() {
    if (this.isInternalHost) return;

    let cnames = [];
    try {
      cnames = await dns.resolveCname(this.hostname);
    } catch {
      this.addFinding({
        severity: 'PASS',
        category: 'Subdomain Takeover',
        title: 'No Dangling CNAME Takeover Risk',
        description: `${this.hostname} does not delegate via a dangling third-party CNAME record.`
      });
      return;
    }
    if (!cnames.length) return;

    const cname = cnames[0].toLowerCase().replace(/\.$/, '');
    const fingerprints = [
      // Fingerprints must be the provider's specific "unclaimed" wording. Generic text
      // such as "404" also appears on live sites and would raise a false takeover alarm.
      { re: /\.github\.io$/, svc: 'GitHub Pages', bodies: ["There isn't a GitHub Pages site here"] },
      { re: /\.herokuapp\.com$/, svc: 'Heroku', bodies: ['No such app', 'no-such-app'] },
      { re: /\.s3[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$/, svc: 'AWS S3', bodies: ['NoSuchBucket', 'The specified bucket does not exist'] },
      { re: /\.azurewebsites\.net$/, svc: 'Azure App Service', bodies: ['404 Web Site not found', 'Web App - Unavailable'] },
      { re: /\.trafficmanager\.net$/, svc: 'Azure Traffic Manager', bodies: [] },
      { re: /\.pages\.dev$/, svc: 'Cloudflare Pages', bodies: ['Nothing is here yet'] },
      { re: /\.netlify\.(app|com)$/, svc: 'Netlify', bodies: ['Not Found - Request ID'] },
      { re: /\.fastly\.net$/, svc: 'Fastly', bodies: ['Fastly error: unknown domain'] },
      { re: /\.readthedocs\.io$/, svc: 'Read the Docs', bodies: ['Maze Found'] },
      { re: /\.surge\.sh$/, svc: 'Surge.sh', bodies: ['project not found'] },
      { re: /\.wpengine\.com$/, svc: 'WP Engine', bodies: [] }
    ];

    const fp = fingerprints.find(f => f.re.test(cname));
    if (!fp) {
      this.addFinding({
        severity: 'INFO',
        category: 'Subdomain Takeover',
        title: 'External CNAME Delegation Detected',
        description: `${this.hostname} is a CNAME to "${cname}", which is not a known takeover-prone provider. No takeover risk inferred, but confirm the target is one you still control.`,
        remediation: 'Remove DNS records that point to third-party services you no longer use.',
        scoreImpact: 0
      });
      return;
    }

    // Confirm by fetching and matching the provider's "unclaimed" fingerprint.
    let bodyMatch = false;
    let fetchFailed = false;
    try {
      const { res } = await safeFetch(
        this.targetUrl,
        {
          method: 'GET',
          signal: AbortSignal.timeout(this.publicMode ? 3500 : 5000),
          headers: { 'User-Agent': 'KalasagAudit/2.0' }
        },
        { publicMode: this.publicMode, dnsLookup: this.dnsLookup }
      );
      const text = (await readTextBounded(res, 16384)).slice(0, 5000);
      bodyMatch = fp.bodies.length > 0 && fp.bodies.some(s => text.toLowerCase().includes(s.toLowerCase()));
    } catch {
      fetchFailed = true;
    }

    if (bodyMatch) {
      this.addFinding({
        severity: 'HIGH',
        category: 'Subdomain Takeover',
        title: `Possible Subdomain Takeover via ${fp.svc}`,
        description: `${this.hostname} delegates (CNAME) to ${fp.svc} at "${cname}", and the response matches ${fp.svc}'s "unclaimed resource" page. An attacker may be able to register this resource and serve content from your domain.`,
        remediation: `Immediately remove the dangling CNAME, or re-claim the ${fp.svc} resource. Do not leave DNS pointing at de-provisioned services.`,
        scoreImpact: 25
      });
    } else {
      this.addFinding({
        severity: 'INFO',
        category: 'Subdomain Takeover',
        title: `CNAME to Takeover-Prone Provider (${fp.svc}) — appears claimed`,
        description: `${this.hostname} points to ${fp.svc} ("${cname}")${fetchFailed ? ' and could not be fetched to confirm' : ' and the live response does not match an unclaimed-resource fingerprint'}. Monitor this record if the backing resource is ever decommissioned.`,
        remediation: 'When retiring the backing service, delete this DNS record first to prevent takeover.',
        scoreImpact: 0
      });
    }
  }

  // -------------------------------------------------------------
  // MODULE: OTP / Verification Endpoint Rate-Limit Test (opt-in)
  // -------------------------------------------------------------
  // -------------------------------------------------------------
  // MODULE: Exposed Database & Admin Service Probe (active TCP)
  // Local mode only. Auto-runs for loopback; opt-in (--services) otherwise.
  // -------------------------------------------------------------
  async checkExposedServices() {
    // Off only in public/Vercel mode or when explicitly disabled (--no-services).
    if (!this.probeServices) return;

    const isLoopback =
      ['localhost', '127.0.0.1', '::1'].includes(this.hostname) || this.hostname.startsWith('127.');

    const services = [
      { port: 3306, name: 'MySQL / MariaDB', kind: 'database' },
      { port: 5432, name: 'PostgreSQL', kind: 'database' },
      { port: 27017, name: 'MongoDB', kind: 'database' },
      { port: 6379, name: 'Redis', kind: 'database' },
      { port: 9200, name: 'Elasticsearch', kind: 'database' },
      { port: 1433, name: 'Microsoft SQL Server', kind: 'database' },
      { port: 11211, name: 'Memcached', kind: 'cache' },
      { port: 5984, name: 'CouchDB', kind: 'database' },
      { port: 3389, name: 'RDP (Remote Desktop)', kind: 'admin' },
      { port: 9000, name: 'Admin service (Portainer/SonarQube/PHP-FPM)', kind: 'admin' }
    ];

    const probe = (svc) => new Promise((resolve) => {
      let settled = false;
      let banner = '';
      const socket = net.connect({ host: this.hostname, port: svc.port });
      const finish = (open) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(open ? { ...svc, banner: banner.slice(0, 100).trim() } : null);
      };
      socket.setTimeout(2500);
      socket.once('connect', () => {
        // Some services greet first (MySQL, Redis). Capture a short banner if so,
        // but an open port with no banner still counts as reachable.
        socket.once('data', (buf) => {
          banner = buf.toString('latin1').replace(/[^\x20-\x7e]/g, '.');
          finish(true);
        });
        setTimeout(() => finish(true), 700);
      });
      socket.once('timeout', () => finish(false));
      socket.once('error', () => finish(false));
    });

    this.log(`[*] Probing ${services.length} database/admin ports on ${this.hostname}...`);
    const open = (await Promise.all(services.map(probe))).filter(Boolean);

    if (open.length === 0) {
      this.addFinding({
        severity: 'PASS',
        category: 'Exposed Services',
        title: 'No Reachable Database or Admin Services',
        description: `Probed ${services.length} common database/admin ports (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, MSSQL, Memcached, CouchDB, RDP) on ${this.hostname} — none accepted a connection.`
      });
      return;
    }

    for (const svc of open) {
      const dbLike = svc.kind === 'database' || svc.kind === 'cache';
      const where = `${this.hostname}:${svc.port}`;
      const bannerNote = svc.banner ? ` Banner: "${svc.banner}".` : '';

      if (isLoopback) {
        // Reachable on loopback only proves it runs locally — normal for dev and
        // NOT itself a vulnerability, so it is informational (0 score impact). The
        // real risk is the service binding 0.0.0.0, which this scan cannot see.
        this.addFinding({
          severity: 'INFO',
          category: 'Exposed Services',
          title: `${svc.name} Listening Locally (${where})`,
          description:
            `A ${svc.name} service is reachable on ${where}.${bannerNote} On localhost this is expected for development — ` +
            `but it becomes a CRITICAL exposure if this service is bound to 0.0.0.0 (all interfaces) on a server. ` +
            `This scan cannot see the bind address, so verify it on the host.`,
          remediation:
            `Bind ${svc.name} to 127.0.0.1 only (e.g. MySQL "bind-address=127.0.0.1", Redis "bind 127.0.0.1", Mongo "bindIp: 127.0.0.1"), ` +
            `require authentication, and never open these ports in a firewall/security group.`,
          scoreImpact: 0
        });
      } else {
        // Reachable over the network from the scanner = genuinely exposed.
        this.addFinding({
          severity: dbLike ? 'HIGH' : 'MEDIUM',
          category: 'Exposed Services',
          title: `${svc.name} Directly Reachable Over the Network (${where})`,
          description:
            `A ${svc.name} service on ${where} accepted a TCP connection from this scanner across the network.${bannerNote} ` +
            `Databases and admin services must never be directly reachable — this exposes them to unauthenticated access, ` +
            `credential brute-force, and known CVEs.`,
          remediation:
            `Firewall ${svc.name} off the public/LAN interface, bind it to localhost or a private subnet reachable only by the ` +
            `application tier, and enforce strong authentication. For cloud hosts, tighten the security group / NSG rules.`,
          scoreImpact: dbLike ? 22 : 12
        });
      }
    }
  }

  // -------------------------------------------------------------
  // MODULE: Bounded Same-Origin Site Crawler & Form Hygiene
  // -------------------------------------------------------------
  async checkSiteDiscoveryAndForms() {
    if (!this.cachedHtml) return;

    const crawl = await crawlSameOriginSite({
      rootUrl: this.targetUrl,
      rootHtml: this.cachedHtml,
      publicMode: this.publicMode,
      maxPages: this.maxPages,
      dnsLookup: this.dnsLookup,
      log: this.log
    });

    this.discoveredPages = crawl.pages;
    this.discoveredApiRoutes = crawl.apiRoutes;
    this.crawlStats = crawl.crawlStats;
    this.crawledGetTargets = crawl.extraInjectionTargets;

    // 1. Sensitive paths listed in robots.txt
    if (crawl.robotsSensitivePaths.length > 0) {
      this.addFinding({
        severity: 'INFO',
        category: 'Site Discovery & Crawl',
        title: `Sensitive Paths Listed in robots.txt (${crawl.robotsSensitivePaths.length})`,
        description: `robots.txt discloses sensitive-looking paths: ${crawl.robotsSensitivePaths.slice(0, 6).join(', ')}. Attackers routinely inspect robots.txt to map administrative or internal routes.`,
        remediation: 'Never rely on robots.txt for security. Enforce authentication on administrative/internal paths and avoid advertising secret URLs in robots.txt.',
        scoreImpact: 0
      });
    }

    // 2. Subpage security header drift (pages missing headers that should be site-wide)
    if (crawl.subpageHeaderGaps.length > 0) {
      const sample = crawl.subpageHeaderGaps
        .slice(0, 4)
        .map(g => `${g.path} (missing ${g.missing.join(', ')})`)
        .join('; ');
      this.addFinding({
        severity: 'LOW',
        category: 'Site Discovery & Crawl',
        title: `Subpage Security Header Drift (${crawl.subpageHeaderGaps.length} Page${crawl.subpageHeaderGaps.length > 1 ? 's' : ''})`,
        description: `Crawled subpages are missing baseline browser protection headers: ${sample}.`,
        remediation: 'Apply CSP, X-Frame-Options, and X-Content-Type-Options globally at your reverse proxy or top-level middleware so every route inherits them.',
        scoreImpact: 3
      });
    }

    // 3. Subpage insecure cookies discovered beyond the homepage (e.g. /login)
    if (crawl.subpageCookieIssues.length > 0) {
      const sample = crawl.subpageCookieIssues
        .slice(0, 4)
        .map(c => `${c.path} (${c.cookies.join(', ')})`)
        .join('; ');
      this.addFinding({
        severity: 'MEDIUM',
        category: 'Cookie Security',
        title: 'Insecure Cookies Set on Discovered Subpage(s)',
        description: `Crawled subpages set cookies lacking Secure or HttpOnly flags: ${sample}.`,
        remediation: 'Configure global session cookie defaults with Secure, HttpOnly, and SameSite=Lax across all routes.',
        scoreImpact: 6
      });
    }

    // 3b. Active mixed content discovered on crawled HTTPS subpages
    if (Array.isArray(crawl.subpageMixedContent) && crawl.subpageMixedContent.length > 0) {
      this.addFinding({
        severity: 'MEDIUM',
        category: 'Frontend & Secrets',
        title: `Active Mixed Content on Crawled Subpage(s) (${crawl.subpageMixedContent.length})`,
        description: `Crawled HTTPS subpages load active scripts/stylesheets/iframes over plaintext HTTP: ${crawl.subpageMixedContent.slice(0, 5).join(', ')}.`,
        remediation: 'Update all subpage script, stylesheet, and iframe URLs to use HTTPS.',
        scoreImpact: 8
      });
    }

    // 4. Discovery summary (PASS when crawl completes cleanly)
    if (crawl.subpageHeaderGaps.length === 0) {
      const routeNote = crawl.apiRoutes.length > 0
        ? ` and mapped ${crawl.apiRoutes.length} API/app route(s) from JavaScript bundles`
        : '';
      this.addFinding({
        severity: 'PASS',
        category: 'Site Discovery & Crawl',
        title: `Multi-Page Discovery Complete (${crawl.pages.length} Page${crawl.pages.length > 1 ? 's' : ''})`,
        description: `Inspected ${crawl.pages.length} same-origin page(s) via links, robots.txt & sitemap.xml${routeNote} with consistent security headers.`
      });
    }

    // 5. Form & Auth Hygiene checks across all discovered pages
    let formIssues = 0;

    if (crawl.formFindings.downgradedFormActions.length > 0) {
      formIssues += 1;
      this.addFinding({
        severity: 'HIGH',
        category: 'Form & Auth Security',
        title: 'HTTPS Form Submits Over Unencrypted HTTP',
        description: `An HTTPS page contains a form whose action submits over plaintext HTTP: ${crawl.formFindings.downgradedFormActions.slice(0, 3).join(', ')}. Form data can be intercepted in transit.`,
        remediation: 'Update all form action URLs to use HTTPS or relative same-origin paths.',
        scoreImpact: 15
      });
    }

    if (crawl.formFindings.httpPasswordPages.length > 0) {
      if (this.isInternalHost) {
        this.addFinding({
          severity: 'INFO',
          category: 'Form & Auth Security',
          title: 'Password Form Served Over Local HTTP (Dev Environment)',
          description: `Password input detected on local/private HTTP page(s): ${crawl.formFindings.httpPasswordPages.slice(0, 4).join(', ')}. Fine for localhost development, but must use HTTPS before deploying.`,
          remediation: 'Ensure production/staging login pages are served strictly over HTTPS.',
          scoreImpact: 0
        });
      } else {
        formIssues += 1;
        this.addFinding({
          severity: 'HIGH',
          category: 'Form & Auth Security',
          title: 'Password Input Served Over Unencrypted HTTP',
          description: `Login/password form found on plaintext HTTP page(s): ${crawl.formFindings.httpPasswordPages.slice(0, 4).join(', ')}. Credentials can be sniffed in cleartext on any shared network.`,
          remediation: 'Enforce HTTPS with HSTS across all authentication pages immediately.',
          scoreImpact: 20
        });
      }
    }

    if (crawl.formFindings.postFormsWithoutCsrf.length > 0) {
      formIssues += 1;
      const sample = crawl.formFindings.postFormsWithoutCsrf
        .slice(0, 4)
        .map(f => f.page)
        .join(', ');
      this.addFinding({
        severity: 'MEDIUM',
        category: 'Form & Auth Security',
        title: `POST Form Missing Anti-CSRF Token Field (${crawl.formFindings.postFormsWithoutCsrf.length})`,
        description: `HTML POST form(s) on [${sample}] do not include a recognizable hidden CSRF token input (e.g. csrf_token, _token, __RequestVerificationToken). Unless protected by custom headers or strict SameSite cookies, attackers may forge state-changing requests.`,
        remediation: 'Include a cryptographically random per-session anti-CSRF hidden token in every state-changing POST form and verify it server-side (plus set SameSite=Lax/Strict on session cookies).',
        scoreImpact: 8
      });
    }

    const totalForms = crawl.pages.reduce((sum, p) => sum + (p.formsCount || 0), 0);
    if (formIssues === 0) {
      this.addFinding({
        severity: 'PASS',
        category: 'Form & Auth Security',
        title: 'Forms & Auth Transport Hygiene Verified',
        description: totalForms > 0
          ? `Reviewed ${totalForms} form(s) across ${crawl.pages.length} discovered page(s) — no cleartext password downgrade or unprotected POST forms detected.`
          : `Reviewed ${crawl.pages.length} discovered page(s) — no exposed unencrypted login or unprotected POST forms detected.`
      });
    }
  }

  // -------------------------------------------------------------
  // MODULE: Active App-Layer Injection (error-based SQLi + reflected XSS)
  // Local mode only. GET parameters only, non-destructive payloads.
  // -------------------------------------------------------------
  async checkInjectionVulns() {
    if (!this.activeInjection) return; // off in public mode / when disabled

    // Collect GET parameters to fuzz: the URL's own query string, inputs of GET
    // forms on the root page, plus GET params/forms discovered on crawled subpages.
    const paramSets = []; // { action(url), params: Map(name->value) }

    if ([...this.parsedUrl.searchParams.keys()].length > 0) {
      paramSets.push({ action: this.targetUrl, params: new Map(this.parsedUrl.searchParams) });
    }

    const html = this.cachedHtml || '';
    const formRe = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
    let fm;
    let formCount = 0;
    while ((fm = formRe.exec(html)) !== null && formCount < 2) {
      const tag = fm[0].slice(0, fm[0].indexOf('>') + 1);
      const method = (tag.match(/\bmethod\s*=\s*["']?(\w+)/i) || [])[1] || 'get';
      if (method.toLowerCase() !== 'get') continue; // only safe, idempotent GET forms
      const actionMatch = tag.match(/\baction\s*=\s*["']([^"']*)["']/i);
      let action = this.targetUrl;
      try { action = new URL(actionMatch ? actionMatch[1] : '', this.targetUrl).toString(); } catch {}
      const names = [...fm[1].matchAll(/<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]);
      if (names.length === 0) continue;
      const params = new Map(names.map((n) => [n, 'test']));
      paramSets.push({ action, params });
      formCount += 1;
    }

    // Flatten & deduplicate up to 25 (action, param) targets (including crawled subpages).
    const targets = [];
    const seenKeys = new Set();
    const pushTarget = (action, name, value) => {
      if (targets.length >= 25) return;
      const key = `${action.split('?')[0]}|${name}`;
      if (seenKeys.has(key)) return;
      seenKeys.add(key);
      targets.push({ action, name, value });
    };

    for (const set of paramSets) {
      for (const [name, value] of set.params) {
        pushTarget(set.action, name, value);
      }
    }
    for (const crawled of this.crawledGetTargets || []) {
      pushTarget(crawled.action, crawled.name, crawled.value);
    }

    this._injectionParamsTested = targets.length;
    if (targets.length === 0) return; // nothing to test (coverage notes this)

    const sqlErrorRe = /(SQL syntax.*?(?:MySQL|MariaDB)|You have an error in your SQL syntax|warning:\s*mysqli?_|mysql_fetch_|valid MySQL result|PostgreSQL.*?ERROR|pg_query\(\)|unterminated quoted string|Microsoft SQL (?:Server|Native Client)|ODBC SQL Server Driver|Unclosed quotation mark after the character string|System\.Data\.SqlClient\.SqlException|ORA-\d{5}|Oracle error|quoted string not properly terminated|SQLiteException|SQLSTATE\[|near ".*?": syntax error)/i;

    const sqlParams = [];
    const xssParams = [];

    const getBody = async (action, name, value) => {
      const u = new URL(action);
      u.searchParams.set(name, value);
      const res = await fetch(u.toString(), {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(3500),
        headers: { 'User-Agent': 'KalasagAudit/2.0' }
      });
      return { type: (res.headers.get('content-type') || '').toLowerCase(), body: await readTextBounded(res, 131072) };
    };

    this.log(`[*] Active injection test on ${targets.length} GET parameter(s)...`);

    // Run in parallel batches with a hard 10s module time budget so slow sites
    // never blow the overall audit timeout.
    const injectionStarted = Date.now();
    const INJECTION_BUDGET_MS = 10_000;
    const batchSize = 5;
    let actuallyTested = 0;

    for (let i = 0; i < targets.length; i += batchSize) {
      if (Date.now() - injectionStarted >= INJECTION_BUDGET_MS) break;
      const batch = targets.slice(i, i + batchSize);

      await Promise.all(
        batch.map(async (t) => {
          if (Date.now() - injectionStarted >= INJECTION_BUDGET_MS) return;
          actuallyTested += 1;
          const marker = `kqz${crypto.randomBytes(3).toString('hex')}`;

          const [baseRes, sqliRes, xssRes] = await Promise.allSettled([
            getBody(t.action, t.name, t.value),
            getBody(t.action, t.name, `${t.value}'`),
            getBody(t.action, t.name, `${marker}<svg/onload=1>`)
          ]);

          if (baseRes.status === 'fulfilled' && sqliRes.status === 'fulfilled') {
            if (sqlErrorRe.test(sqliRes.value.body) && !sqlErrorRe.test(baseRes.value.body)) {
              sqlParams.push(t.name);
            }
          }

          if (xssRes.status === 'fulfilled') {
            const { type, body } = xssRes.value;
            if (type.includes('html') && body.includes(`${marker}<svg/onload=1>`)) {
              xssParams.push(t.name);
            }
          }
        })
      );
    }
    this._injectionParamsTested = actuallyTested || targets.length;

    if (sqlParams.length > 0) {
      this.addFinding({
        severity: 'CRITICAL',
        category: 'Injection',
        title: 'Error-Based SQL Injection',
        description:
          `Injecting a single quote into parameter(s) [${[...new Set(sqlParams)].join(', ')}] caused a database error to surface in the response, ` +
          `while the normal page did not. This indicates user input reaches a SQL query unparameterized — an attacker can read, modify, or destroy the database.`,
        remediation:
          'Use parameterized queries / prepared statements for every query (PDO prepared statements, mysqli bind_param). Never concatenate user input into SQL. Add a least-privilege DB account.',
        scoreImpact: 45
      });
    }

    if (xssParams.length > 0) {
      this.addFinding({
        severity: 'HIGH',
        category: 'Injection',
        title: 'Reflected Cross-Site Scripting (XSS)',
        description:
          `Parameter(s) [${[...new Set(xssParams)].join(', ')}] reflect injected markup (e.g. <svg>) into the HTML response without encoding. ` +
          `An attacker can craft a link that runs arbitrary JavaScript in a victim's browser, stealing sessions or performing actions as them.`,
        remediation:
          'Context-encode all user input on output (htmlspecialchars for HTML, and the correct encoder for attribute/JS/URL contexts). Add a strict Content-Security-Policy as defense in depth.',
        scoreImpact: 20
      });
    }

    if (sqlParams.length === 0 && xssParams.length === 0) {
      this.addFinding({
        severity: 'PASS',
        category: 'Injection',
        title: 'No Injection Flaws Detected in Tested Parameters',
        description: `Tested ${targets.length} GET parameter(s) for error-based SQL injection and reflected XSS — none were vulnerable.`
      });
    }
  }

  async checkOtpRateLimiting() {
    const findings = await runOtpRateLimitTest(this.otpConfig, this.log);
    for (const f of findings) {
      this.addFinding(f);
    }
  }

  // -------------------------------------------------------------
  // MODULE 8: DNS & Email Security (SPF, DMARC, MX)
  // Smart Skip for Private / Local IP Networks
  // -------------------------------------------------------------
  async checkDnsAndEmailSecurity() {
    if (this.isInternalHost) {
      this.addFinding({
        severity: 'INFO',
        category: 'Email & DNS Security',
        title: 'Internal / Private Host Detected',
        description: `Host "${this.hostname}" is a private IP / local network. Public DNS email records (SPF/DMARC) do not apply to internal addresses.`,
        remediation: 'Public email security checks are skipped for private hosts.',
        scoreImpact: 0
      });
      return;
    }

    // Mail policy lives on the organizational domain: scanning www.example.com must not
    // report "missing SPF/DMARC" when example.com publishes them.
    const mailDomain = this.organizationalDomain(this.hostname);
    const txtRecords = async (name) => {
      try {
        return (await dns.resolveTxt(name)).map(r => r.join(''));
      } catch {
        return []; // NXDOMAIN / no TXT records
      }
    };

    // 1. SPF: the hostname's own record, else the organizational domain's.
    let spfDomain = this.hostname;
    let spf = (await txtRecords(this.hostname)).find(s => /^v=spf1\b/i.test(s));
    if (!spf && mailDomain !== this.hostname) {
      spfDomain = mailDomain;
      spf = (await txtRecords(mailDomain)).find(s => /^v=spf1\b/i.test(s));
    }
    if (!spf) {
      this.addFinding({
        severity: 'LOW',
        category: 'Email & DNS Security',
        title: 'Missing SPF Record on Domain',
        description: `No Sender Policy Framework (SPF) record found for ${mailDomain}. Phishers and spammers can easily forge emails pretending to be sent from your domain name.`,
        remediation: 'Add a DNS TXT record defining authorized mail sending servers: v=spf1 include:_spf.yourprovider.com ~all',
        scoreImpact: 5
      });
    } else {
      this.addFinding({
        severity: 'PASS',
        category: 'Email & DNS Security',
        title: 'SPF Record Configured',
        description: `SPF record is published on ${spfDomain}: "${spf.substring(0, 45)}..."`
      });
    }

    // 2. DMARC: RFC 7489 §6.6.3 — _dmarc.<host> first, then the organizational domain,
    // where the sp= tag (if present) is the policy for subdomains.
    let dmarcDomain = `_dmarc.${this.hostname}`;
    let dmarc = (await txtRecords(dmarcDomain)).find(s => /^v=DMARC1\b/i.test(s));
    let usedOrganizationalRecord = false;
    if (!dmarc && mailDomain !== this.hostname) {
      dmarcDomain = `_dmarc.${mailDomain}`;
      dmarc = (await txtRecords(dmarcDomain)).find(s => /^v=DMARC1\b/i.test(s));
      usedOrganizationalRecord = Boolean(dmarc);
    }

    if (!dmarc) {
      this.addFinding({
        severity: 'MEDIUM',
        category: 'Email & DNS Security',
        title: 'Missing DMARC Record (_dmarc)',
        description: `No DMARC record found at _dmarc.${this.hostname}${mailDomain !== this.hostname ? ` or _dmarc.${mailDomain}` : ''}. Mail servers will not reject fraudulent emails that fail SPF/DKIM checks.`,
        remediation: `Create a TXT record at _dmarc.${mailDomain}: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${mailDomain}`,
        scoreImpact: 8
      });
    } else {
      // Parse tags exactly: a substring test would read "sp=none" as "p=none".
      const tags = Object.fromEntries(dmarc.split(';')
        .map(t => t.split('=').map(s => s.trim().toLowerCase()))
        .filter(([key]) => key));
      const policy = usedOrganizationalRecord && tags.sp ? tags.sp : tags.p;
      const policyLabel = usedOrganizationalRecord && tags.sp ? 'sp' : 'p';
      if (policy === 'none') {
        this.addFinding({
          severity: 'LOW',
          category: 'Email & DNS Security',
          title: `DMARC Policy is Set to "${policyLabel}=none" (Monitoring Only)`,
          description: `DMARC at ${dmarcDomain} is in observation mode for this host. Spoofed emails will still be delivered to recipient inboxes.`,
          remediation: `Upgrade the DMARC policy from ${policyLabel}=none to quarantine or reject once SPF/DKIM alignment is verified.`,
          scoreImpact: 3
        });
      } else {
        this.addFinding({
          severity: 'PASS',
          category: 'Email & DNS Security',
          title: 'Enforced DMARC Policy Active',
          description: `DMARC at ${dmarcDomain} applies ${policyLabel}=${policy || 'unset'} to this host.`
        });
      }
    }

    await this.checkDnsRecordsExtended();
  }

  // -------------------------------------------------------------
  // MODULE 8b: Extended DNS (CAA, MX + DKIM presence, DKIM selectors)
  // -------------------------------------------------------------
  async checkDnsRecordsExtended() {
    // 1. CAA — restricts which CAs may issue certs for the domain (mis-issuance defense).
    // RFC 8659 §3: CAs climb from the hostname to its parents, so a record on the
    // organizational domain also protects www and other subdomains.
    try {
      const organizational = this.organizationalDomain(this.hostname);
      const labels = this.hostname.split('.');
      let caa = [];
      let lookupInconclusive = false;
      for (let i = 0; i < labels.length; i++) {
        const name = labels.slice(i).join('.');
        try {
          caa = await dns.resolveCaa(name);
        } catch (err) {
          // ENODATA/ENOTFOUND mean "no CAA here, keep climbing". Anything else (resolver
          // without CAA support, timeout, SERVFAIL) means we could not check: never
          // report a missing record we did not actually see.
          if (err && (err.code === 'ENODATA' || err.code === 'ENOTFOUND')) {
            caa = [];
          } else {
            lookupInconclusive = true;
            break;
          }
        }
        if (caa.length > 0 || name === organizational) break;
      }
      if (lookupInconclusive) {
        // Skip silently, as before: a resolver limitation is not a finding.
      } else if (!caa || caa.length === 0) {
        this.addFinding({
          severity: 'LOW',
          category: 'Email & DNS Security',
          title: 'No CAA Record (Any CA May Issue Certificates)',
          description: 'Without a CAA record, any public Certificate Authority can issue a TLS certificate for this domain, widening the mis-issuance attack surface.',
          remediation: 'Add a CAA record restricting issuance, e.g. 0 issue "letsencrypt.org".',
          scoreImpact: 2
        });
      } else {
        this.addFinding({
          severity: 'PASS',
          category: 'Email & DNS Security',
          title: 'CAA Record Published',
          description: `Certificate issuance is restricted via CAA (${caa.length} record(s)).`
        });
      }
    } catch {
      // Resolver may not support CAA — skip silently.
    }

    // 2. MX presence — only run DKIM discovery if the domain actually sends mail
    let hasMx = false;
    try {
      const mx = await dns.resolveMx(this.hostname);
      hasMx = Array.isArray(mx) && mx.length > 0;
    } catch {
      hasMx = false;
    }

    if (!hasMx) return; // No mail exchangers — DKIM/DMARC alignment is moot.

    // 3. DKIM — the selector is chosen by the sender and not discoverable from DNS,
    // so we best-effort probe common selectors. Absence here is INFORMATIONAL only
    // (we cannot prove DKIM is missing without the real selector).
    const selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim', 'mail', 's1', 's2'];
    let foundSelector = null;
    await Promise.all(selectors.map(async (sel) => {
      if (foundSelector) return;
      try {
        const rec = await dns.resolveTxt(`${sel}._domainkey.${this.hostname}`);
        const joined = rec.map(r => r.join('')).join('');
        if (/v=DKIM1|k=rsa|p=/i.test(joined)) foundSelector = sel;
      } catch {
        // selector not present
      }
    }));

    if (foundSelector) {
      this.addFinding({
        severity: 'PASS',
        category: 'Email & DNS Security',
        title: 'DKIM Signing Key Published',
        description: `A DKIM public key was found at selector "${foundSelector}._domainkey.${this.hostname}", enabling cryptographic email signing.`
      });
    } else {
      this.addFinding({
        severity: 'INFO',
        category: 'Email & DNS Security',
        title: 'DKIM Not Detected on Common Selectors',
        description: `The domain has MX records but no DKIM key was found on common selectors (${selectors.join(', ')}). DKIM may still exist under a custom selector this scanner cannot guess.`,
        remediation: 'Verify DKIM is configured with your mail provider; publish the provider-specific selector so DMARC alignment can pass.',
        scoreImpact: 0
      });
    }
  }
}
