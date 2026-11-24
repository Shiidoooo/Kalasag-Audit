import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPORT_CSS_PATH = path.resolve(__dirname, '..', 'public', 'report.css');

const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, PASS: 5 };

const CATEGORY_CONTEXT = {
  'Transport Security': {
    standard: 'OWASP A02:2021 • RFC 9110',
    impact: 'Unencrypted HTTP traffic can be intercepted or modified on public Wi-Fi, ISP networks, or corporate proxies, exposing logins and session tokens.'
  },
  'TLS / SSL Certificate': {
    standard: 'PCI-DSS 4.0 • RFC 8446 • OWASP A02:2021',
    impact: 'Expired, untrusted, or weak TLS encryption triggers browser warnings, breaks API integrations, and exposes traffic to downgrade or interception attacks.'
  },
  'Security Headers': {
    standard: 'OWASP A05:2021 • W3C CSP L3 • RFC 6797',
    impact: 'Browser security headers act as a built-in safety net. Without them, a single injection bug or malicious iframe can escalate into account takeover or credential theft.'
  },
  'Configuration Hygiene': {
    standard: 'OWASP A05:2021',
    impact: 'Duplicate headers from overlapping proxies and application middleware indicate conflicting security configs that are harder to maintain cleanly.'
  },
  'Information Leakage': {
    standard: 'OWASP A05:2021 • CIS Server Benchmark',
    impact: 'Broadcasting exact server or framework version numbers helps automated scanners immediately match your infrastructure against known CVE exploits.'
  },
  'Cookie Security': {
    standard: 'OWASP A07:2021 • CWE-1004 • RFC 6265bis',
    impact: 'Cookies often carry user login sessions. Missing Secure, HttpOnly, or SameSite flags make sessions vulnerable to theft via XSS, network sniffing, or CSRF.'
  },
  'HTTP Method Tampering': {
    standard: 'OWASP WSTG-CONF-06 • CWE-749',
    impact: 'Permissive HTTP methods like active TRACE or unauthenticated PUT/DELETE allow attackers to bypass cookie protections, upload malicious files, or delete site content.'
  },
  'Access Control (CORS)': {
    standard: 'OWASP A01:2021 • CWE-942',
    impact: 'A misconfigured CORS policy that trusts arbitrary external origins with credentials allows malicious websites to silently read private data from a logged-in user’s browser.'
  },
  'Exposed Artifacts & APIs': {
    standard: 'OWASP A05:2021 • CWE-538 • RFC 9116',
    impact: 'Accidentally public .env files, .git repositories, or debug endpoints can leak database passwords, API keys, and complete source code.'
  },
  'Frontend & Secrets': {
    standard: 'OWASP A06:2021 • W3C SRI',
    impact: 'Mixed HTTP content, unpinned third-party scripts, or hardcoded API keys expose users to supply-chain script hijacking and unauthorized cloud billing abuse.'
  },
  'Outdated Components': {
    standard: 'OWASP A06:2021 • CWE-1104',
    impact: 'Outdated or end-of-life JavaScript libraries carry publicly documented XSS vulnerabilities with ready-made exploit payloads.'
  },
  'Open Redirect': {
    standard: 'OWASP A01:2021 • CWE-601',
    impact: 'Attackers abuse trusted domain links that blindly redirect to external URLs to run convincing phishing campaigns and steal OAuth tokens.'
  },
  'Subdomain Takeover': {
    standard: 'OWASP WSTG-CONF-10',
    impact: 'A DNS record pointing to a deleted cloud resource lets an attacker claim that resource and serve phishing pages under your trusted brand domain.'
  },
  'Email & DNS Security': {
    standard: 'RFC 7208 (SPF) • RFC 7489 (DMARC) • RFC 8659 (CAA)',
    impact: 'Without enforced SPF, DMARC, and CAA records, attackers can send spoofed emails pretending to come from your domain or attempt unauthorized certificate issuance.'
  },
  'OTP / Rate Limiting': {
    standard: 'OWASP API4:2023 • OAT-019',
    impact: 'Unthrottled verification endpoints allow attackers to flood victims with SMS or email codes ("OTP bombing") while draining your messaging gateway budget.'
  },
  'Injection': {
    standard: 'OWASP A03:2021 • CWE-89 (SQLi) • CWE-79 (XSS)',
    impact: 'Unparameterized SQL queries or unescaped user output let attackers read/modify database records or execute arbitrary scripts in victim browsers.'
  },
  'Exposed Services': {
    standard: 'OWASP A05:2021 • CWE-1327',
    impact: 'Directly reachable database or administrative ports expose critical data stores to brute-force attacks, unauthenticated access, and known service CVEs.'
  },
  'Site Discovery & Crawl': {
    standard: 'OWASP WSTG-INFO-03 • Multi-Page Perimeter Scope',
    impact: 'Security headers or cookies applied inconsistently across subpages leave secondary routes weaker than the homepage.'
  },
  'Form & Auth Security': {
    standard: 'OWASP A01 / A02 / A07 • CWE-352 (CSRF)',
    impact: 'Unencrypted login forms or state-changing POST forms missing anti-CSRF protections expose credentials and authenticated user actions to interception or forgery.'
  }
};

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getGradeColor(grade) {
  if (!grade) return '#B45309';
  if (grade.startsWith('A')) return '#157347';
  if (grade === 'B') return '#1D4ED8';
  if (grade === 'C') return '#B45309';
  return '#B42318';
}

function getGradeColorClass(grade) {
  if (!grade) return 'grade-color-c';
  if (grade.startsWith('A')) return 'grade-color-a';
  if (grade === 'B') return 'grade-color-b';
  if (grade === 'C') return 'grade-color-c';
  return 'grade-color-df';
}

function getExecutiveHeadline(counts) {
  if (counts.CRITICAL > 0) return 'Immediate Action Needed';
  if (counts.HIGH > 0) return 'High-Priority Gaps Detected';
  if (counts.MEDIUM > 0) return 'Good Baseline — Minor Hardening Recommended';
  if (counts.LOW > 0) return 'Strong Security Posture';
  return 'Excellent Security Posture';
}

function getNextStepsSummary(counts) {
  if (counts.CRITICAL > 0) {
    return `Fix the ${counts.CRITICAL} critical exposure(s) right away (within 24 hours), then schedule the remaining ${counts.HIGH + counts.MEDIUM + counts.LOW} item(s).`;
  }
  if (counts.HIGH > 0) {
    return `No urgent critical leaks. Plan to resolve the ${counts.HIGH} high-priority item(s) within 1–7 days.`;
  }
  const minor = counts.MEDIUM + counts.LOW;
  if (minor > 0) {
    return `No critical or high risks found. The ${minor} medium/low hardening item(s) can be addressed during regular maintenance.`;
  }
  return `No remediation actions required — all ${counts.PASS} verified security controls are properly configured.`;
}

function getExecutiveNarrative(report, counts) {
  const host = report.hostname || report.targetUrl;
  const totalIssues = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;

  if (counts.CRITICAL > 0) {
    return `Our security check on ${host} found ${counts.CRITICAL} critical issue(s) that should be fixed right away. Although ${counts.PASS} security control(s) are working properly, critical issues can directly expose sensitive data and cap the overall grade at ${report.grade} (${report.score}/100) until fixed.`;
  }
  if (counts.HIGH > 0) {
    return `Our security check on ${host} found no critical data leaks, but spotted ${counts.HIGH} high-priority security gap(s). Fixing these alongside the ${counts.PASS} controls already working will significantly strengthen your site beyond its current ${report.grade} (${report.score}/100) grade.`;
  }
  if (totalIssues === 0) {
    return `${host} is very well protected, earning a grade of ${report.grade} (${report.score}/100). All ${counts.PASS} verified security controls passed with zero critical, high, medium, or low issues found.`;
  }
  return `${host} is well protected overall, with ${counts.PASS} verified security controls passing and zero critical or high-severity risks found. Addressing the remaining ${totalIssues} minor hardening item(s) below will polish the configuration even further.`;
}

function getStatusBadgeClass(status) {
  switch (status) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    case 'LOW': return 'badge-low';
    case 'INFO': return 'badge-info';
    case 'SKIPPED': return 'badge-skipped';
    default: return 'badge-pass';
  }
}

function formatReadableDate(iso) {
  try {
    const d = new Date(iso || Date.now());
    const datePart = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    const timePart = d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
    return `${datePart} • ${timePart}`;
  } catch {
    return String(iso || '');
  }
}

/**
 * Generates the formatted A4 HTML report.
 * - For live browser preview (`inlineCss: false`), links `/report.css` and `/report-preview.js`
 *   so it passes strict `style-src 'self'; script-src 'self'` CSP cleanly!
 * - For standalone headless PDF rendering (`inlineCss: true`), embeds `public/report.css` inline
 *   so the temp `file://` document renders identically with zero external asset paths.
 */
export async function buildEnterpriseReportHtml(report, { inlineCss = false, autoPrint = false } = {}) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, PASS: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }

  const issues = findings
    .filter((f) => f.severity !== 'PASS')
    .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || (b.scoreImpact || 0) - (a.scoreImpact || 0));
  const passed = findings.filter((f) => f.severity === 'PASS');

  const score = Math.max(0, Math.min(100, Number(report.score) || 0));
  const grade = String(report.grade || 'N/A');
  const gradeColor = getGradeColor(grade);
  const gradeColorClass = getGradeColorClass(grade);
  const circumference = 2 * Math.PI * 48;
  const dashOffset = (circumference * (1 - score / 100)).toFixed(2);
  const reportId = `KLS-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  const coverage = Array.isArray(report.coverage) ? report.coverage : [];
  const discoveredPages = Array.isArray(report.discoveredPages) ? report.discoveredPages : [];
  const discoveredApiRoutes = Array.isArray(report.discoveredApiRoutes) ? report.discoveredApiRoutes : [];
  const totalProbes = report.totalProbesExecuted || findings.length;
  const headline = getExecutiveHeadline(counts);
  const narrative = getExecutiveNarrative(report, counts);
  const nextSteps = getNextStepsSummary(counts);

  let styleBlock = '<link rel="stylesheet" href="/report.css">';
  if (inlineCss) {
    const cssText = await fs.readFile(REPORT_CSS_PATH, 'utf-8');
    styleBlock = `<style>${cssText}</style>`;
  }

  const coverageRows = coverage.length
    ? coverage.map((mod) => `
      <tr>
        <td class="col-domain"><strong>${escapeHtml(mod.name)}</strong><div class="sub-std">${escapeHtml(mod.standard)}</div></td>
        <td>${escapeHtml(mod.checks)}${mod.skippedReason ? `<div class="sub-skip">Note: ${escapeHtml(mod.skippedReason)}</div>` : ''}</td>
        <td class="col-center mono">${mod.probesRun}</td>
        <td class="col-center"><span class="badge ${getStatusBadgeClass(mod.status)}">${escapeHtml(mod.status === 'PASS' ? 'PASSED' : mod.status)}</span></td>
      </tr>
    `).join('')
    : `<tr><td colspan="4">Re-scan target to capture the full 12-domain probe coverage matrix.</td></tr>`;

  const issueCards = issues.length
    ? issues.map((item, idx) => {
        const refId = `KLS-${String(idx + 1).padStart(3, '0')}`;
        const ctx = CATEGORY_CONTEXT[item.category] || {
          standard: 'OWASP Web Security Testing Guide',
          impact: 'Configuration weaknesses increase the external attack surface and weaken defense-in-depth protections.'
        };
        const sevClass = `badge-${(item.severity || 'info').toLowerCase()}`;
        const borderClass = `border-${(item.severity || 'info').toLowerCase()}`;
        return `
          <article class="finding-card ${borderClass}">
            <div class="finding-top">
              <div class="finding-id-row">
                <span class="finding-ref mono">${refId}</span>
                <span class="badge ${sevClass}">${escapeHtml(item.severity)}</span>
                <span class="finding-cat">${escapeHtml(item.category)}</span>
              </div>
              <div class="finding-meta-right">
                <span class="finding-std">${escapeHtml(ctx.standard)}</span>
                ${item.scoreImpact > 0 ? `<span class="impact-tag mono">-${item.scoreImpact} pts</span>` : ''}
              </div>
            </div>
            <h3 class="finding-title">${escapeHtml(item.title)}</h3>
            <div class="finding-grid">
              <div class="finding-col">
                <div class="mini-label">Technical Observation</div>
                <p>${escapeHtml(item.description)}</p>
              </div>
              <div class="finding-col">
                <div class="mini-label">Why It Matters (Risk &amp; Impact)</div>
                <p>${escapeHtml(ctx.impact)}</p>
              </div>
            </div>
            ${item.remediation && item.remediation !== 'No specific fix needed.' ? `
              <div class="fix-box">
                <div class="fix-label">Recommended Fix</div>
                <div class="fix-text">${escapeHtml(item.remediation)}</div>
              </div>
            ` : ''}
          </article>
        `;
      }).join('')
    : `
      <div class="all-clear-box">
        <strong>Zero Security Weaknesses Detected.</strong> All automated outside-in checks across the audited perimeter passed cleanly with no actionable remediation required.
      </div>
    `;

  const passedCards = passed.length
    ? passed.map((p) => `
      <div class="pass-card">
        <div class="pass-head">
          <span class="pass-check">&#10003;</span>
          <strong>${escapeHtml(p.title)}</strong>
        </div>
        <div class="pass-cat">${escapeHtml(p.category)}</div>
        <p class="pass-desc">${escapeHtml(p.description)}</p>
      </div>
    `).join('')
    : `<p>No passed checks were recorded for this scan.</p>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Kalasag Audit Report — ${escapeHtml(report.hostname || report.targetUrl)}</title>
  ${styleBlock}
</head>
<body${autoPrint && !inlineCss ? ' data-auto-print="true"' : ''}>
  ${inlineCss ? '' : `
  <div class="preview-toolbar">
    <span class="preview-toolbar-title"><strong>Kalasag Audit</strong> &mdash; Report Preview</span>
    <button type="button" id="preview-print-btn" class="preview-print-btn">Print / Save as PDF</button>
  </div>
  `}

  <div class="page-wrap">
    <header class="doc-header">
      <div class="doc-header-top">
        <div class="brand-lockup">
          <svg width="38" height="38" viewBox="0 0 64 64" fill="none" aria-hidden="true">
            <path d="M32 4L48 11.5L51 35C51 46.5 42.5 55.2 32 60C21.5 55.2 13 46.5 13 35L16 11.5L32 4Z" fill="#1B2432" stroke="#C8A252" stroke-width="2.8" stroke-linejoin="round"/>
            <path d="M21 20L32 14.5L43 20M22.5 44.5L32 49.5L41.5 44.5" stroke="#C8A252" stroke-opacity="0.65" stroke-width="1.6" stroke-linecap="round"/>
            <circle cx="32" cy="32" r="9.5" fill="#0F172A" stroke="#157347" stroke-width="2.2"/>
            <circle cx="32" cy="32" r="4" fill="#34D399"/>
          </svg>
          <div>
            <div class="brand-title">Kalasag <span>Audit</span></div>
            <div class="brand-tag">Website Security Posture Report</div>
          </div>
        </div>
        <div class="doc-classification">
          <div class="classification-pill">Confidential &bull; Security Report</div>
          <div class="report-id-line mono">${reportId}</div>
        </div>
      </div>

      <div class="meta-strip">
        <div>
          <div class="meta-item-label">Target Audited</div>
          <div class="meta-item-val mono">${escapeHtml(report.targetUrl)}</div>
        </div>
        <div>
          <div class="meta-item-label">Environment</div>
          <div class="meta-item-val">${report.isInternalHost ? 'Internal / Local' : 'Public Website'}</div>
        </div>
        <div>
          <div class="meta-item-label">Scanned On</div>
          <div class="meta-item-val">${escapeHtml(formatReadableDate(report.scanTime))}</div>
        </div>
        <div>
          <div class="meta-item-label">Coverage</div>
          <div class="meta-item-val">${totalProbes} Checks &bull; ${coverage.length || 12} Areas</div>
        </div>
      </div>
    </header>

    <section class="verdict-card">
      <div class="verdict-top">
        <div class="gauge-box">
          <svg class="gauge-svg" width="114" height="114" viewBox="0 0 114 114">
            <circle cx="57" cy="57" r="48" fill="none" stroke="#E2E8F0" stroke-width="7.5"/>
            <circle cx="57" cy="57" r="48" fill="none" stroke="${gradeColor}" stroke-width="7.5" stroke-linecap="round" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${dashOffset}"/>
          </svg>
          <div class="gauge-center">
            <div class="gauge-grade ${gradeColorClass}">${escapeHtml(grade)}</div>
            <div class="gauge-score">${score} / 100</div>
          </div>
        </div>
        <div>
          <div class="verdict-kicker">Executive Summary</div>
          <h1 class="verdict-heading">${escapeHtml(headline)}</h1>
          <p class="verdict-text">${escapeHtml(narrative)}</p>
          ${report.gradeCappedBy ? `<div class="cap-note">Grade Ceiling Applied: At least one ${escapeHtml(report.gradeCappedBy)} finding caps the maximum grade until resolved.</div>` : ''}
        </div>
      </div>

      <div class="metrics-bar">
        <div class="metric-cell ${counts.CRITICAL ? 'is-active-crit' : 'is-zero'}">
          <div class="metric-num">${counts.CRITICAL}</div>
          <div class="metric-lbl"><span class="metric-dot dot-crit"></span>Critical</div>
        </div>
        <div class="metric-cell ${counts.HIGH ? 'is-active-high' : 'is-zero'}">
          <div class="metric-num">${counts.HIGH}</div>
          <div class="metric-lbl"><span class="metric-dot dot-high"></span>High</div>
        </div>
        <div class="metric-cell ${counts.MEDIUM ? 'is-active-med' : 'is-zero'}">
          <div class="metric-num">${counts.MEDIUM}</div>
          <div class="metric-lbl"><span class="metric-dot dot-med"></span>Medium</div>
        </div>
        <div class="metric-cell ${counts.LOW ? 'is-active-low' : 'is-zero'}">
          <div class="metric-num">${counts.LOW}</div>
          <div class="metric-lbl"><span class="metric-dot dot-low"></span>Low</div>
        </div>
        <div class="metric-cell ${counts.INFO ? 'is-active-info' : 'is-zero'}">
          <div class="metric-num">${counts.INFO}</div>
          <div class="metric-lbl"><span class="metric-dot dot-info"></span>Info</div>
        </div>
        <div class="metric-cell ${counts.PASS ? 'is-active-pass' : 'is-zero'}">
          <div class="metric-num">${counts.PASS}</div>
          <div class="metric-lbl"><span class="metric-dot dot-pass"></span>Passed</div>
        </div>
      </div>

      <div class="next-steps-bar">
        <span class="next-steps-tag">Recommended Next Step:</span>
        <span>${escapeHtml(nextSteps)}</span>
      </div>
    </section>

    <div class="section-head">
      <h2>1. Security Coverage Matrix (${coverage.length || 14} Domains &bull; ${totalProbes} Automated Checks)</h2>
      <span>Multi-Page Perimeter Scope</span>
    </div>
    <table class="matrix">
      <thead>
        <tr>
          <th>Security Domain &amp; Standards</th>
          <th>Checks Performed</th>
          <th class="col-center">Checks</th>
          <th class="col-center">Status</th>
        </tr>
      </thead>
      <tbody>
        ${coverageRows}
      </tbody>
    </table>

    ${(discoveredPages.length > 0 || discoveredApiRoutes.length > 0) ? `
    <div class="section-head">
      <h2>2. Discovered Site Map &amp; API Routes (${discoveredPages.length} Page${discoveredPages.length === 1 ? '' : 's'}${discoveredApiRoutes.length ? ` &bull; ${discoveredApiRoutes.length} JS Route${discoveredApiRoutes.length === 1 ? '' : 's'}` : ''})</h2>
      <span>Same-Origin Crawl &amp; JS Extraction</span>
    </div>
    <table class="matrix">
      <thead>
        <tr>
          <th>Discovered Path</th>
          <th>Source</th>
          <th class="col-center">Status</th>
          <th class="col-center">Forms</th>
        </tr>
      </thead>
      <tbody>
        ${discoveredPages.slice(0, 35).map((p) => `
          <tr>
            <td class="mono">${escapeHtml(p.path || p.url)}${p.title ? `<div class="sub-std">${escapeHtml(p.title)}</div>` : ''}</td>
            <td>${escapeHtml(p.source || 'crawl')}${p.depth !== undefined ? ` (D${p.depth})` : ''}</td>
            <td class="col-center mono">${escapeHtml(p.status || 200)}</td>
            <td class="col-center mono">${p.formsCount || 0}</td>
          </tr>
        `).join('')}
        ${discoveredPages.length > 35 ? `<tr><td colspan="4" class="sub-std">+ ${discoveredPages.length - 35} additional crawled page(s) recorded in the full JSON/Markdown export.</td></tr>` : ''}
      </tbody>
    </table>
    ${discoveredApiRoutes.length > 0 ? `
      <div class="method-box">
        <h3>API &amp; App Endpoints Referenced in JavaScript (${discoveredApiRoutes.length})</h3>
        <p class="mono">${discoveredApiRoutes.map(r => escapeHtml(r)).join(' &bull; ')}</p>
      </div>
    ` : ''}
    ` : ''}

    <div class="section-head">
      <h2>${(discoveredPages.length > 0 || discoveredApiRoutes.length > 0) ? '3' : '2'}. Detailed Findings, Risk Analysis &amp; Remediation (${issues.length})</h2>
      <span>Ordered by Priority &amp; Score Impact</span>
    </div>
    ${issueCards}

    <div class="section-head">
      <h2>${(discoveredPages.length > 0 || discoveredApiRoutes.length > 0) ? '4' : '3'}. Verified Defensive Controls (${passed.length})</h2>
      <span>Confirmed Active Protections</span>
    </div>
    <div class="pass-grid">
      ${passedCards}
    </div>

    <div class="section-head">
      <h2>${(discoveredPages.length > 0 || discoveredApiRoutes.length > 0) ? '5' : '4'}. Grading Methodology &amp; Verification Standards</h2>
      <span>Kalasag Audit Engine v2.0</span>
    </div>
    <div class="method-box">
      <h3>How Kalasag Audit Scores &amp; Verifies Findings</h3>
      <p><strong>Fair Diminishing-Returns Scoring:</strong> Critical and High findings deduct full points and enforce strict grade ceilings (any Critical finding caps the grade at <strong>D / 40</strong>; High caps at <strong>B / 84</strong>; Medium caps at <strong>A / 94</strong>). Medium and Low findings apply diminishing returns (capped at -30 and -15 respectively) so minor configuration notes cannot bury a fundamentally secure application.</p>
      <p><strong>Anti-False-Alarm Verification:</strong> Every probe is validated against real specifications (W3C CSP Level 3 directive fallback, RFC 6797 quoted HSTS, RFC 7489 DMARC subdomain rules, subpath-relative artifact checks, baseline-compared error-based SQLi/XSS checks in local mode, HTML soft-404 rejection, and canary-verified checks). No destructive payloads or credential brute-forcing are executed.</p>
      <p><strong>Confidentiality &amp; Scope:</strong> Generated by Kalasag Audit for authorized security assessment and hardening. Share remediation findings privately with the system owners.</p>
    </div>

    <footer class="report-footer">
      <span>Generated by <strong>Kalasag Audit v2.0</strong> &mdash; Local-First Web Security Auditor</span>
      <span class="mono">${reportId} &bull; ${escapeHtml(report.hostname || '')}</span>
    </footer>
  </div>

  ${inlineCss ? '' : '<script src="/report-preview.js" defer></script>'}
</body>
</html>`;
}

async function findHeadlessBrowser() {
  const candidates =
    process.platform === 'win32'
      ? [
          process.env.KALASAG_CHROME_PATH,
          'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
          'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
          'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
          'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
        ]
      : process.platform === 'darwin'
        ? [
            process.env.KALASAG_CHROME_PATH,
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
            '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'
          ]
        : [
            process.env.KALASAG_CHROME_PATH,
            '/usr/bin/google-chrome',
            '/usr/bin/chromium',
            '/usr/bin/chromium-browser',
            '/usr/bin/microsoft-edge'
          ];

  for (const candidate of candidates) {
    if (!candidate) continue;
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // try next
    }
  }
  return null;
}

/**
 * Renders the formatted A4 HTML report into a real binary PDF buffer using
 * the local system's headless Chrome or Edge (zero npm dependencies).
 */
export async function renderEnterprisePdf(report) {
  const browserPath = await findHeadlessBrowser();
  if (!browserPath) {
    const err = new Error('No local Chrome or Edge browser was found for direct PDF generation.');
    err.statusCode = 503;
    err.code = 'PDF_ENGINE_UNAVAILABLE';
    throw err;
  }

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kalasag-pdf-'));
  const htmlPath = path.join(tmpDir, 'report.html');
  const pdfPath = path.join(tmpDir, 'report.pdf');
  const userDataDir = path.join(tmpDir, 'profile');

  try {
    const html = await buildEnterpriseReportHtml(report, { inlineCss: true });
    await fs.writeFile(htmlPath, html, 'utf-8');

    const fileUrl = `file:///${htmlPath.replace(/\\/g, '/')}`;
    await execFileAsync(
      browserPath,
      [
        '--headless=new',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-extensions',
        `--user-data-dir=${userDataDir}`,
        '--no-pdf-header-footer',
        `--print-to-pdf=${pdfPath}`,
        fileUrl
      ],
      { timeout: 25000, windowsHide: true }
    );

    return await fs.readFile(pdfPath);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}
