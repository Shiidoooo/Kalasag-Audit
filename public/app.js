/**
 * Kalasag Audit — Local Web UI Controller
 * Zero external dependencies, strict textContent rendering (no untrusted innerHTML),
 * centralized API client with timeouts & AbortController cancellation, URL-synced views.
 */

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'PASS'];
const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, PASS: 5 };
const SEVERITY_LABELS = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
  PASS: 'Passed'
};
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * 66; // ~414.69

// Application state (single source of truth)
const BROWSER_HISTORY_KEY = 'kalasag-browser-history';
const MAX_BROWSER_HISTORY = 25;

const state = {
  activeView: 'scanner',
  isScanning: false,
  abortController: null,
  currentScan: null,
  historyItems: [],
  runtime: {
    mode: 'local',
    features: {
      pdfDirect: true,
      serverHistory: true,
      otpTest: true
    }
  },
  otpUi: {
    fieldKey: 'mobile',
    maxRequests: 4
  },
  filters: {
    severity: 'ALL',
    category: 'ALL',
    search: '',
    sort: 'severity'
  }
};

// Centralized API client
const api = {
  async request(path, options = {}) {
    const controller = options.controller || new AbortController();
    const timeoutMs = options.timeoutMs || 50000;
    const timer = setTimeout(() => controller.abort(new Error('Request timed out.')), timeoutMs);

    try {
      const res = await fetch(path, {
        method: options.method || 'GET',
        headers: options.body ? { 'Content-Type': 'application/json', ...(options.headers || {}) } : options.headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
        signal: controller.signal
      });

      const contentType = (res.headers.get('content-type') || '').toLowerCase();
      if (options.rawResponse) {
        if (!res.ok) throw new Error(`Request failed with status ${res.status}`);
        return res;
      }

      const data = contentType.includes('application/json') ? await res.json() : null;
      if (!res.ok || (data && data.status === 'error')) {
        const msg = data?.message || `Server returned HTTP ${res.status}`;
        const err = new Error(msg);
        err.code = data?.error?.code || 'HTTP_ERROR';
        throw err;
      }
      return data;
    } finally {
      clearTimeout(timer);
    }
  },

  health: () => api.request('/api/health', { timeoutMs: 5000 }),
  runAudit: (payload, controller) => api.request('/api/audit', { method: 'POST', body: payload, controller, timeoutMs: 65000 }),
  listHistory: () => api.request('/api/history', { timeoutMs: 8000 }),
  getHistoryItem: (id) => api.request(`/api/history/${encodeURIComponent(id)}`, { timeoutMs: 8000 }),
  deleteHistoryItem: (id) => api.request(`/api/history/${encodeURIComponent(id)}`, { method: 'DELETE', timeoutMs: 8000 }),
  clearHistory: () => api.request('/api/history', { method: 'DELETE', timeoutMs: 8000 }),
  exportMarkdown: (report) => api.request('/api/export/markdown', { method: 'POST', body: { report }, rawResponse: true, timeoutMs: 10000 }),
  exportPdf: (report) => api.request('/api/export/pdf', { method: 'POST', body: { report }, rawResponse: true, timeoutMs: 30000 }),
  exportHtmlPreview: (report) => api.request('/api/export/html', { method: 'POST', body: { report }, rawResponse: true, timeoutMs: 10000 })
};

// DOM references
const el = {
  navLinks: document.querySelectorAll('[data-nav]'),
  views: {
    scanner: document.getElementById('view-scanner'),
    history: document.getElementById('view-history'),
    about: document.getElementById('view-about')
  },
  themeToggle: document.getElementById('theme-toggle'),
  engineStatus: document.getElementById('engine-status'),
  engineStatusLabel: document.getElementById('engine-status-label'),
  heroEyebrowText: document.getElementById('hero-eyebrow-text'),
  heroSubtitleText: document.getElementById('hero-subtitle-text'),
  statChecksVal: document.getElementById('stat-checks-val'),
  statModeVal: document.getElementById('stat-mode-val'),
  statModeLabel: document.getElementById('stat-mode-label'),
  howStep1Desc: document.getElementById('how-step1-desc'),
  howStep2Title: document.getElementById('how-step2-title'),
  historyBadge: document.getElementById('history-count-badge'),

  // Scanner controls
  commandDeck: document.getElementById('command-deck'),
  howStrip: document.getElementById('how-it-works-strip'),
  auditForm: document.getElementById('audit-form'),
  targetUrlInput: document.getElementById('target-url'),
  urlError: document.getElementById('url-error'),
  runAuditBtn: document.getElementById('run-audit-btn'),
  presetChips: document.querySelectorAll('[data-preset]'),
  presetSelf: document.getElementById('preset-self'),
  presetAlt: document.getElementById('preset-alt'),
  crawlMaxPages: document.getElementById('crawl-max-pages'),
  crawlOpt100: document.getElementById('crawl-opt-100'),

  // Guided Optional OTP drawer
  otpDrawer: document.getElementById('otp-drawer'),
  otpToggleBtn: document.getElementById('otp-toggle-btn'),
  otpStatusPill: document.getElementById('otp-status-pill'),
  otpPanel: document.getElementById('otp-panel'),
  otpEnabled: document.getElementById('otp-enabled'),
  otpFields: document.getElementById('otp-fields'),
  otpUrl: document.getElementById('otp-url'),
  otpRecipient: document.getElementById('otp-recipient'),
  otpFieldBtns: document.querySelectorAll('[data-otp-field]'),
  otpMaxBtns: document.querySelectorAll('[data-otp-max]'),
  otpPreviewText: document.getElementById('otp-preview-text'),
  otpExtraToggle: document.getElementById('otp-extra-toggle'),
  otpExtraPanel: document.getElementById('otp-extra-panel'),
  otpMethod: document.getElementById('otp-method'),
  otpApiKey: document.getElementById('otp-api-key'),
  otpHeaders: document.getElementById('otp-headers'),
  otpBody: document.getElementById('otp-body'),
  otpConfirm: document.getElementById('otp-confirm'),

  // Error & Loading
  errorBanner: document.getElementById('audit-error-banner'),
  errorMessage: document.getElementById('audit-error-message'),
  retryAuditBtn: document.getElementById('retry-audit-btn'),
  loadingPanel: document.getElementById('scan-loading-panel'),
  loadingTargetLabel: document.getElementById('loading-target-label'),
  loadingTimer: document.getElementById('loading-timer'),
  phaseItems: document.querySelectorAll('.phase-item'),
  cancelAuditBtn: document.getElementById('cancel-audit-btn'),

  // Results
  resultsDashboard: document.getElementById('results-dashboard'),
  gaugeArc: document.getElementById('gauge-arc'),
  resultGrade: document.getElementById('result-grade'),
  resultScore: document.getElementById('result-score'),
  resultHostType: document.getElementById('result-host-type'),
  resultProbesCount: document.getElementById('result-probes-count'),
  resultScanTime: document.getElementById('result-scan-time'),
  resultDuration: document.getElementById('result-duration'),
  resultTargetUrl: document.getElementById('result-target-url'),
  resultVerdictSummary: document.getElementById('result-verdict-summary'),
  gradeCapBanner: document.getElementById('grade-cap-banner'),
  gradeCapText: document.getElementById('grade-cap-text'),
  severityStrip: document.getElementById('severity-strip'),
  moduleGrid: document.getElementById('module-grid'),
  discoveredRoutesBlock: document.getElementById('discovered-routes-block'),
  discoveredRoutesSummary: document.getElementById('discovered-routes-summary'),
  routesFilterWrap: document.getElementById('routes-filter-wrap'),
  routesSearch: document.getElementById('routes-search'),
  discoveredPagesList: document.getElementById('discovered-pages-list'),
  apiRoutesWrap: document.getElementById('api-routes-wrap'),
  apiRoutesChips: document.getElementById('api-routes-chips'),
  clearFiltersBtn: document.getElementById('clear-filters-btn'),
  findingsCountLabel: document.getElementById('findings-count-label'),
  findingSearch: document.getElementById('finding-search'),
  categoryFilter: document.getElementById('category-filter'),
  sortFilter: document.getElementById('sort-filter'),
  findingsList: document.getElementById('findings-list'),

  // Export actions
  exportPdfBtn: document.getElementById('export-pdf-btn'),
  previewReportBtn: document.getElementById('preview-report-btn'),
  copyAiBtn: document.getElementById('copy-ai-btn'),
  exportMdBtn: document.getElementById('export-md-btn'),
  exportJsonBtn: document.getElementById('export-json-btn'),
  rescanCurrentBtn: document.getElementById('rescan-current-btn'),

  // History view
  historyEyebrowText: document.getElementById('history-eyebrow-text'),
  historyEmptyText: document.getElementById('history-empty-text'),
  refreshHistoryBtn: document.getElementById('refresh-history-btn'),
  clearHistoryBtn: document.getElementById('clear-history-btn'),
  historyEmpty: document.getElementById('history-empty'),
  historyTableWrap: document.getElementById('history-table-wrap'),
  historyTbody: document.getElementById('history-tbody'),

  // Dialog & Toast
  confirmDialog: document.getElementById('confirm-dialog'),
  dialogCancelBtn: document.getElementById('dialog-cancel-btn'),
  dialogConfirmBtn: document.getElementById('dialog-confirm-btn'),
  toastRegion: document.getElementById('toast-region')
};

// =========================================================================
// Helpers
// =========================================================================
function createEl(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function showToast(message) {
  const toast = createEl('div', 'toast', message);
  el.toastRegion.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

function formatDateTime(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return iso;
  }
}

function getGradeClass(grade) {
  if (!grade) return 'grade-c';
  if (grade.startsWith('A')) return 'grade-a';
  if (grade === 'B') return 'grade-b';
  if (grade === 'C') return 'grade-c';
  return 'grade-df';
}

function getGaugeStrokeColor(grade) {
  if (!grade) return 'var(--gold)';
  if (grade.startsWith('A')) return 'var(--sev-pass)';
  if (grade === 'B') return 'var(--sev-low)';
  if (grade === 'C') return 'var(--sev-medium)';
  return 'var(--sev-critical)';
}

function computeCounts(findings = []) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, PASS: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }
  return counts;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// =========================================================================
// Guided OTP Preview & Controls
// =========================================================================
function updateOtpPreview() {
  const method = el.otpMethod.value || 'POST';
  const recipientPreview = el.otpRecipient.value.trim() || (state.otpUi.fieldKey === 'email' ? 'you@company.com' : '09171234567');
  const max = state.otpUi.maxRequests;

  let bodyDisplay;
  if (state.otpUi.fieldKey === 'custom') {
    bodyDisplay = el.otpBody.value.trim() || '{"mobile":"{{RECIPIENT}}"}';
  } else {
    bodyDisplay = JSON.stringify({ [state.otpUi.fieldKey]: recipientPreview });
  }

  el.otpPreviewText.textContent = `${method} ${bodyDisplay} — up to ${max} sends, stops immediately once blocked`;
}

function syncOtpStatusPill() {
  const isOn = el.otpEnabled.checked;
  el.otpStatusPill.textContent = isOn ? 'Enabled' : 'Off';
  el.otpStatusPill.classList.toggle('pill-active', isOn);
  el.otpStatusPill.classList.toggle('pill-muted', !isOn);
}

// =========================================================================
// Theme & Navigation
// =========================================================================
function initTheme() {
  const saved = localStorage.getItem('kalasag-theme');
  document.documentElement.setAttribute('data-theme', saved || 'dark');
}

function handleToggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('kalasag-theme', next);
  showToast(`Switched to ${next} theme.`);
}

function setActiveView(viewName, updateHash = true) {
  const valid = ['scanner', 'history', 'about'].includes(viewName) ? viewName : 'scanner';
  state.activeView = valid;

  for (const [key, section] of Object.entries(el.views)) {
    const isMatch = key === valid;
    section.hidden = !isMatch;
    section.classList.toggle('is-active', isMatch);
  }

  document.querySelectorAll('.primary-nav [data-nav]').forEach(link => {
    const isMatch = link.getAttribute('data-nav') === valid;
    link.classList.toggle('is-active', isMatch);
    if (isMatch) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });

  if (updateHash && window.location.hash !== `#${valid}`) {
    window.history.replaceState(null, '', `#${valid}`);
  }

  if (valid === 'history') {
    refreshHistory();
  }
}

// =========================================================================
// Audit Execution Flow
// =========================================================================
let timerInterval = null;
let phaseTimeouts = [];

function startLoadingVisuals(targetLabel) {
  el.loadingTargetLabel.textContent = targetLabel;
  el.loadingTimer.textContent = '0.0s';
  el.howStrip.hidden = true;
  el.loadingPanel.hidden = false;
  el.errorBanner.hidden = true;
  el.resultsDashboard.hidden = true;
  el.runAuditBtn.disabled = true;
  el.runAuditBtn.classList.add('is-loading');

  el.phaseItems.forEach((item, idx) => {
    item.classList.toggle('is-active', idx === 0);
    item.classList.remove('is-done');
  });

  const startedAt = Date.now();
  timerInterval = setInterval(() => {
    el.loadingTimer.textContent = `${((Date.now() - startedAt) / 1000).toFixed(1)}s`;
  }, 100);

  phaseTimeouts = [
    setTimeout(() => {
      el.phaseItems[0]?.classList.replace('is-active', 'is-done');
      el.phaseItems[1]?.classList.add('is-active');
    }, 350),
    setTimeout(() => {
      el.phaseItems[1]?.classList.replace('is-active', 'is-done');
      el.phaseItems[2]?.classList.add('is-active');
    }, 1100)
  ];
}

function stopLoadingVisuals() {
  clearInterval(timerInterval);
  phaseTimeouts.forEach(clearTimeout);
  phaseTimeouts = [];
  el.loadingPanel.hidden = true;
  el.runAuditBtn.disabled = false;
  el.runAuditBtn.classList.remove('is-loading');
}

function setFieldError(message) {
  if (!message) {
    el.urlError.hidden = true;
    el.urlError.textContent = '';
    el.targetUrlInput.classList.remove('is-invalid');
    return;
  }
  el.urlError.textContent = message;
  el.urlError.hidden = false;
  el.targetUrlInput.classList.add('is-invalid');
  el.targetUrlInput.focus();
}

function buildAuditPayload() {
  const url = el.targetUrlInput.value.trim();
  if (!url) {
    setFieldError('Please enter a website URL to scan (for example: https://example.com or http://localhost:3000).');
    return null;
  }
  setFieldError('');

  const payload = {
    url,
    maxPages: Number(el.crawlMaxPages?.value) || 50
  };

  if (state.runtime.features.otpTest && el.otpEnabled.checked) {
    const otpUrl = el.otpUrl.value.trim();
    const recipient = el.otpRecipient.value.trim();
    if (!otpUrl) {
      setFieldError('Please enter your "Send OTP" API URL inside the optional OTP check, or turn the OTP switch off.');
      return null;
    }
    if (!recipient) {
      setFieldError('Please enter your own test phone number or email for the optional OTP check.');
      return null;
    }
    if (!el.otpConfirm.checked) {
      setFieldError('Please check the confirmation box confirming you own the OTP API and test phone/email.');
      return null;
    }

    let parsedHeaders = { 'Content-Type': 'application/json' };
    const rawHeaders = el.otpHeaders.value.trim();
    if (rawHeaders) {
      try {
        parsedHeaders = JSON.parse(rawHeaders);
      } catch {
        setFieldError('Extra Headers must be valid JSON (or leave the default).');
        return null;
      }
    }

    // Convenience API Key / Bearer field merges cleanly into headers
    const apiKey = el.otpApiKey.value.trim();
    if (apiKey) {
      if (/^bearer\s+/i.test(apiKey)) {
        parsedHeaders.Authorization = apiKey;
      } else {
        parsedHeaders['X-Api-Key'] = apiKey;
      }
    }

    const bodyTemplate =
      state.otpUi.fieldKey === 'custom'
        ? el.otpBody.value
        : JSON.stringify({ [state.otpUi.fieldKey]: '{{RECIPIENT}}' });

    payload.confirmOtp = true;
    payload.otpTest = {
      url: otpUrl,
      method: el.otpMethod.value || 'POST',
      recipient,
      maxRequests: state.otpUi.maxRequests,
      headers: parsedHeaders,
      body: bodyTemplate
    };
  }

  return payload;
}

async function handleAuditSubmit(event) {
  if (event) event.preventDefault();
  if (state.isScanning) return;

  const payload = buildAuditPayload();
  if (!payload) return;

  state.isScanning = true;
  state.abortController = new AbortController();
  startLoadingVisuals(payload.url);

  try {
    const response = await api.runAudit(payload, state.abortController);
    state.currentScan = response.data;
    if (!state.runtime.features.serverHistory) {
      browserHistory.add(state.currentScan);
    }
    resetFilters();
    renderReportDashboard(state.currentScan);
    refreshHistory();
    showToast(`Scan finished: Grade ${response.data.report.grade} (${response.data.report.score}/100)`);
  } catch (err) {
    if (err.name === 'AbortError') {
      showToast('Scan cancelled.');
      if (!state.currentScan) el.howStrip.hidden = false;
    } else {
      el.errorMessage.textContent = err.message || 'Unable to complete the scan. Check that the URL is reachable.';
      el.errorBanner.hidden = false;
    }
  } finally {
    state.isScanning = false;
    state.abortController = null;
    stopLoadingVisuals();
  }
}

function handleCancelAudit() {
  if (state.abortController) {
    state.abortController.abort();
  }
}

// =========================================================================
// Results Rendering (Strict DOM Building — Zero Untrusted innerHTML)
// =========================================================================
function resetFilters() {
  state.filters = { severity: 'ALL', category: 'ALL', search: '', sort: 'severity' };
  el.findingSearch.value = '';
  el.categoryFilter.value = 'ALL';
  el.sortFilter.value = 'severity';
}

function renderReportDashboard(scan) {
  const { report, elapsedMs } = scan;
  const counts = computeCounts(report.findings);
  const issueTotal = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW + counts.INFO;

  el.commandDeck.classList.add('is-compact');
  el.howStrip.hidden = true;
  el.errorBanner.hidden = true;
  el.resultsDashboard.hidden = false;

  const score = Math.max(0, Math.min(100, Number(report.score) || 0));
  const offset = GAUGE_CIRCUMFERENCE * (1 - score / 100);
  el.gaugeArc.style.strokeDasharray = String(GAUGE_CIRCUMFERENCE);
  el.gaugeArc.style.stroke = getGaugeStrokeColor(report.grade);
  requestAnimationFrame(() => {
    el.gaugeArc.style.strokeDashoffset = String(offset);
  });

  el.resultGrade.textContent = report.grade;
  el.resultGrade.style.color = getGaugeStrokeColor(report.grade);
  el.resultScore.textContent = String(score);

  el.resultHostType.textContent = report.isInternalHost ? 'Local / Private Host' : 'Public Website';
  const totalProbes = report.totalProbesExecuted || report.findings.length;
  const domainCount = Array.isArray(report.coverage) ? report.coverage.length : 12;
  el.resultProbesCount.textContent = `${totalProbes} Checks \u2022 ${domainCount} Modules`;
  el.resultScanTime.textContent = formatDateTime(report.scanTime);
  el.resultDuration.textContent = elapsedMs ? `Scanned in ${(elapsedMs / 1000).toFixed(2)}s` : '';
  el.resultTargetUrl.textContent = report.targetUrl;

  if (counts.CRITICAL > 0) {
    el.resultVerdictSummary.textContent = `Action needed: ${counts.CRITICAL} critical issue(s) found that should be fixed right away (${counts.PASS} checks passed).`;
  } else if (counts.HIGH > 0) {
    el.resultVerdictSummary.textContent = `No critical leaks found, but ${counts.HIGH} high-priority issue(s) need attention (${counts.PASS} checks passed).`;
  } else if (issueTotal === 0) {
    el.resultVerdictSummary.textContent = `Excellent security! All ${counts.PASS} checks passed with zero issues found.`;
  } else {
    el.resultVerdictSummary.textContent = `Looking solid! ${counts.PASS} checks passed, with ${issueTotal} minor or informational note(s) to review.`;
  }

  if (report.gradeCappedBy) {
    el.gradeCapText.textContent = `Why is the grade capped? At least one ${report.gradeCappedBy} issue limits the maximum grade. Fixing it unlocks a higher tier.`;
    el.gradeCapBanner.hidden = false;
  } else {
    el.gradeCapBanner.hidden = true;
  }

  renderSeverityStrip(counts);
  renderModuleMatrix(report.findings);
  renderDiscoveredRoutes(report);
  populateCategoryDropdown(report.findings);
  renderFindingsList();
}

function renderDiscoveredRoutes(report, filterText = '') {
  const pages = Array.isArray(report.discoveredPages) ? report.discoveredPages : [];
  const apiRoutes = Array.isArray(report.discoveredApiRoutes) ? report.discoveredApiRoutes : [];
  const stats = report.crawlStats || null;

  if (pages.length === 0 && apiRoutes.length === 0) {
    el.discoveredRoutesBlock.hidden = true;
    return;
  }

  el.discoveredRoutesBlock.hidden = false;
  if (el.routesFilterWrap) {
    el.routesFilterWrap.hidden = pages.length <= 8;
    if (!filterText && el.routesSearch) el.routesSearch.value = '';
  }

  const depthInfo = stats?.maxDepthReached ? ` across depth ${stats.maxDepthReached}` : '';
  const limitInfo = stats?.truncatedByLimit ? ` (crawl limit ${stats.maxPages} reached)` : '';
  const pagesWithIssues = pages.filter(p => Array.isArray(p.issues) && p.issues.length > 0).length;
  el.discoveredRoutesSummary.textContent =
    `Automatically audited all ${pages.length} discovered page(s)${depthInfo}${limitInfo} — ` +
    `${pagesWithIssues === 0 ? 'all pages clean on per-page checks' : `${pagesWithIssues} page(s) flagged`}` +
    (apiRoutes.length > 0 ? ` • ${apiRoutes.length} JS API/app route(s) mapped.` : '.');

  const needle = filterText.trim().toLowerCase();
  const visiblePages = needle
    ? pages.filter(p => `${p.path || ''} ${p.title || ''} ${p.source || ''}`.toLowerCase().includes(needle))
    : pages;

  el.discoveredPagesList.replaceChildren();
  for (const page of visiblePages) {
    const pageIssues = Array.isArray(page.issues) ? page.issues : [];
    const wrap = createEl('div', 'discovered-page-item');
    const row = createEl('div', 'discovered-page-row');

    const info = createEl('div', 'discovered-page-info');
    info.append(
      createEl('span', 'discovered-page-path mono', page.path || page.url),
      createEl('span', 'source-tag', page.source || 'crawl')
    );
    if (page.depth !== undefined) {
      info.appendChild(createEl('span', 'depth-tag mono', `D${page.depth}`));
    }
    if (page.title) {
      info.appendChild(createEl('span', 'discovered-page-title', page.title));
    }

    const meta = createEl('div', 'discovered-page-meta');
    meta.append(
      createEl('span', 'mono status-chip', `HTTP ${page.status || 200}`),
      createEl('span', 'forms-chip', `${page.formsCount || 0} form${(page.formsCount || 0) === 1 ? '' : 's'}`)
    );

    if (pageIssues.length === 0) {
      meta.appendChild(createEl('span', 'page-audit-badge is-clean', '\u2713 Audited'));
    } else {
      const detailBtn = createEl(
        'button',
        'page-audit-badge is-flagged',
        `${pageIssues.length} Issue${pageIssues.length > 1 ? 's' : ''} \u25BE`
      );
      detailBtn.type = 'button';
      detailBtn.setAttribute('aria-expanded', 'false');

      const detailList = createEl('div', 'page-issue-details');
      detailList.hidden = true;
      for (const issue of pageIssues) {
        const line = createEl('div', 'page-issue-line');
        line.append(
          createEl('span', `sev-badge sev-${(issue.severity || 'info').toLowerCase()}`, issue.severity || 'INFO'),
          createEl('span', null, issue.label)
        );
        detailList.appendChild(line);
      }

      detailBtn.addEventListener('click', () => {
        const next = detailBtn.getAttribute('aria-expanded') !== 'true';
        detailBtn.setAttribute('aria-expanded', String(next));
        detailList.hidden = !next;
      });

      meta.appendChild(detailBtn);
      row.append(info, meta);
      wrap.append(row, detailList);
      el.discoveredPagesList.appendChild(wrap);
      continue;
    }

    row.append(info, meta);
    wrap.appendChild(row);
    el.discoveredPagesList.appendChild(wrap);
  }

  if (apiRoutes.length > 0) {
    el.apiRoutesWrap.hidden = false;
    el.apiRoutesChips.replaceChildren();
    for (const route of apiRoutes) {
      el.apiRoutesChips.appendChild(createEl('span', 'route-chip mono', route));
    }
  } else {
    el.apiRoutesWrap.hidden = true;
  }
}

function renderSeverityStrip(counts) {
  el.severityStrip.replaceChildren();
  for (const sev of SEVERITY_ORDER) {
    const btn = createEl('button', `sev-tile sev-${sev.toLowerCase()}`);
    btn.type = 'button';
    btn.dataset.sev = sev;
    if (state.filters.severity === sev) btn.classList.add('is-selected');
    btn.setAttribute('aria-pressed', String(state.filters.severity === sev));

    btn.append(
      createEl('span', 'sev-tile-count', counts[sev]),
      createEl('span', 'sev-tile-label', SEVERITY_LABELS[sev])
    );

    btn.addEventListener('click', () => {
      state.filters.severity = state.filters.severity === sev ? 'ALL' : sev;
      renderSeverityStrip(counts);
      renderFindingsList();
    });

    el.severityStrip.appendChild(btn);
  }
}

function renderModuleMatrix(findings) {
  const byCategory = new Map();
  for (const f of findings) {
    const cat = f.category || 'General';
    if (!byCategory.has(cat)) {
      byCategory.set(cat, { name: cat, issues: 0, passed: 0, worstRank: 99, worstSev: 'PASS' });
    }
    const bucket = byCategory.get(cat);
    if (f.severity === 'PASS') {
      bucket.passed += 1;
    } else {
      bucket.issues += 1;
      const rank = SEVERITY_RANK[f.severity] ?? 4;
      if (rank < bucket.worstRank) {
        bucket.worstRank = rank;
        bucket.worstSev = f.severity;
      }
    }
  }

  el.moduleGrid.replaceChildren();

  const sortedCategories = [...byCategory.values()].sort((a, b) => a.worstRank - b.worstRank || a.name.localeCompare(b.name));
  for (const mod of sortedCategories) {
    const card = createEl('button', 'module-card');
    card.type = 'button';
    if (state.filters.category === mod.name) card.classList.add('is-selected');

    const top = createEl('div', 'module-card-top');
    top.append(
      createEl('span', 'module-name', mod.name),
      createEl('span', `sev-badge sev-${mod.worstSev.toLowerCase()}`, mod.worstSev === 'PASS' ? 'Clean' : mod.worstSev)
    );

    const summaryText = mod.issues === 0
      ? `${mod.passed} check(s) passed`
      : `${mod.issues} item(s) \u2022 ${mod.passed} passed`;

    card.append(top, createEl('span', 'module-counts', summaryText));
    card.addEventListener('click', () => {
      state.filters.category = state.filters.category === mod.name ? 'ALL' : mod.name;
      el.categoryFilter.value = state.filters.category;
      renderModuleMatrix(findings);
      renderFindingsList();
    });

    el.moduleGrid.appendChild(card);
  }
}

function populateCategoryDropdown(findings) {
  const categories = [...new Set(findings.map(f => f.category || 'General'))].sort();
  el.categoryFilter.replaceChildren(new Option('All Areas', 'ALL'));
  for (const cat of categories) {
    el.categoryFilter.appendChild(new Option(cat, cat));
  }
  el.categoryFilter.value = state.filters.category;
}

function renderFindingsList() {
  if (!state.currentScan) return;
  const allFindings = state.currentScan.report.findings || [];
  const { severity, category, search, sort } = state.filters;
  const needle = search.trim().toLowerCase();

  const hasActiveFilter = severity !== 'ALL' || category !== 'ALL' || Boolean(needle);
  el.clearFiltersBtn.hidden = !hasActiveFilter;

  const filtered = allFindings.filter(f => {
    if (severity !== 'ALL' && f.severity !== severity) return false;
    if (category !== 'ALL' && (f.category || 'General') !== category) return false;
    if (needle) {
      const hay = `${f.title} ${f.description} ${f.remediation} ${f.category} ${f.severity}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    if (sort === 'impact') {
      return (b.scoreImpact || 0) - (a.scoreImpact || 0) || (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
    }
    if (sort === 'category') {
      return (a.category || '').localeCompare(b.category || '') || (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
    }
    return (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || (b.scoreImpact || 0) - (a.scoreImpact || 0);
  });

  el.findingsCountLabel.textContent = `Showing ${filtered.length} of ${allFindings.length} checks`;
  el.findingsList.replaceChildren();

  if (filtered.length === 0) {
    const empty = createEl('div', 'empty-state');
    empty.append(
      createEl('h2', null, 'No Results Match Your Filter'),
      createEl('p', null, 'Click "Show All Results" or try a different search keyword.')
    );
    el.findingsList.appendChild(empty);
    return;
  }

  filtered.forEach((item, index) => {
    const sevClass = `sev-${(item.severity || 'info').toLowerCase()}`;
    const card = createEl('article', `finding-card ${sevClass}`);

    const startExpanded = ['CRITICAL', 'HIGH', 'MEDIUM'].includes(item.severity);
    const bodyId = `finding-body-${index}`;

    const trigger = createEl('button', 'finding-trigger');
    trigger.type = 'button';
    trigger.setAttribute('aria-expanded', String(startExpanded));
    trigger.setAttribute('aria-controls', bodyId);

    const left = createEl('div', 'finding-head-left');
    left.append(
      createEl('span', `sev-badge ${sevClass}`, item.severity),
      createEl('span', 'finding-title', item.title),
      createEl('span', 'finding-cat-tag', item.category)
    );

    const right = createEl('div', 'finding-head-right');
    if (item.scoreImpact > 0) {
      right.appendChild(createEl('span', 'impact-pill', `-${item.scoreImpact} pts`));
    }
    const chevron = createEl('span', 'finding-chevron', '\u25BE');
    chevron.setAttribute('aria-hidden', 'true');
    right.appendChild(chevron);

    trigger.append(left, right);

    const body = createEl('div', 'finding-body');
    body.id = bodyId;
    body.hidden = !startExpanded;

    body.appendChild(createEl('p', 'finding-desc', item.description));

    if (item.remediation && item.remediation !== 'No specific fix needed.' && item.severity !== 'PASS') {
      const remBox = createEl('div', 'remediation-box');
      const remContent = createEl('div');
      remContent.append(
        createEl('span', 'remediation-label', 'How to Fix This'),
        createEl('p', 'remediation-text', item.remediation)
      );

      const copyBtn = createEl('button', 'btn btn-ghost btn-sm', 'Copy Fix');
      copyBtn.type = 'button';
      copyBtn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(item.remediation);
          showToast('Fix copied to clipboard.');
        } catch {
          showToast('Could not access clipboard.');
        }
      });

      remBox.append(remContent, copyBtn);
      body.appendChild(remBox);
    }

    trigger.addEventListener('click', () => {
      const next = trigger.getAttribute('aria-expanded') !== 'true';
      trigger.setAttribute('aria-expanded', String(next));
      body.hidden = !next;
    });

    card.append(trigger, body);
    el.findingsList.appendChild(card);
  });
}

// =========================================================================
// Export Actions
// =========================================================================
function openStatelessReportForm(report, { autoPrint = false } = {}) {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = '/api/export/html';
  form.target = '_blank';
  form.hidden = true;

  const reportInput = document.createElement('input');
  reportInput.type = 'hidden';
  reportInput.name = 'report';
  reportInput.value = JSON.stringify(report);

  const printInput = document.createElement('input');
  printInput.type = 'hidden';
  printInput.name = 'autoPrint';
  printInput.value = autoPrint ? '1' : '0';

  form.append(reportInput, printInput);
  document.body.appendChild(form);
  form.submit();
  form.remove();
}

async function handleExportPdf() {
  if (!state.currentScan) return;

  // In public/Vercel mode (no local headless browser), open the styled A4 HTML
  // report with auto-print so the user can Save as PDF cleanly in one click.
  if (!state.runtime.features.pdfDirect) {
    showToast('Opening print-ready PDF view...');
    openStatelessReportForm(state.currentScan.report, { autoPrint: true });
    return;
  }

  el.exportPdfBtn.disabled = true;
  el.exportPdfBtn.classList.add('is-loading');
  showToast('Generating PDF...');

  try {
    const res = await api.exportPdf(state.currentScan.report);
    const blob = await res.blob();
    const host = (state.currentScan.report.hostname || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
    const dateStamp = new Date().toISOString().slice(0, 10);
    downloadBlob(blob, `Kalasag-Audit-Report-${host}-${dateStamp}.pdf`);
    showToast('PDF saved.');
  } catch {
    showToast('Opening print-ready PDF view...');
    openStatelessReportForm(state.currentScan.report, { autoPrint: true });
  } finally {
    el.exportPdfBtn.disabled = false;
    el.exportPdfBtn.classList.remove('is-loading');
  }
}

function handlePreviewReport() {
  if (!state.currentScan?.report) return;
  // Stateless POST form opens in a new tab with /report.css under strict CSP —
  // works identically locally and on Vercel without needing server-side storage.
  openStatelessReportForm(state.currentScan.report, { autoPrint: false });
}

async function handleCopyForAi() {
  if (!state.currentScan) return;
  try {
    const res = await api.exportMarkdown(state.currentScan.report);
    const mdText = await res.text();
    await navigator.clipboard.writeText(mdText);
    showToast('AI-ready Markdown copied — paste directly into any AI.');
  } catch (err) {
    showToast(`Copy failed: ${err.message}`);
  }
}

async function handleExportMarkdown() {
  if (!state.currentScan) return;
  try {
    const res = await api.exportMarkdown(state.currentScan.report);
    const blob = await res.blob();
    const host = (state.currentScan.report.hostname || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
    const dateStamp = new Date().toISOString().slice(0, 10);
    downloadBlob(blob, `kalasag-audit-${host}-${dateStamp}.md`);
    showToast('Markdown report downloaded.');
  } catch (err) {
    showToast(`Export failed: ${err.message}`);
  }
}

function handleExportJson() {
  if (!state.currentScan) return;
  const host = (state.currentScan.report.hostname || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStamp = new Date().toISOString().slice(0, 10);
  const blob = new Blob([JSON.stringify(state.currentScan.report, null, 2)], { type: 'application/json' });
  downloadBlob(blob, `kalasag-audit-${host}-${dateStamp}.json`);
  showToast('JSON report exported.');
}

async function handleCopySummary() {
  if (!state.currentScan) return;
  const { report } = state.currentScan;
  const counts = computeCounts(report.findings);
  const lines = [
    `Kalasag Audit — ${report.targetUrl}`,
    `Grade: ${report.grade} (${report.score}/100)${report.gradeCappedBy ? ` [capped by ${report.gradeCappedBy}]` : ''}`,
    `Critical: ${counts.CRITICAL} | High: ${counts.HIGH} | Medium: ${counts.MEDIUM} | Low: ${counts.LOW} | Info: ${counts.INFO} | Passed: ${counts.PASS}`,
    `Scanned: ${report.scanTime}`
  ];
  try {
    await navigator.clipboard.writeText(lines.join('\n'));
    showToast('Summary copied to clipboard.');
  } catch {
    showToast('Could not copy summary.');
  }
}

// =========================================================================
// History Management (Server-backed locally; private browser localStorage in Cloud mode)
// =========================================================================
const browserHistory = {
  readAll() {
    try {
      const raw = localStorage.getItem(BROWSER_HISTORY_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  },
  writeAll(items) {
    try {
      localStorage.setItem(BROWSER_HISTORY_KEY, JSON.stringify(items.slice(0, MAX_BROWSER_HISTORY)));
    } catch {
      // Ignore storage quota errors gracefully
    }
  },
  add(scan) {
    const entry = {
      id: scan.id || String(Date.now()),
      savedAt: new Date().toISOString(),
      elapsedMs: scan.elapsedMs || 0,
      summary: scan.summary || computeCounts(scan.report?.findings),
      report: scan.report
    };
    const next = [entry, ...this.readAll().filter(item => item.id !== entry.id)];
    this.writeAll(next);
    return entry;
  },
  listSummaries() {
    return this.readAll().map(({ id, elapsedMs, savedAt, summary, report }) => ({
      id,
      elapsedMs,
      savedAt,
      targetUrl: report?.targetUrl || '',
      hostname: report?.hostname || '',
      isInternalHost: Boolean(report?.isInternalHost),
      score: report?.score ?? 0,
      grade: report?.grade || 'N/A',
      gradeCappedBy: report?.gradeCappedBy || null,
      counts: summary || computeCounts(report?.findings)
    }));
  },
  getById(id) {
    return this.readAll().find(entry => entry.id === id) || null;
  },
  removeById(id) {
    this.writeAll(this.readAll().filter(entry => entry.id !== id));
  },
  clear() {
    this.writeAll([]);
  }
};

async function refreshHistory() {
  if (!state.runtime.features.serverHistory) {
    state.historyItems = browserHistory.listSummaries();
    el.historyBadge.textContent = String(state.historyItems.length);
    el.clearHistoryBtn.disabled = state.historyItems.length === 0;
    renderHistoryTable();
    return;
  }
  try {
    const res = await api.listHistory();
    state.historyItems = res.data?.items || [];
    el.historyBadge.textContent = String(state.historyItems.length);
    el.clearHistoryBtn.disabled = state.historyItems.length === 0;
    renderHistoryTable();
  } catch {
    // Non-fatal on startup
  }
}

function renderHistoryTable() {
  const items = state.historyItems;
  el.historyEmpty.hidden = items.length > 0;
  el.historyTableWrap.hidden = items.length === 0;
  el.historyTbody.replaceChildren();

  for (const item of items) {
    const tr = document.createElement('tr');

    const urlCell = document.createElement('td');
    urlCell.appendChild(createEl('span', 'mono', item.targetUrl));

    const gradeCell = document.createElement('td');
    gradeCell.appendChild(createEl('span', `grade-pill ${getGradeClass(item.grade)}`, item.grade));

    const scoreCell = createEl('td', 'mono', `${item.score}/100`);

    const countsCell = document.createElement('td');
    const wrap = createEl('div', 'mini-counts');
    const c = item.counts || {};
    if (c.CRITICAL) wrap.appendChild(createEl('span', 'sev-badge sev-critical', `${c.CRITICAL} Crit`));
    if (c.HIGH) wrap.appendChild(createEl('span', 'sev-badge sev-high', `${c.HIGH} High`));
    if (c.MEDIUM) wrap.appendChild(createEl('span', 'sev-badge sev-medium', `${c.MEDIUM} Med`));
    if (c.LOW) wrap.appendChild(createEl('span', 'sev-badge sev-low', `${c.LOW} Low`));
    if (!c.CRITICAL && !c.HIGH && !c.MEDIUM && !c.LOW) {
      wrap.appendChild(createEl('span', 'sev-badge sev-pass', `${c.PASS || 0} Passed`));
    }
    countsCell.appendChild(wrap);

    const timeCell = createEl('td', null, formatDateTime(item.savedAt));

    const actionsCell = document.createElement('td');
    const actionWrap = createEl('div', 'row-actions');

    const openBtn = createEl('button', 'btn btn-secondary btn-sm', 'Open Report');
    openBtn.type = 'button';
    openBtn.addEventListener('click', () => handleOpenHistoryItem(item.id));

    const rescanBtn = createEl('button', 'btn btn-ghost btn-sm', 'Re-Scan');
    rescanBtn.type = 'button';
    rescanBtn.addEventListener('click', () => {
      el.targetUrlInput.value = item.targetUrl;
      setActiveView('scanner');
      handleAuditSubmit();
    });

    const delBtn = createEl('button', 'btn btn-danger btn-sm', 'Delete');
    delBtn.type = 'button';
    delBtn.setAttribute('aria-label', `Delete scan record for ${item.targetUrl}`);
    delBtn.addEventListener('click', () => handleDeleteHistoryItem(item.id));

    actionWrap.append(openBtn, rescanBtn, delBtn);
    actionsCell.appendChild(actionWrap);

    tr.append(urlCell, gradeCell, scoreCell, countsCell, timeCell, actionsCell);
    el.historyTbody.appendChild(tr);
  }
}

async function handleOpenHistoryItem(id) {
  if (!state.runtime.features.serverHistory) {
    const entry = browserHistory.getById(id);
    if (!entry) {
      showToast('Saved report not found.');
      return;
    }
    state.currentScan = entry;
    el.targetUrlInput.value = entry.report.targetUrl;
    resetFilters();
    setActiveView('scanner');
    renderReportDashboard(state.currentScan);
    showToast(`Loaded saved report for ${entry.report.hostname}.`);
    return;
  }

  try {
    const res = await api.getHistoryItem(id);
    state.currentScan = res.data;
    el.targetUrlInput.value = res.data.report.targetUrl;
    resetFilters();
    setActiveView('scanner');
    renderReportDashboard(state.currentScan);
    showToast(`Loaded saved report for ${res.data.report.hostname}.`);
  } catch (err) {
    showToast(`Could not load report: ${err.message}`);
  }
}

async function handleDeleteHistoryItem(id) {
  if (!state.runtime.features.serverHistory) {
    browserHistory.removeById(id);
    await refreshHistory();
    showToast('Scan record deleted.');
    return;
  }
  try {
    await api.deleteHistoryItem(id);
    await refreshHistory();
    showToast('Scan record deleted.');
  } catch (err) {
    showToast(`Delete failed: ${err.message}`);
  }
}

async function handleConfirmClearHistory() {
  el.confirmDialog.close();
  if (!state.runtime.features.serverHistory) {
    browserHistory.clear();
    await refreshHistory();
    showToast('Browser scan history cleared.');
    return;
  }
  try {
    await api.clearHistory();
    await refreshHistory();
    showToast('All local scan history cleared.');
  } catch (err) {
    showToast(`Failed to clear history: ${err.message}`);
  }
}

// =========================================================================
// Health Ping, Runtime Mode Adaptation & Event Binding
// =========================================================================
function applyRuntimeMode() {
  const isPublic = state.runtime.mode === 'public';
  if (el.presetSelf) {
    el.presetSelf.setAttribute('data-preset', window.location.origin);
  }

  if (isPublic) {
    if (el.engineStatusLabel) el.engineStatusLabel.textContent = 'Online';
    if (el.heroEyebrowText) el.heroEyebrowText.textContent = 'Live Cloud Scanner \u2022 14 Security Checks';
    if (el.heroSubtitleText) {
      el.heroSubtitleText.textContent =
        'Paste any public website or API URL below. Kalasag Audit crawls same-origin pages and inspects SSL certificates, security headers, cookies, leaked files (.env, .git), forms, outdated scripts, and DNS protection, then gives you a clear grade and exact fixes.';
    }
    if (el.statChecksVal) el.statChecksVal.textContent = '14';
    if (el.statModeVal) el.statModeVal.textContent = 'Private';
    if (el.statModeLabel) el.statModeLabel.textContent = 'Browser-Only';
    if (el.howStep1Desc) el.howStep1Desc.textContent = 'Works with live public websites (https://) and APIs — automatically crawls up to 100 same-origin pages.';
    if (el.howStep2Title) el.howStep2Title.textContent = 'Smart 14-Point Inspection';
    if (el.targetUrlInput) el.targetUrlInput.placeholder = 'https://example.com';
    if (el.otpDrawer) el.otpDrawer.hidden = true;
    if (el.otpEnabled) el.otpEnabled.checked = false;
    if (el.presetAlt) {
      el.presetAlt.setAttribute('data-preset', 'https://developer.mozilla.org');
      el.presetAlt.textContent = 'developer.mozilla.org';
    }
    if (el.historyEyebrowText) el.historyEyebrowText.textContent = 'Saved Privately in Your Browser';
    if (el.historyEmptyText) {
      el.historyEmptyText.textContent = 'Run your first website scan from the Scanner tab. Your last 25 reports are saved privately in your browser.';
    }
  } else {
    if (el.engineStatusLabel) el.engineStatusLabel.textContent = 'Online';
    if (el.otpDrawer) el.otpDrawer.hidden = false;
  }
}

async function checkEngineHealth() {
  try {
    const res = await api.health();
    el.engineStatus.classList.remove('is-offline');
    if (res?.data?.mode) {
      state.runtime.mode = res.data.mode;
    }
    if (res?.data?.features) {
      state.runtime.features = {
        ...state.runtime.features,
        ...res.data.features
      };
    }
    applyRuntimeMode();
  } catch {
    el.engineStatus.classList.add('is-offline');
    if (el.engineStatusLabel) el.engineStatusLabel.textContent = 'Offline';
  }
}

function bindEvents() {
  el.themeToggle.addEventListener('click', handleToggleTheme);

  el.navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      setActiveView(link.getAttribute('data-nav'));
    });
  });

  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.replace(/^#/, '') || 'scanner';
    setActiveView(hash, false);
  });

  el.auditForm.addEventListener('submit', handleAuditSubmit);
  el.retryAuditBtn.addEventListener('click', () => handleAuditSubmit());
  el.cancelAuditBtn.addEventListener('click', handleCancelAudit);

  el.targetUrlInput.addEventListener('input', () => {
    if (!el.urlError.hidden) setFieldError('');
  });

  el.presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      el.targetUrlInput.value = chip.getAttribute('data-preset');
      setFieldError('');
      el.targetUrlInput.focus();
    });
  });

  // Guided OTP Drawer events
  el.otpToggleBtn.addEventListener('click', () => {
    const next = el.otpToggleBtn.getAttribute('aria-expanded') !== 'true';
    el.otpToggleBtn.setAttribute('aria-expanded', String(next));
    el.otpPanel.hidden = !next;
  });

  el.otpEnabled.addEventListener('change', () => {
    el.otpFields.hidden = !el.otpEnabled.checked;
    syncOtpStatusPill();
    updateOtpPreview();
  });

  el.otpFieldBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const val = btn.getAttribute('data-otp-field');
      state.otpUi.fieldKey = val;
      el.otpFieldBtns.forEach(b => {
        const active = b === btn;
        b.classList.toggle('is-active', active);
        b.setAttribute('aria-pressed', String(active));
      });
      if (val === 'custom') {
        el.otpExtraToggle.setAttribute('aria-expanded', 'true');
        el.otpExtraPanel.hidden = false;
      } else {
        el.otpBody.value = JSON.stringify({ [val]: '{{RECIPIENT}}' });
      }
      updateOtpPreview();
    });
  });

  el.otpMaxBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      state.otpUi.maxRequests = Number(btn.getAttribute('data-otp-max')) || 4;
      el.otpMaxBtns.forEach(b => {
        const active = b === btn;
        b.classList.toggle('is-active', active);
        b.setAttribute('aria-pressed', String(active));
      });
      updateOtpPreview();
    });
  });

  el.otpExtraToggle.addEventListener('click', () => {
    const next = el.otpExtraToggle.getAttribute('aria-expanded') !== 'true';
    el.otpExtraToggle.setAttribute('aria-expanded', String(next));
    el.otpExtraPanel.hidden = !next;
  });

  el.otpRecipient.addEventListener('input', updateOtpPreview);
  el.otpMethod.addEventListener('change', updateOtpPreview);
  el.otpBody.addEventListener('input', updateOtpPreview);

  // Filter controls
  el.findingSearch.addEventListener('input', () => {
    state.filters.search = el.findingSearch.value;
    renderFindingsList();
  });

  if (el.routesSearch) {
    el.routesSearch.addEventListener('input', () => {
      if (state.currentScan) {
        renderDiscoveredRoutes(state.currentScan.report, el.routesSearch.value);
      }
    });
  }

  el.categoryFilter.addEventListener('change', () => {
    state.filters.category = el.categoryFilter.value;
    if (state.currentScan) renderModuleMatrix(state.currentScan.report.findings);
    renderFindingsList();
  });

  el.sortFilter.addEventListener('change', () => {
    state.filters.sort = el.sortFilter.value;
    renderFindingsList();
  });

  el.clearFiltersBtn.addEventListener('click', () => {
    resetFilters();
    if (state.currentScan) {
      renderSeverityStrip(computeCounts(state.currentScan.report.findings));
      renderModuleMatrix(state.currentScan.report.findings);
      renderFindingsList();
    }
  });

  // Export & Utility
  el.exportPdfBtn.addEventListener('click', handleExportPdf);
  el.previewReportBtn.addEventListener('click', handlePreviewReport);
  el.copyAiBtn.addEventListener('click', handleCopyForAi);
  el.exportMdBtn.addEventListener('click', handleExportMarkdown);
  el.exportJsonBtn.addEventListener('click', handleExportJson);
  el.rescanCurrentBtn.addEventListener('click', () => {
    if (state.currentScan) {
      el.targetUrlInput.value = state.currentScan.report.targetUrl;
      handleAuditSubmit();
    }
  });

  // History controls & dialog
  el.refreshHistoryBtn.addEventListener('click', () => {
    refreshHistory();
    showToast('History refreshed.');
  });

  el.clearHistoryBtn.addEventListener('click', () => {
    el.confirmDialog.showModal();
  });

  el.dialogCancelBtn.addEventListener('click', () => el.confirmDialog.close());
  el.dialogConfirmBtn.addEventListener('click', handleConfirmClearHistory);
}

// Boot
initTheme();
bindEvents();
syncOtpStatusPill();
updateOtpPreview();
const initialHash = window.location.hash.replace(/^#/, '') || 'scanner';
setActiveView(initialHash, false);
checkEngineHealth().finally(() => refreshHistory());
