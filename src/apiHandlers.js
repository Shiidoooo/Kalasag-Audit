import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { SecurityAuditor } from './auditor.js';
import { Reporter } from './reporter.js';
import { validateOtpConfig } from './otpTester.js';
import { buildEnterpriseReportHtml, renderEnterprisePdf } from './pdfReporter.js';
import {
  InMemoryRateLimiter,
  extractClientIp,
  isAllowedSameOrigin,
  isPublicDeployment,
  validateTargetUrl
} from './securityGuard.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const DEFAULT_PUBLIC_DIR = path.resolve(__dirname, '..', 'public');
export const DEFAULT_HISTORY_FILE = path.resolve(__dirname, '..', '.kalasag-history.json');

const MAX_AUDIT_BODY_BYTES = 64 * 1024;   // 64 KB for /api/audit
const MAX_EXPORT_BODY_BYTES = 512 * 1024; // 512 KB for /api/export/* (full scan reports)
const MAX_HISTORY_ITEMS = 30;
const LOCAL_AUDIT_TIMEOUT_MS = 60_000;
const PUBLIC_AUDIT_TIMEOUT_MS = 48_000;

export const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin'
};

export function setSecurityHeaders(res, req = null, { publicMode = false } = {}) {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(key, value);
  }
  const forwardedProto = String(req?.headers?.['x-forwarded-proto'] || '').toLowerCase();
  if (publicMode || forwardedProto === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

export function sendJson(res, statusCode, payload, req = null, opts = {}) {
  setSecurityHeaders(res, req, opts);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = statusCode;
  res.end(JSON.stringify(payload));
}

export function sendSuccess(res, statusCode, data, message, req = null, opts = {}) {
  sendJson(res, statusCode, { status: 'success', data, message }, req, opts);
}

export function sendError(res, statusCode, code, message, details = [], requestId = crypto.randomUUID(), req = null, opts = {}) {
  sendJson(
    res,
    statusCode,
    {
      status: 'error',
      data: null,
      message,
      error: { code, details },
      requestId
    },
    req,
    opts
  );
}

export async function readRequestBody(req, { maxBytes = MAX_AUDIT_BODY_BYTES } = {}) {
  // Vercel Functions may pre-parse req.body as an object or string.
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      return normalizeParsedFormBody(req.body);
    }
    const rawStr = Buffer.isBuffer(req.body) ? req.body.toString('utf-8') : String(req.body);
    if (Buffer.byteLength(rawStr, 'utf-8') > maxBytes) {
      const err = new Error(`Request payload exceeds maximum allowed size (${Math.round(maxBytes / 1024)} KB).`);
      err.statusCode = 413;
      err.code = 'PAYLOAD_TOO_LARGE';
      throw err;
    }
    return parseRawBody(rawStr, req.headers?.['content-type'] || '');
  }

  const chunks = [];
  let totalBytes = 0;

  for await (const chunk of req) {
    totalBytes += chunk.length;
    if (totalBytes > maxBytes) {
      const err = new Error(`Request payload exceeds maximum allowed size (${Math.round(maxBytes / 1024)} KB).`);
      err.statusCode = 413;
      err.code = 'PAYLOAD_TOO_LARGE';
      throw err;
    }
    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString('utf-8').trim();
  return parseRawBody(raw, req.headers?.['content-type'] || '');
}

function normalizeParsedFormBody(obj) {
  if (!obj || typeof obj !== 'object') return {};
  const out = { ...obj };
  if (typeof out.report === 'string') {
    try {
      out.report = JSON.parse(out.report);
    } catch {
      const err = new Error('Form field "report" contains malformed JSON.');
      err.statusCode = 400;
      err.code = 'MALFORMED_JSON';
      throw err;
    }
  }
  if (out.autoPrint !== undefined) {
    out.autoPrint = out.autoPrint === true || out.autoPrint === '1' || out.autoPrint === 'true';
  }
  return out;
}

function parseRawBody(raw, contentType) {
  if (!raw) return {};
  const lowerType = String(contentType).toLowerCase();

  if (lowerType.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(raw);
    const reportStr = params.get('report');
    const autoPrint = params.get('autoPrint') === '1';
    if (!reportStr) return {};
    try {
      return { report: JSON.parse(reportStr), autoPrint };
    } catch {
      const err = new Error('Form field "report" contains malformed JSON.');
      err.statusCode = 400;
      err.code = 'MALFORMED_JSON';
      throw err;
    }
  }

  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      const err = new Error('Request body must be a JSON object.');
      err.statusCode = 400;
      err.code = 'INVALID_JSON_OBJECT';
      throw err;
    }
    return parsed;
  } catch (err) {
    if (err.statusCode) throw err;
    const parseErr = new Error('Request body contains malformed JSON.');
    parseErr.statusCode = 400;
    parseErr.code = 'MALFORMED_JSON';
    throw parseErr;
  }
}

export function summarizeReport(report) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, PASS: 0 };
  for (const f of report.findings || []) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }
  return counts;
}

export class LocalHistoryStore {
  constructor(filePath, logger = console) {
    this.filePath = filePath;
    this.logger = logger;
    this.cache = null;
  }

  async load() {
    if (this.cache !== null) return this.cache;
    try {
      const raw = await fs.readFile(this.filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      this.cache = Array.isArray(parsed) ? parsed.slice(0, MAX_HISTORY_ITEMS) : [];
    } catch (err) {
      if (err && err.code !== 'ENOENT') {
        this.logger.warn(`[Kalasag Audit] Could not read history file: ${err.message}`);
      }
      this.cache = [];
    }
    return this.cache;
  }

  async save(items) {
    this.cache = items.slice(0, MAX_HISTORY_ITEMS);
    try {
      const tmp = `${this.filePath}.tmp`;
      await fs.writeFile(tmp, JSON.stringify(this.cache, null, 2), 'utf-8');
      await fs.rename(tmp, this.filePath);
    } catch (err) {
      this.logger.warn(`[Kalasag Audit] Could not persist history to disk (${err.code || err.message}); keeping in-memory cache only.`);
    }
  }

  async listSummaries() {
    const items = await this.load();
    return items.map(({ id, elapsedMs, savedAt, summary, report }) => ({
      id,
      elapsedMs,
      savedAt,
      targetUrl: report.targetUrl,
      hostname: report.hostname,
      isInternalHost: report.isInternalHost,
      score: report.score,
      grade: report.grade,
      gradeCappedBy: report.gradeCappedBy || null,
      counts: summary
    }));
  }

  async getById(id) {
    const items = await this.load();
    return items.find(entry => entry.id === id) || null;
  }

  async add(report, elapsedMs) {
    const items = await this.load();
    const entry = {
      id: crypto.randomUUID(),
      savedAt: new Date().toISOString(),
      elapsedMs,
      summary: summarizeReport(report),
      report
    };
    await this.save([entry, ...items]);
    return entry;
  }

  async removeById(id) {
    const items = await this.load();
    const next = items.filter(entry => entry.id !== id);
    if (next.length === items.length) return false;
    await this.save(next);
    return true;
  }

  async clear() {
    await this.save([]);
  }
}

export function createApiContext(options = {}) {
  const publicMode = options.publicMode !== undefined ? Boolean(options.publicMode) : isPublicDeployment();
  const startedAt = Date.now();
  const historyStore = publicMode
    ? null
    : new LocalHistoryStore(options.historyFile || DEFAULT_HISTORY_FILE);
  const rateLimiter = options.rateLimiter || new InMemoryRateLimiter({
    maxRequests: options.rateLimitMax ?? (publicMode ? 8 : 60),
    windowMs: options.rateLimitWindowMs ?? 60_000
  });

  return {
    publicMode,
    startedAt,
    historyStore,
    rateLimiter,
    dnsLookup: options.dnsLookup,
    auditTimeoutMs: options.auditTimeoutMs ?? (publicMode ? PUBLIC_AUDIT_TIMEOUT_MS : LOCAL_AUDIT_TIMEOUT_MS)
  };
}

// =========================================================================
// Modular Endpoint Handlers (shared by Local HTTP Server & Vercel Functions)
// =========================================================================

export async function handleHealth(req, res, ctx) {
  return sendSuccess(
    res,
    200,
    {
      app: 'Kalasag Audit',
      version: '2.0.0',
      mode: ctx.publicMode ? 'public' : 'local',
      features: {
        pdfDirect: !ctx.publicMode,
        serverHistory: !ctx.publicMode,
        otpTest: !ctx.publicMode
      },
      uptimeSec: Math.floor((Date.now() - ctx.startedAt) / 1000)
    },
    'Kalasag Audit service is healthy.',
    req,
    { publicMode: ctx.publicMode }
  );
}

export async function handleAudit(req, res, ctx, requestId = crypto.randomUUID()) {
  if (!isAllowedSameOrigin(req, { publicMode: ctx.publicMode })) {
    return sendError(
      res,
      403,
      'CROSS_ORIGIN_FORBIDDEN',
      'Cross-origin audit requests are not permitted.',
      [],
      requestId,
      req,
      { publicMode: ctx.publicMode }
    );
  }

  const clientIp = extractClientIp(req);
  const limit = ctx.rateLimiter.check(clientIp);
  if (!limit.allowed) {
    res.setHeader('Retry-After', String(limit.retryAfterSec));
    return sendError(
      res,
      429,
      'RATE_LIMIT_EXCEEDED',
      `Too many scan requests. Please wait ${limit.retryAfterSec} seconds before scanning again.`,
      [],
      requestId,
      req,
      { publicMode: ctx.publicMode }
    );
  }

  const body = await readRequestBody(req);
  const targetCheck = await validateTargetUrl(body.url, {
    publicMode: ctx.publicMode,
    dnsLookup: ctx.dnsLookup
  });

  if (!targetCheck.ok) {
    return sendError(
      res,
      422,
      targetCheck.code || 'VALIDATION_ERROR',
      targetCheck.error,
      [{ field: 'url', message: targetCheck.error }],
      requestId,
      req,
      { publicMode: ctx.publicMode }
    );
  }

  // Active OTP probe is strictly local-only and disabled on public deployments (FS-02).
  let otpConfig = null;
  if (body.otpTest) {
    if (ctx.publicMode) {
      return sendError(
        res,
        403,
        'OTP_DISABLED_IN_PUBLIC_MODE',
        'The active OTP rate-limit probe is disabled on public deployments. Run Kalasag Audit locally to test your own OTP endpoints.',
        [],
        requestId,
        req,
        { publicMode: ctx.publicMode }
      );
    }
    if (body.confirmOtp !== true) {
      return sendError(
        res,
        422,
        'OTP_CONFIRMATION_REQUIRED',
        'You must explicitly confirm authorization before running the active OTP rate-limit probe.',
        [{ field: 'confirmOtp', message: 'Explicit confirmation is required.' }],
        requestId,
        req,
        { publicMode: ctx.publicMode }
      );
    }
    const otpCheck = validateOtpConfig(body.otpTest);
    if (!otpCheck.ok) {
      return sendError(
        res,
        422,
        'INVALID_OTP_CONFIG',
        otpCheck.error,
        [{ field: 'otpTest', message: otpCheck.error }],
        requestId,
        req,
        { publicMode: ctx.publicMode }
      );
    }
    otpConfig = body.otpTest;
  }

  // Clamp optional crawl page limit safely (up to 100 pages in both local and cloud mode).
  const maxAllowedPages = 100;
  const defaultPages = 50;
  const requestedPages = Number(body.maxPages);
  const maxPages = Number.isFinite(requestedPages) && requestedPages >= 1
    ? Math.min(maxAllowedPages, Math.floor(requestedPages))
    : defaultPages;

  const logs = [];
  const auditor = new SecurityAuditor(targetCheck.target, {
    otpTest: otpConfig,
    publicMode: ctx.publicMode,
    maxPages,
    // Active DB/admin port probe + app-layer injection tests (SQLi/XSS) run
    // automatically on every local scan; the auditor keeps them disabled in
    // public mode so the hosted scanner cannot attack third parties.
    probeServices: !ctx.publicMode,
    activeInjection: !ctx.publicMode,
    dnsLookup: ctx.dnsLookup,
    log: (line) => logs.push(line)
  });

  const started = Date.now();
  let timeoutId;
  const report = await Promise.race([
    auditor.runAllChecks(),
    new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        const err = new Error('The audit timed out. The target host may be unreachable or very slow.');
        err.statusCode = 504;
        err.code = 'AUDIT_TIMEOUT';
        reject(err);
      }, ctx.auditTimeoutMs);
    })
  ]).finally(() => clearTimeout(timeoutId));

  const elapsedMs = Date.now() - started;
  const summary = summarizeReport(report);
  let id = crypto.randomUUID();

  if (ctx.historyStore) {
    const saved = await ctx.historyStore.add(report, elapsedMs);
    id = saved.id;
  }

  return sendSuccess(
    res,
    200,
    { id, elapsedMs, summary, logs, report },
    `Completed security audit for ${report.hostname}.`,
    req,
    { publicMode: ctx.publicMode }
  );
}

export async function handleExportMarkdown(req, res, ctx, requestId = crypto.randomUUID()) {
  const body = await readRequestBody(req, { maxBytes: MAX_EXPORT_BODY_BYTES });
  const report = body.report;
  if (!report || typeof report !== 'object' || !Array.isArray(report.findings)) {
    return sendError(res, 422, 'INVALID_REPORT', 'A valid audit report payload is required to export Markdown.', [], requestId, req, { publicMode: ctx.publicMode });
  }

  const markdown = Reporter.buildMarkdown(report);
  const cleanHost = String(report.hostname || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStamp = new Date().toISOString().slice(0, 10);

  setSecurityHeaders(res, req, { publicMode: ctx.publicMode });
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="kalasag-audit-${cleanHost}-${dateStamp}.md"`);
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = 200;
  res.end(markdown);
}

export async function handleExportPdf(req, res, ctx, requestId = crypto.randomUUID()) {
  if (ctx.publicMode) {
    return sendError(
      res,
      503,
      'PDF_ENGINE_UNAVAILABLE',
      'Direct server-side PDF rendering is available in local mode only. Use the printable report preview to Save as PDF.',
      [],
      requestId,
      req,
      { publicMode: ctx.publicMode }
    );
  }

  const body = await readRequestBody(req, { maxBytes: MAX_EXPORT_BODY_BYTES });
  const report = body.report;
  if (!report || typeof report !== 'object' || !Array.isArray(report.findings)) {
    return sendError(res, 422, 'INVALID_REPORT', 'A valid audit report payload is required to export PDF.', [], requestId, req, { publicMode: ctx.publicMode });
  }

  const pdfBuffer = await renderEnterprisePdf(report);
  const cleanHost = String(report.hostname || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStamp = new Date().toISOString().slice(0, 10);

  setSecurityHeaders(res, req, { publicMode: ctx.publicMode });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="Kalasag-Audit-Report-${cleanHost}-${dateStamp}.pdf"`);
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = 200;
  res.end(pdfBuffer);
}

export async function handleExportHtml(req, res, ctx, requestId = crypto.randomUUID()) {
  const body = await readRequestBody(req, { maxBytes: MAX_EXPORT_BODY_BYTES });
  const report = body.report;
  if (!report || typeof report !== 'object' || !Array.isArray(report.findings)) {
    return sendError(res, 422, 'INVALID_REPORT', 'A valid audit report payload is required.', [], requestId, req, { publicMode: ctx.publicMode });
  }

  const html = await buildEnterpriseReportHtml(report, {
    inlineCss: false,
    autoPrint: Boolean(body.autoPrint)
  });

  setSecurityHeaders(res, req, { publicMode: ctx.publicMode });
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = 200;
  res.end(html);
}

export async function handlePreviewById(req, res, ctx, id, requestId = crypto.randomUUID()) {
  if (!ctx.historyStore) {
    return sendError(res, 403, 'HISTORY_LOCAL_ONLY', 'Server-side report storage is disabled in public mode. Use POST /api/export/html instead.', [], requestId, req, { publicMode: ctx.publicMode });
  }
  if (!/^[a-zA-Z0-9-]{8,64}$/.test(id)) {
    return sendError(res, 400, 'INVALID_ID', 'Invalid report identifier.', [], requestId, req, { publicMode: ctx.publicMode });
  }
  const entry = await ctx.historyStore.getById(id);
  if (!entry) {
    return sendError(res, 404, 'NOT_FOUND', 'Saved scan report not found.', [], requestId, req, { publicMode: ctx.publicMode });
  }

  const html = await buildEnterpriseReportHtml(entry.report, { inlineCss: false });
  setSecurityHeaders(res, req, { publicMode: ctx.publicMode });
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.statusCode = 200;
  res.end(html);
}

export async function handleHistoryCollection(req, res, ctx, method, requestId = crypto.randomUUID()) {
  if (!ctx.historyStore) {
    return sendError(res, 403, 'HISTORY_LOCAL_ONLY', 'Server-side history is disabled in public mode; scan history is stored privately in your browser.', [], requestId, req, { publicMode: ctx.publicMode });
  }
  if (method === 'GET') {
    const items = await ctx.historyStore.listSummaries();
    return sendSuccess(res, 200, { items }, `Loaded ${items.length} audit history record(s).`, req, { publicMode: ctx.publicMode });
  }
  if (method === 'DELETE') {
    await ctx.historyStore.clear();
    return sendSuccess(res, 200, { cleared: true }, 'Audit history cleared.', req, { publicMode: ctx.publicMode });
  }
  return sendError(res, 405, 'METHOD_NOT_ALLOWED', `Method ${method} not allowed on /api/history.`, [], requestId, req, { publicMode: ctx.publicMode });
}

export async function handleHistoryItem(req, res, ctx, method, id, requestId = crypto.randomUUID()) {
  if (!ctx.historyStore) {
    return sendError(res, 403, 'HISTORY_LOCAL_ONLY', 'Server-side history is disabled in public mode.', [], requestId, req, { publicMode: ctx.publicMode });
  }
  if (!/^[a-zA-Z0-9-]{8,64}$/.test(id)) {
    return sendError(res, 400, 'INVALID_ID', 'Invalid history record identifier.', [], requestId, req, { publicMode: ctx.publicMode });
  }
  if (method === 'GET') {
    const entry = await ctx.historyStore.getById(id);
    if (!entry) return sendError(res, 404, 'NOT_FOUND', 'Audit record not found.', [], requestId, req, { publicMode: ctx.publicMode });
    return sendSuccess(res, 200, entry, 'Audit record loaded.', req, { publicMode: ctx.publicMode });
  }
  if (method === 'DELETE') {
    const removed = await ctx.historyStore.removeById(id);
    if (!removed) return sendError(res, 404, 'NOT_FOUND', 'Audit record not found.', [], requestId, req, { publicMode: ctx.publicMode });
    return sendSuccess(res, 200, { id, deleted: true }, 'Audit record deleted.', req, { publicMode: ctx.publicMode });
  }
  return sendError(res, 405, 'METHOD_NOT_ALLOWED', `Method ${method} not allowed.`, [], requestId, req, { publicMode: ctx.publicMode });
}

/**
 * Wraps an async handler for Vercel Serverless Functions with centralized safe error handling.
 */
export function wrapVercelHandler(allowedMethod, handlerFn) {
  const sharedCtx = createApiContext();
  return async function vercelHandler(req, res) {
    const requestId = crypto.randomUUID();
    const method = (req.method || 'GET').toUpperCase();

    if (method !== allowedMethod) {
      res.setHeader('Allow', allowedMethod);
      return sendError(res, 405, 'METHOD_NOT_ALLOWED', `Method ${method} not allowed.`, [], requestId, req, { publicMode: sharedCtx.publicMode });
    }

    try {
      await handlerFn(req, res, sharedCtx, requestId);
    } catch (err) {
      const status = err.statusCode || 500;
      const code = err.code || 'INTERNAL_ERROR';
      const isSafeOperational = status < 500 || code === 'AUDIT_TIMEOUT' || code === 'PDF_ENGINE_UNAVAILABLE';
      const safeMessage = isSafeOperational ? err.message : 'An unexpected internal error occurred while processing the request.';
      if (status >= 500) {
        console.error(`[Kalasag Audit][${requestId}]`, err.message);
      }
      sendError(res, status, code, safeMessage, [], requestId, req, { publicMode: sharedCtx.publicMode });
    }
  };
}
