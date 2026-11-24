import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  DEFAULT_PUBLIC_DIR,
  createApiContext,
  handleAudit,
  handleExportHtml,
  handleExportMarkdown,
  handleExportPdf,
  handleHealth,
  handleHistoryCollection,
  handleHistoryItem,
  handlePreviewById,
  sendError,
  setSecurityHeaders
} from './apiHandlers.js';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon'
};

async function serveStaticFile(req, res, publicDir, requestPathname, publicMode) {
  // Map root "/" to index.html; reject dotfiles and traversal segments.
  let decoded;
  try {
    decoded = decodeURIComponent(requestPathname);
  } catch {
    return sendError(res, 400, 'BAD_PATH', 'Malformed URL path.', [], undefined, req, { publicMode });
  }

  const relativePath = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  if (!relativePath || relativePath.split('/').some(seg => seg === '..' || seg.startsWith('.'))) {
    return sendError(res, 404, 'NOT_FOUND', 'Resource not found.', [], undefined, req, { publicMode });
  }

  const resolvedRoot = path.resolve(publicDir);
  const fullPath = path.resolve(resolvedRoot, relativePath);
  if (fullPath !== resolvedRoot && !fullPath.startsWith(resolvedRoot + path.sep)) {
    return sendError(res, 404, 'NOT_FOUND', 'Resource not found.', [], undefined, req, { publicMode });
  }

  try {
    const stat = await fs.stat(fullPath);
    if (!stat.isFile()) {
      return sendError(res, 404, 'NOT_FOUND', 'Resource not found.', [], undefined, req, { publicMode });
    }
    const ext = path.extname(fullPath).toLowerCase();
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    const content = await fs.readFile(fullPath);

    setSecurityHeaders(res, req, { publicMode });
    res.setHeader('Content-Type', mime);
    res.setHeader(
      'Cache-Control',
      ['.jpg', '.jpeg', '.png', '.webp', '.svg', '.ico'].includes(ext)
        ? 'public, max-age=3600'
        : 'no-cache'
    );
    res.statusCode = 200;
    res.end(content);
  } catch {
    sendError(res, 404, 'NOT_FOUND', 'Resource not found.', [], undefined, req, { publicMode });
  }
}

export function createAppServer(options = {}) {
  const publicDir = options.publicDir || DEFAULT_PUBLIC_DIR;
  const ctx = createApiContext(options);

  const server = http.createServer(async (req, res) => {
    const requestId = crypto.randomUUID();
    const method = (req.method || 'GET').toUpperCase();

    // Explicitly block TRACE/TRACK and unsafe methods on non-API routes.
    if (method === 'TRACE' || method === 'TRACK') {
      setSecurityHeaders(res, req, { publicMode: ctx.publicMode });
      res.statusCode = 405;
      res.end('Method Not Allowed');
      return;
    }

    let urlObj;
    try {
      urlObj = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
    } catch {
      return sendError(res, 400, 'INVALID_REQUEST_URL', 'Malformed request URL.', [], requestId, req, { publicMode: ctx.publicMode });
    }

    const pathname = urlObj.pathname;

    try {
      if (pathname === '/api/health' && method === 'GET') {
        return await handleHealth(req, res, ctx);
      }
      if (pathname === '/api/audit' && method === 'POST') {
        return await handleAudit(req, res, ctx, requestId);
      }
      if (pathname === '/api/export/markdown' && method === 'POST') {
        return await handleExportMarkdown(req, res, ctx, requestId);
      }
      if (pathname === '/api/export/pdf' && method === 'POST') {
        return await handleExportPdf(req, res, ctx, requestId);
      }
      if (pathname === '/api/export/html' && method === 'POST') {
        return await handleExportHtml(req, res, ctx, requestId);
      }
      if (pathname.startsWith('/api/reports/') && pathname.endsWith('/preview') && method === 'GET') {
        const id = pathname.slice('/api/reports/'.length, -'/preview'.length);
        return await handlePreviewById(req, res, ctx, id, requestId);
      }
      if (pathname === '/api/history') {
        return await handleHistoryCollection(req, res, ctx, method, requestId);
      }
      if (pathname.startsWith('/api/history/')) {
        const id = pathname.slice('/api/history/'.length);
        return await handleHistoryItem(req, res, ctx, method, id, requestId);
      }
      if (pathname.startsWith('/api/')) {
        return sendError(res, 404, 'API_NOT_FOUND', 'API endpoint not found.', [], requestId, req, { publicMode: ctx.publicMode });
      }

      // Static UI assets (GET / HEAD only)
      if (method !== 'GET' && method !== 'HEAD') {
        setSecurityHeaders(res, req, { publicMode: ctx.publicMode });
        res.setHeader('Allow', 'GET, HEAD');
        res.statusCode = 405;
        res.end('Method Not Allowed');
        return;
      }

      await serveStaticFile(req, res, publicDir, pathname, ctx.publicMode);
    } catch (err) {
      const status = err.statusCode || 500;
      const code = err.code || 'INTERNAL_ERROR';
      const isSafeOperational = status < 500 || code === 'AUDIT_TIMEOUT' || code === 'PDF_ENGINE_UNAVAILABLE';
      const safeMessage = isSafeOperational ? err.message : 'An unexpected internal error occurred while processing the request.';
      if (status >= 500) {
        console.error(`[Kalasag Audit][${requestId}]`, err.message);
      }
      sendError(res, status, code, safeMessage, [], requestId, req, { publicMode: ctx.publicMode });
    }
  });

  return server;
}
