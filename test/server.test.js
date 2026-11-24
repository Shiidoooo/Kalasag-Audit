import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createAppServer } from '../src/server.js';

let server;
let baseUrl;
let tmpDir;
let historyFile;

before(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kalasag-test-'));
  historyFile = path.join(tmpDir, 'history.json');
  server = createAppServer({ historyFile });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
  await fs.rm(tmpDir, { recursive: true, force: true });
});

test('UI serves index.html with strict defensive headers (no unsafe-inline)', async () => {
  const res = await fetch(`${baseUrl}/`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.ok(html.includes('Kalasag Audit'));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  const csp = res.headers.get('content-security-policy') || '';
  assert.ok(csp.includes("object-src 'none'"));
  assert.ok(!csp.includes("'unsafe-inline'"));
});

test('Static server serves custom logo, hero, and layers assets and blocks path traversal', async () => {
  for (const asset of ['/assets/kalasag-mark.svg', '/assets/kalasag-logo.jpg', '/assets/kalasag-hero.jpg', '/assets/kalasag-layers.jpg']) {
    const res = await fetch(`${baseUrl}${asset}`);
    assert.equal(res.status, 200, `Expected 200 for ${asset}`);
  }
  const traversal = await fetch(`${baseUrl}/..%2fpackage.json`);
  assert.equal(traversal.status, 404);
  const dotfile = await fetch(`${baseUrl}/.env`);
  assert.equal(dotfile.status, 404);
});

test('GET /api/health returns healthy status envelope', async () => {
  const res = await fetch(`${baseUrl}/api/health`);
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.equal(json.status, 'success');
  assert.equal(json.data.app, 'Kalasag Audit');
});

test('POST /api/audit rejects missing or invalid URLs with 422', async () => {
  const res = await fetch(`${baseUrl}/api/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'ftp://invalid.example' })
  });
  assert.equal(res.status, 422);
  const json = await res.json();
  assert.equal(json.status, 'error');
  assert.equal(json.error.code, 'VALIDATION_ERROR');
});

test('POST /api/audit refuses OTP test without explicit confirmOtp === true', async () => {
  const res = await fetch(`${baseUrl}/api/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: baseUrl,
      otpTest: { url: `${baseUrl}/otp`, recipient: '09171234567' }
    })
  });
  assert.equal(res.status, 422);
  const json = await res.json();
  assert.equal(json.error.code, 'OTP_CONFIRMATION_REQUIRED');
});

test('Self-audit against Kalasag Audit UI passes with A+ (100/100) and saves to history + exports Markdown', async () => {
  const auditRes = await fetch(`${baseUrl}/api/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: baseUrl })
  });
  assert.equal(auditRes.status, 200);
  const auditJson = await auditRes.json();
  assert.equal(auditJson.status, 'success');
  assert.equal(auditJson.data.report.grade, 'A+', JSON.stringify(auditJson.data.report.findings, null, 2));
  assert.equal(auditJson.data.report.score, 100);
  assert.ok(auditJson.data.report.totalProbesExecuted >= 40, 'Should report full probe coverage count');
  assert.ok(Array.isArray(auditJson.data.report.coverage) && auditJson.data.report.coverage.length >= 12);

  const savedId = auditJson.data.id;

  // Verify history lists the saved scan
  const listRes = await fetch(`${baseUrl}/api/history`);
  const listJson = await listRes.json();
  assert.equal(listJson.data.items.length, 1);
  assert.equal(listJson.data.items[0].id, savedId);

  // Verify Enterprise PDF export produces a real binary %PDF document
  const pdfRes = await fetch(`${baseUrl}/api/export/pdf`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ report: auditJson.data.report })
  });
  assert.equal(pdfRes.status, 200);
  assert.equal(pdfRes.headers.get('content-type'), 'application/pdf');
  const pdfBytes = Buffer.from(await pdfRes.arrayBuffer());
  assert.equal(pdfBytes.subarray(0, 5).toString('ascii'), '%PDF-');
  assert.ok(pdfBytes.length > 5000, 'Generated PDF should contain full report content');

  // Verify Report Preview route renders with external /report.css (strict CSP safe)
  const previewRes = await fetch(`${baseUrl}/api/reports/${savedId}/preview`);
  assert.equal(previewRes.status, 200);
  const previewHtml = await previewRes.text();
  assert.ok(previewHtml.includes('<link rel="stylesheet" href="/report.css">'));
  assert.ok(!previewHtml.includes('onclick='));

  // Verify Markdown export is AI-friendly
  const mdRes = await fetch(`${baseUrl}/api/export/markdown`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ report: auditJson.data.report })
  });
  assert.equal(mdRes.status, 200);
  const mdText = await mdRes.text();
  assert.ok(mdText.includes('# Kalasag Audit — AI-Ready Security Remediation Report'));
  assert.ok(mdText.includes('## Prompt / Instructions for AI Coding Assistant'));
  assert.ok(mdText.includes('Already Passing Controls — Do Not Regress'));

  // Verify delete history record
  const delRes = await fetch(`${baseUrl}/api/history/${savedId}`, { method: 'DELETE' });
  assert.equal(delRes.status, 200);
  const afterList = await (await fetch(`${baseUrl}/api/history`)).json();
  assert.equal(afterList.data.items.length, 0);
});
