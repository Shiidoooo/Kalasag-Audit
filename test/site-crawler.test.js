import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  extractLinksFromHtml,
  extractApiRoutesFromJs,
  parseRobotsTxt,
  parseSitemapXml,
  analyzePageForms
} from '../src/siteCrawler.js';
import { SecurityAuditor } from '../src/auditor.js';

function startMockApp(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

function stopMockApp(server) {
  server.closeAllConnections?.();
  return new Promise((resolve) => server.close(resolve));
}

test('extractLinksFromHtml keeps same-origin pages and skips comments, external links, static assets & logout', () => {
  const html = `
    <html><body>
      <!-- <a href="/commented-out">Hidden</a> -->
      <a href="/about">About</a>
      <a href="/search.php?q=docs">Search</a>
      <a href="/logout">Sign out</a>
      <a href="/delete-account">Delete</a>
      <a href="/assets/logo.png">Logo</a>
      <a href="https://evil.example/phish">External</a>
      <a href="mailto:test@example.com">Mail</a>
      <a href="#top">Anchor</a>
    </body></html>
  `;
  const links = extractLinksFromHtml(html, 'https://app.example/', 'https://app.example');
  assert.deepEqual(links.sort(), [
    'https://app.example/about',
    'https://app.example/search.php?q=docs'
  ]);
});

test('extractApiRoutesFromJs extracts Katana-style API routes from JS bundles and skips static assets', () => {
  const js = `
    const a = fetch('/api/v1/users');
    axios.post('/auth/login', data);
    const b = '/v2/orders/export';
    const img = '/assets/kalasag-logo.jpg';
  `;
  const routes = extractApiRoutesFromJs(js);
  assert.ok(routes.includes('/api/v1/users'));
  assert.ok(routes.includes('/auth/login'));
  assert.ok(routes.includes('/v2/orders/export'));
  assert.ok(!routes.some(r => r.includes('kalasag-logo.jpg')));
});

test('parseRobotsTxt & parseSitemapXml extract same-origin URLs and flag sensitive disallowed paths', () => {
  const robots = `
    User-agent: *
    Disallow: /admin/
    Disallow: /backup/db
    Allow: /docs/
    Sitemap: https://app.example/sitemap.xml
  `;
  const parsed = parseRobotsTxt(robots, 'https://app.example');
  assert.ok(parsed.sensitivePaths.includes('/admin/'));
  assert.ok(parsed.sensitivePaths.includes('/backup/db'));
  assert.ok(parsed.paths.includes('https://app.example/docs/'));
  assert.deepEqual(parsed.sitemaps, ['https://app.example/sitemap.xml']);

  const xml = `
    <urlset>
      <url><loc>https://app.example/pricing</loc></url>
      <url><loc>https://other.example/ignore</loc></url>
    </urlset>
  `;
  assert.deepEqual(parseSitemapXml(xml, 'https://app.example'), ['https://app.example/pricing']);
});

test('analyzePageForms catches missing CSRF on explicit POST forms, ignores JS forms, and detects HTTPS->HTTP downgrade', () => {
  const html = `
    <form id="spa-form"><input name="url" type="text"></form>
    <form method="post" action="http://app.example/login">
      <input name="email" type="email">
      <input name="password" type="password">
    </form>
    <form method="post" action="/profile">
      <input type="hidden" name="_csrf_token" value="abc">
      <input name="bio" type="text">
    </form>
  `;
  const res = analyzePageForms(html, 'https://app.example/account');
  assert.equal(res.formsCount, 3);
  assert.equal(res.postFormsWithoutCsrf.length, 1);
  assert.equal(res.downgradedFormActions.length, 1);
  assert.equal(res.downgradedFormActions[0], 'http://app.example/login');
  assert.equal(res.httpPasswordForm, false); // page itself is HTTPS
});

test('Multi-page local scan discovers subpages, JS API routes, missing POST CSRF, and SQLi on a crawled subpage', async () => {
  const { server, baseUrl } = await startMockApp((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');

    if (u.pathname === '/') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'self'; object-src 'none'; base-uri 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff'
      });
      res.end(`
        <!doctype html><html><head><title>Demo App</title></head><body>
          <a href="/login">Login</a>
          <a href="/search?q=books">Search</a>
          <script src="/bundle.js"></script>
        </body></html>
      `);
      return;
    }

    if (u.pathname === '/bundle.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end(`fetch('/api/v1/orders'); axios.get('/api/v1/profile');`);
      return;
    }

    if (u.pathname === '/login') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        // Intentionally omit CSP to test subpage header drift detection
        'X-Content-Type-Options': 'nosniff'
      });
      res.end(`
        <!doctype html><html><head><title>Login</title></head><body>
          <form method="post" action="/login">
            <input name="user" type="text">
            <input name="pass" type="password">
          </form>
        </body></html>
      `);
      return;
    }

    if (u.pathname === '/search') {
      const q = u.searchParams.get('q') || '';
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'self'; object-src 'none'; base-uri 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff'
      });
      if (q.includes("'")) {
        res.end('<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</html>');
      } else {
        res.end(`<html><head><title>Search</title></head><body>Results for safe query</body></html>`);
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  try {
    // Pass ONLY the root URL — prove Kalasag crawls /login, /search?q=books, and /bundle.js!
    const auditor = new SecurityAuditor(baseUrl, { probeServices: false });
    const report = await auditor.runAllChecks();

    const paths = report.discoveredPages.map(p => p.path);
    assert.ok(paths.includes('/'), `Expected / in ${paths}`);
    assert.ok(paths.includes('/login'), `Expected /login in ${paths}`);
    assert.ok(paths.includes('/search?q=books'), `Expected /search?q=books in ${paths}`);

    assert.ok(report.discoveredApiRoutes.includes('/api/v1/orders'));
    assert.ok(report.discoveredApiRoutes.includes('/api/v1/profile'));

    const titles = report.findings.map(f => `${f.severity}: ${f.title}`);
    assert.ok(titles.some(t => /MEDIUM: POST Form Missing Anti-CSRF Token/.test(t)), titles.join('\n'));
    assert.ok(titles.some(t => /LOW: Subpage Security Header Drift/.test(t)), titles.join('\n'));
    assert.ok(titles.some(t => /CRITICAL: Error-Based SQL Injection/.test(t)), titles.join('\n'));
  } finally {
    await stopMockApp(server);
  }
});

test('Recursive multi-depth BFS crawls Depth 1 -> Depth 2 -> Depth 3, harvests subpage JS, and avoids pagination traps', async () => {
  const { server, baseUrl } = await startMockApp((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    const hdrs = {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'self'; object-src 'none'; base-uri 'self'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff'
    };

    if (u.pathname === '/') {
      // Emit 25 pagination links (?page=1..25) PLUS real depth links to verify anti-trap dedup!
      const traps = Array.from({ length: 25 }, (_, i) => `<a href="/blog?page=${i + 1}">P${i + 1}</a>`).join('');
      res.writeHead(200, hdrs);
      res.end(`<html><head><title>Home</title></head><body>${traps}<a href="/level1">L1</a></body></html>`);
      return;
    }
    if (u.pathname === '/level1') {
      res.writeHead(200, hdrs);
      res.end(`<html><head><title>Level 1</title></head><body><a href="/level2">L2</a></body></html>`);
      return;
    }
    if (u.pathname === '/level2') {
      res.writeHead(200, hdrs);
      res.end(`<html><head><title>Level 2</title></head><body><a href="/level3">L3</a><script src="/sub-app.js"></script></body></html>`);
      return;
    }
    if (u.pathname === '/level3') {
      res.writeHead(200, hdrs);
      res.end(`<html><head><title>Level 3 Deep</title></head><body>Deep page</body></html>`);
      return;
    }
    if (u.pathname === '/sub-app.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end(`fetch('/api/v3/deep-records');`);
      return;
    }
    if (u.pathname === '/blog') {
      res.writeHead(200, hdrs);
      res.end(`<html><head><title>Blog</title></head><body>Blog list</body></html>`);
      return;
    }
    res.writeHead(404);
    res.end('Not Found');
  });

  try {
    const auditor = new SecurityAuditor(baseUrl, { probeServices: false, maxPages: 50 });
    const report = await auditor.runAllChecks();
    const paths = report.discoveredPages.map(p => p.path);

    // Must reach depth 3 without being starved by 25 pagination URLs!
    assert.ok(paths.includes('/level1'), `Missing /level1 in ${paths}`);
    assert.ok(paths.includes('/level2'), `Missing /level2 in ${paths}`);
    assert.ok(paths.includes('/level3'), `Missing /level3 in ${paths}`);
    assert.equal(report.crawlStats.maxDepthReached, 3);

    // Anti-trap: at most 2 /blog?page=* pages should have been crawled (not all 25!)
    const blogPages = paths.filter(p => p.startsWith('/blog?page='));
    assert.ok(blogPages.length <= 2, `Expected anti-trap <= 2 blog pages, got ${blogPages.length}`);

    // Subpage JS bundle route harvested at depth 2!
    assert.ok(report.discoveredApiRoutes.includes('/api/v3/deep-records'));
  } finally {
    await stopMockApp(server);
  }
});

test('extractPageTitle decodes numeric and named HTML entities cleanly', async () => {
  const { extractPageTitle } = await import('../src/siteCrawler.js');
  assert.equal(
    extractPageTitle('<title>About Us &#8211; Example &amp; Co &mdash; Home</title>'),
    'About Us \u2013 Example & Co \u2014 Home'
  );
});
