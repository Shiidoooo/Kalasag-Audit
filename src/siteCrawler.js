import { readTextBounded, safeFetch } from './securityGuard.js';

const STATIC_EXT_RE = /\.(?:png|jpe?g|gif|svg|webp|ico|bmp|css|js|mjs|map|woff2?|ttf|eot|otf|pdf|zip|gz|tar|rar|7z|mp4|mp3|wav|avi|mov|webm|xml|rss|atom|json)$/i;
const DESTRUCTIVE_PATH_RE = /(?:^|[\/_-])(?:logout|log-out|signout|sign-out|signoff|delete|remove|destroy|drop|reset|revoke)(?:[\/_.-]|$)/i;
const SENSITIVE_ROBOTS_RE = /^\/(?:admin|administrator|wp-admin|phpmyadmin|pma|adminer|backup|backups|db|database|sql|dump|internal|private|secret|staging|dev|debug|config|cgi-bin|api\/internal|server-status|actuator)/i;
const CSRF_FIELD_RE = /(?:csrf|xsrf|_token|authenticity_token|__requestverificationtoken|antiforgery|request_token|form_token|form_key|wpnonce|nonce)/i;

/**
 * Normalizes a candidate href/action against a base URL, keeping only safe
 * same-origin HTTP(S) HTML-page URLs (drops hashes, skips mailto/js/media/logout).
 */
export function normalizeCrawlUrl(rawHref, baseUrl, allowedOrigin) {
  if (!rawHref || typeof rawHref !== 'string') return null;
  const trimmed = rawHref.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;
  if (/^(?:mailto:|tel:|javascript:|data:|blob:)/i.test(trimmed)) return null;

  let parsed;
  try {
    parsed = new URL(trimmed, baseUrl);
  } catch {
    return null;
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) return null;
  if (parsed.origin !== allowedOrigin) return null;
  if (STATIC_EXT_RE.test(parsed.pathname)) return null;
  if (DESTRUCTIVE_PATH_RE.test(parsed.pathname)) return null;

  parsed.hash = '';
  return parsed.toString();
}

/**
 * Builds a structural route signature (e.g. "/item.php?id&tab" or "/users/:num")
 * so pagination/ID loops (?page=1..500) cannot starve other real routes.
 */
export function routePatternKey(urlStr) {
  try {
    const u = new URL(urlStr);
    const normalizedPath = u.pathname
      .replace(/\/\d+(?=\/|$)/g, '/:num')
      .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi, '/:uuid');
    const paramNames = [...new Set([...u.searchParams.keys()])].sort().join('&');
    return paramNames ? `${normalizedPath}?${paramNames}` : normalizedPath;
  } catch {
    return urlStr;
  }
}

/**
 * Extracts same-origin page links from live HTML (ignoring HTML comments).
 */
export function extractLinksFromHtml(html, baseUrl, allowedOrigin) {
  if (!html) return [];
  const live = html.replace(/<!--[\s\S]*?-->/g, '');
  const found = new Set();

  const patterns = [
    /<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["']/gi,
    /<form\b[^>]*?\baction\s*=\s*["']([^"']+)["']/gi,
    /<iframe\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']/gi
  ];

  for (const re of patterns) {
    let m;
    while ((m = re.exec(live)) !== null) {
      const normalized = normalizeCrawlUrl(m[1], baseUrl, allowedOrigin);
      if (normalized) found.add(normalized);
    }
  }

  return [...found];
}

/**
 * Extracts same-origin <script src="..."> URLs from HTML.
 */
export function extractSameOriginScripts(html, baseUrl, allowedOrigin) {
  if (!html) return [];
  const live = html.replace(/<!--[\s\S]*?-->/g, '');
  const scripts = new Set();
  const scriptRe = /<script\b[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let sm;
  while ((sm = scriptRe.exec(live)) !== null) {
    try {
      const resolved = new URL(sm[1], baseUrl);
      if (resolved.origin === allowedOrigin) {
        resolved.hash = '';
        scripts.add(resolved.toString());
      }
    } catch {
      // ignore invalid script URL
    }
  }
  return [...scripts];
}

/**
 * Katana-inspired JavaScript endpoint extractor: discovers internal API & app
 * routes referenced inside same-origin JS bundles (e.g. fetch('/api/users')).
 */
export function extractApiRoutesFromJs(jsCode, limit = 60) {
  if (!jsCode || typeof jsCode !== 'string') return [];
  const sample = jsCode.length > 450_000 ? jsCode.slice(0, 450_000) : jsCode;
  const routes = new Set();

  // Pattern 1: explicit /api/..., /v1/..., /v2/..., /graphql, /auth/..., /rest/... paths
  const apiPathRe = /['"`](\/(?:api|v[1-9]|graphql|auth|rest|rpc|admin|internal)(?:\/[a-zA-Z0-9._:${}-]+)*)['"`]/g;
  let m;
  while ((m = apiPathRe.exec(sample)) !== null) {
    const candidate = cleanJsRoute(m[1]);
    if (candidate) routes.add(candidate);
    if (routes.size >= limit) break;
  }

  // Pattern 2: fetch('/path') or axios.get('/path') calls
  if (routes.size < limit) {
    const callRe = /\b(?:fetch|axios\.(?:get|post|put|patch|delete|request)|\.open\s*\(\s*['"`][A-Z]+['"`]\s*,)\s*\(?\s*['"`](\/[a-zA-Z0-9._:${}\/?&=-]{2,120})['"`]/gi;
    while ((m = callRe.exec(sample)) !== null) {
      const candidate = cleanJsRoute(m[1]);
      if (candidate) routes.add(candidate);
      if (routes.size >= limit) break;
    }
  }

  return [...routes].sort();
}

function cleanJsRoute(raw) {
  if (!raw || raw.length < 2 || raw.length > 140) return null;
  if (raw.startsWith('//')) return null;
  if (/^\/assets\/|^\/static\/|^\/images\/|^\/fonts\//i.test(raw)) return null;
  if (STATIC_EXT_RE.test(raw.split('?')[0])) return null;
  if (/\s/.test(raw)) return null;
  return raw;
}

/**
 * Parses robots.txt for Allow/Disallow entries, Sitemap URLs, and sensitive hints.
 */
export function parseRobotsTxt(text, allowedOrigin) {
  const paths = new Set();
  const sensitivePaths = new Set();
  const sitemaps = new Set();

  if (!text || /<!doctype|<html/i.test(text.slice(0, 300))) {
    return { paths: [], sensitivePaths: [], sitemaps: [] };
  }

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;

    const sitemapMatch = line.match(/^sitemap:\s*(\S+)/i);
    if (sitemapMatch) {
      try {
        const u = new URL(sitemapMatch[1], allowedOrigin);
        if (u.origin === allowedOrigin) sitemaps.add(u.toString());
      } catch {
        // ignore invalid sitemap URL
      }
      continue;
    }

    const ruleMatch = line.match(/^(?:allow|disallow):\s*(\/\S*)/i);
    if (ruleMatch) {
      const p = ruleMatch[1].replace(/\*.*$/, '');
      if (!p || p === '/') continue;
      if (SENSITIVE_ROBOTS_RE.test(p)) {
        sensitivePaths.add(p);
      }
      const normalized = normalizeCrawlUrl(p, allowedOrigin, allowedOrigin);
      if (normalized) paths.add(normalized);
    }
  }

  return {
    paths: [...paths].slice(0, 30),
    sensitivePaths: [...sensitivePaths].slice(0, 15),
    sitemaps: [...sitemaps].slice(0, 4)
  };
}

/**
 * Extracts same-origin <loc> URLs from sitemap.xml (or nested sitemapindex).
 */
export function parseSitemapXml(xml, allowedOrigin, limit = 40) {
  if (!xml || !/<(?:urlset|sitemapindex)\b/i.test(xml)) return [];
  const urls = new Set();
  const locRe = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  let m;
  while ((m = locRe.exec(xml)) !== null) {
    const candidate = m[1].trim();
    // Allow .xml child sitemap links to be returned separately when parsing sitemapindex
    if (/<sitemapindex\b/i.test(xml) && /\.xml(?:\?|$)/i.test(candidate)) {
      try {
        const u = new URL(candidate, allowedOrigin);
        if (u.origin === allowedOrigin) urls.add(u.toString());
      } catch { /* ignore */ }
    } else {
      const normalized = normalizeCrawlUrl(candidate, allowedOrigin, allowedOrigin);
      if (normalized) urls.add(normalized);
    }
    if (urls.size >= limit) break;
  }
  return [...urls];
}

/**
 * Decodes common named and numeric HTML entities so page titles render cleanly
 * (e.g. "About Us &#8211; Company" -> "About Us – Company").
 */
export function decodeHtmlEntities(str) {
  if (!str) return '';
  const named = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    nbsp: ' ',
    ndash: '\u2013',
    mdash: '\u2014',
    rsquo: '\u2019',
    lsquo: '\u2018',
    rdquo: '\u201D',
    ldquo: '\u201C',
    bull: '\u2022',
    copy: '\u00A9',
    reg: '\u00AE',
    hellip: '\u2026'
  };
  return String(str)
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
      const cp = parseInt(hex, 16);
      return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    })
    .replace(/&#(\d+);/g, (_, dec) => {
      const cp = parseInt(dec, 10);
      return Number.isFinite(cp) && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    })
    .replace(/&([a-z]+);/gi, (full, name) => named[name.toLowerCase()] ?? full);
}

/**
 * Extracts HTML page <title> safely (plain decoded text).
 */
export function extractPageTitle(html) {
  if (!html) return '';
  const m = html.match(/<title\b[^>]*>([\s\S]{1,220}?)<\/title>/i);
  if (!m) return '';
  const clean = decodeHtmlEntities(m[1].replace(/<[^>]+>/g, ''));
  return clean.replace(/\s+/g, ' ').trim().slice(0, 95);
}

/**
 * Checks an HTML page for active/passive mixed content and exposed client keys.
 */
function inspectSubpageContent(html, isHttps) {
  const issues = [];
  if (!html) return issues;
  const live = html.replace(/<!--[\s\S]*?-->/g, '');

  if (isHttps) {
    const activeRe = /<(?:script|link|iframe|object|embed)\b[^>]*?\b(?:src|href|data)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
    const isLoadingTag = (tag) => !/^<link\b/i.test(tag)
      || /\brel\s*=\s*["']?[^"'>]*\b(?:stylesheet|icon|preload|modulepreload|manifest)\b/i.test(tag);
    const activeHits = [...live.matchAll(activeRe)].filter(m => isLoadingTag(m[0]));
    if (activeHits.length > 0) {
      issues.push({ severity: 'MEDIUM', label: `Active mixed content (${activeHits.length} http:// asset${activeHits.length > 1 ? 's' : ''})` });
    }
  }

  if (/['"`](AIza[0-9A-Za-z-_]{35})['"`]/.test(live)) {
    issues.push({ severity: 'LOW', label: 'Google API key in page markup' });
  }

  return issues;
}

/**
 * Analyzes every <form> element on an HTML page for auth/CSRF/transport hygiene
 * and collects safe GET form targets for local injection checks.
 */
export function analyzePageForms(html, pageUrl) {
  const result = {
    formsCount: 0,
    postFormsWithoutCsrf: [],
    httpPasswordForm: false,
    downgradedFormActions: [],
    getTargets: []
  };

  if (!html) return result;
  const live = html.replace(/<!--[\s\S]*?-->/g, '');
  const parsedPage = new URL(pageUrl);
  const pageIsHttps = parsedPage.protocol === 'https:';

  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(live)) !== null) {
    result.formsCount += 1;
    const attrs = fm[1] || '';
    const inner = fm[2] || '';

    const methodMatch = attrs.match(/\bmethod\s*=\s*["']?([a-zA-Z]+)["']?/i);
    const hasExplicitMethod = Boolean(methodMatch);
    const method = (methodMatch ? methodMatch[1] : 'get').toLowerCase();

    const actionMatch = attrs.match(/\baction\s*=\s*["']([^"']*)["']/i);
    const rawAction = actionMatch ? actionMatch[1].trim() : '';
    let resolvedAction = pageUrl;
    try {
      resolvedAction = new URL(rawAction || '', pageUrl).toString();
    } catch {
      resolvedAction = pageUrl;
    }

    const inputTags = [...inner.matchAll(/<(?:input|textarea|select)\b([^>]*)>/gi)].map(m => m[1] || '');
    const fieldNames = [];
    let hasPassword = false;
    let hasCsrfField = false;

    for (const inputAttrs of inputTags) {
      const typeMatch = inputAttrs.match(/\btype\s*=\s*["']?([a-zA-Z0-9_-]+)["']?/i);
      const nameMatch = inputAttrs.match(/\bname\s*=\s*["']([^"']+)["']/i);
      const inputType = (typeMatch ? typeMatch[1] : 'text').toLowerCase();
      const inputName = nameMatch ? nameMatch[1] : '';

      if (inputType === 'password') hasPassword = true;
      if (inputName) {
        if (CSRF_FIELD_RE.test(inputName)) hasCsrfField = true;
        if (!['submit', 'button', 'reset', 'image', 'file'].includes(inputType)) {
          fieldNames.push(inputName);
        }
      }
    }

    if (hasPassword && !pageIsHttps) {
      result.httpPasswordForm = true;
    }

    if (pageIsHttps && resolvedAction.startsWith('http://')) {
      result.downgradedFormActions.push(resolvedAction);
    }

    // Only flag explicit HTML POST forms so JS/SPA forms without method="post" aren't false-flagged
    if (hasExplicitMethod && method === 'post' && fieldNames.length > 0 && !hasCsrfField) {
      result.postFormsWithoutCsrf.push({
        page: parsedPage.pathname + parsedPage.search,
        action: resolvedAction
      });
    }

    if (method === 'get' && fieldNames.length > 0) {
      for (const name of fieldNames.slice(0, 4)) {
        result.getTargets.push({ action: resolvedAction, name, value: 'test' });
      }
    }
  }

  return result;
}

/**
 * Inspects a subpage's HTTP headers & cookies for security drift compared to the root.
 */
function inspectSubpageHeaders(headers, isHttps) {
  const missing = [];
  if (!headers.get('content-security-policy')) missing.push('CSP');
  const hasXfo = Boolean(headers.get('x-frame-options'));
  const csp = (headers.get('content-security-policy') || '').toLowerCase();
  if (!hasXfo && !csp.includes('frame-ancestors')) missing.push('X-Frame-Options');
  const xcto = (headers.get('x-content-type-options') || '').toLowerCase();
  if (!xcto.includes('nosniff')) missing.push('X-Content-Type-Options');

  const insecureCookies = [];
  const cookiesList = typeof headers.getSetCookie === 'function'
    ? headers.getSetCookie()
    : (headers.get('set-cookie') ? [headers.get('set-cookie')] : []);

  for (const cookieStr of cookiesList) {
    const parts = cookieStr.split(';').map(p => p.trim());
    const name = (parts[0] || '').split('=')[0];
    if (!name || name.includes(' ')) continue;
    const maxAge = parts.find(p => /^max-age=/i.test(p));
    if (maxAge && parseInt(maxAge.split('=')[1], 10) <= 0) continue;
    if (/^_ga|^_gid|^_gat/i.test(name)) continue;

    const hasSecure = parts.some(p => p.toLowerCase() === 'secure');
    const hasHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
    if ((isHttps && !hasSecure) || !hasHttpOnly) {
      insecureCookies.push(name);
    }
  }

  return { missing, insecureCookies };
}

/**
 * Multi-depth recursive BFS same-origin crawler with anti-trap route dedup,
 * sitemap/robots discovery, JS bundle API endpoint harvesting, and time budget.
 *
 * Defaults:
 *  - Local mode: up to 50 pages (maxDepth 3, concurrency 8, 12s budget, up to 12 JS bundles)
 *  - Public/Vercel mode: up to 25 pages (maxDepth 2, concurrency 6, 7.5s budget, up to 6 JS bundles)
 */
export async function crawlSameOriginSite({
  rootUrl,
  rootHtml = '',
  publicMode = false,
  dnsLookup,
  maxPages = 50,
  maxDepth = 3,
  concurrency = 10,
  timeBudgetMs = publicMode ? 22_000 : 18_000,
  timeoutMs = 5500,
  log = () => {}
}) {
  const effectiveMaxPages = Math.max(1, Math.min(100, Number(maxPages) || 50));
  const crawlStartedAt = Date.now();
  const parsedRoot = new URL(rootUrl);
  const origin = parsedRoot.origin;
  const guardOpts = { publicMode, dnsLookup, maxRedirects: 2 };
  const fetchHeaders = { 'User-Agent': 'KalasagAudit/2.0' };

  const rootClean = parsedRoot.toString().replace(/#.*$/, '');
  const queued = new Set([rootClean]);
  const patternCounts = new Map();
  const rootPattern = routePatternKey(rootClean);
  patternCounts.set(rootPattern, 1);

  const rootFormInfo = analyzePageForms(rootHtml, rootUrl);
  const rootIssues = [];
  if (rootFormInfo.downgradedFormActions.length > 0) {
    rootIssues.push({ severity: 'HIGH', label: 'HTTPS form submits over HTTP' });
  }
  if (rootFormInfo.httpPasswordForm && !parsedRoot.protocol.startsWith('https')) {
    rootIssues.push({ severity: 'INFO', label: 'Password input on HTTP' });
  }
  if (rootFormInfo.postFormsWithoutCsrf.length > 0) {
    rootIssues.push({ severity: 'MEDIUM', label: `POST form missing CSRF token (${rootFormInfo.postFormsWithoutCsrf.length})` });
  }

  const pages = [
    {
      url: rootClean,
      path: parsedRoot.pathname + parsedRoot.search,
      status: 200,
      title: extractPageTitle(rootHtml),
      source: 'root',
      depth: 0,
      formsCount: rootFormInfo.formsCount,
      audited: true,
      issues: rootIssues,
      missingHeaders: [],
      insecureCookies: []
    }
  ];

  const allFormFindings = {
    postFormsWithoutCsrf: [...rootFormInfo.postFormsWithoutCsrf],
    httpPasswordPages: rootFormInfo.httpPasswordForm ? [parsedRoot.pathname + parsedRoot.search] : [],
    downgradedFormActions: [...rootFormInfo.downgradedFormActions]
  };
  const extraInjectionTargets = [...rootFormInfo.getTargets];
  const apiRoutes = new Set(extractApiRoutesFromJs(rootHtml, 80));
  const discoveredScripts = new Set(extractSameOriginScripts(rootHtml, rootUrl, origin));

  // BFS queue: { url, source, depth }
  const queue = [];
  let totalLinksSeen = 1;
  let maxDepthReached = 0;

  const enqueue = (candidateUrl, source, depth) => {
    if (!candidateUrl || depth > maxDepth) return;
    if (queued.has(candidateUrl)) return;

    // Anti-trap: allow at most 2 URLs per identical structural pattern (e.g. /post?id=1 & /post?id=2)
    // so pagination loops never crowd out distinct application routes.
    const pat = routePatternKey(candidateUrl);
    const count = patternCounts.get(pat) || 0;
    if (count >= 2 && (candidateUrl.includes('?') || pat.includes(':num') || pat.includes(':uuid'))) {
      return;
    }

    queued.add(candidateUrl);
    patternCounts.set(pat, count + 1);
    totalLinksSeen += 1;
    queue.push({ url: candidateUrl, source, depth });
  };

  for (const link of extractLinksFromHtml(rootHtml, rootUrl, origin)) {
    enqueue(link, 'link', 1);
  }

  // Step 1: Fetch robots.txt & sitemap.xml in parallel (non-fatal)
  const fetchSmallText = async (target) => {
    try {
      const { res } = await safeFetch(
        target,
        { method: 'GET', signal: AbortSignal.timeout(timeoutMs), headers: fetchHeaders },
        guardOpts
      );
      if (res.status !== 200) return '';
      return await readTextBounded(res, 98_304);
    } catch {
      return '';
    }
  };

  const [robotsText, rootSitemapText] = await Promise.all([
    fetchSmallText(`${origin}/robots.txt`),
    fetchSmallText(`${origin}/sitemap.xml`)
  ]);

  const robots = parseRobotsTxt(robotsText, origin);
  const robotsSensitivePaths = robots.sensitivePaths;
  for (const u of robots.paths) {
    enqueue(u, 'robots', 1);
  }

  let sitemapUrls = parseSitemapXml(rootSitemapText, origin, 40);
  // If /sitemap.xml is a sitemapindex pointing to child .xml files, follow the first child sitemap
  if (sitemapUrls.length > 0 && /\.xml(?:\?|$)/i.test(sitemapUrls[0])) {
    const childXml = await fetchSmallText(sitemapUrls[0]);
    sitemapUrls = parseSitemapXml(childXml, origin, 40);
  } else if (sitemapUrls.length === 0 && robots.sitemaps.length > 0) {
    const altXml = await fetchSmallText(robots.sitemaps[0]);
    const parsedAlt = parseSitemapXml(altXml, origin, 40);
    if (parsedAlt.length > 0 && /\.xml(?:\?|$)/i.test(parsedAlt[0])) {
      const childXml = await fetchSmallText(parsedAlt[0]);
      sitemapUrls = parseSitemapXml(childXml, origin, 40);
    } else {
      sitemapUrls = parsedAlt;
    }
  }
  for (const u of sitemapUrls) {
    enqueue(u, 'sitemap', 1);
  }

  // Step 2: Recursive BFS crawl up to effectiveMaxPages within timeBudgetMs
  const subpageHeaderGaps = [];
  const subpageCookieIssues = [];
  const subpageMixedContent = [];
  let timeBudgetReached = false;
  let queueIndex = 0;

  if (queue.length > 0) {
    log(`[*] Crawling same-origin pages (up to ${effectiveMaxPages}, depth ${maxDepth})...`);
  }

  while (queueIndex < queue.length && pages.length < effectiveMaxPages) {
    if (Date.now() - crawlStartedAt >= timeBudgetMs) {
      timeBudgetReached = true;
      break;
    }

    const remainingSlots = effectiveMaxPages - pages.length;
    const batch = queue.slice(queueIndex, queueIndex + Math.min(concurrency, remainingSlots));
    queueIndex += batch.length;

    await Promise.all(
      batch.map(async (item) => {
        if (Date.now() - crawlStartedAt >= timeBudgetMs) {
          timeBudgetReached = true;
          return;
        }

        // Queue any GET query parameters present on this discovered URL for local injection testing
        try {
          const cu = new URL(item.url);
          for (const [k, v] of cu.searchParams) {
            extraInjectionTargets.push({ action: item.url, name: k, value: v || 'test' });
          }
        } catch { /* ignore */ }

        try {
          const { res, finalUrl } = await safeFetch(
            item.url,
            { method: 'GET', signal: AbortSignal.timeout(timeoutMs), headers: fetchHeaders },
            guardOpts
          );
          const contentType = (res.headers.get('content-type') || '').toLowerCase();
          const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml');
          const body = isHtml ? await readTextBounded(res, 131_072) : '';
          const parsedFinal = new URL(finalUrl || item.url);
          const isHttps = parsedFinal.protocol === 'https:';
          const pagePath = parsedFinal.pathname + parsedFinal.search;

          let formsCount = 0;
          let headerAudit = { missing: [], insecureCookies: [] };
          const pageIssues = [];

          if (res.status >= 200 && res.status < 400 && isHtml) {
            const formInfo = analyzePageForms(body, finalUrl || item.url);
            formsCount = formInfo.formsCount;
            allFormFindings.postFormsWithoutCsrf.push(...formInfo.postFormsWithoutCsrf);
            if (formInfo.httpPasswordForm) {
              allFormFindings.httpPasswordPages.push(pagePath);
              pageIssues.push({ severity: isHttps ? 'INFO' : 'HIGH', label: 'Password form over plain HTTP' });
            }
            if (formInfo.downgradedFormActions.length > 0) {
              allFormFindings.downgradedFormActions.push(...formInfo.downgradedFormActions);
              pageIssues.push({ severity: 'HIGH', label: 'HTTPS form submits over HTTP' });
            }
            if (formInfo.postFormsWithoutCsrf.length > 0) {
              pageIssues.push({ severity: 'MEDIUM', label: `POST form missing CSRF token (${formInfo.postFormsWithoutCsrf.length})` });
            }
            extraInjectionTargets.push(...formInfo.getTargets);

            headerAudit = inspectSubpageHeaders(res.headers, isHttps);
            if (headerAudit.missing.length > 0) {
              subpageHeaderGaps.push({ path: pagePath, missing: headerAudit.missing });
              pageIssues.push({ severity: 'LOW', label: `Missing headers: ${headerAudit.missing.join(', ')}` });
            }
            if (headerAudit.insecureCookies.length > 0) {
              subpageCookieIssues.push({ path: pagePath, cookies: headerAudit.insecureCookies });
              pageIssues.push({ severity: 'MEDIUM', label: `Insecure cookie(s): ${headerAudit.insecureCookies.join(', ')}` });
            }

            const contentIssues = inspectSubpageContent(body, isHttps);
            for (const ci of contentIssues) {
              pageIssues.push(ci);
              if (ci.label.startsWith('Active mixed content')) {
                subpageMixedContent.push(pagePath);
              }
            }

            // Extract inline JS routes and linked same-origin scripts from this subpage
            for (const r of extractApiRoutesFromJs(body, 20)) {
              apiRoutes.add(r);
            }
            for (const scriptUrl of extractSameOriginScripts(body, finalUrl || item.url, origin)) {
              discoveredScripts.add(scriptUrl);
            }

            // Recursive BFS: enqueue newly discovered links at depth + 1!
            if (item.depth < maxDepth) {
              for (const nextLink of extractLinksFromHtml(body, finalUrl || item.url, origin)) {
                enqueue(nextLink, 'link', item.depth + 1);
              }
            }
          }

          if (item.depth > maxDepthReached) maxDepthReached = item.depth;

          pages.push({
            url: finalUrl || item.url,
            path: pagePath,
            status: res.status,
            title: isHtml ? extractPageTitle(body) : '',
            source: item.source,
            depth: item.depth,
            formsCount,
            audited: true,
            issues: pageIssues,
            missingHeaders: headerAudit.missing,
            insecureCookies: headerAudit.insecureCookies
          });
        } catch {
          // Unreachable or timed-out subpage — skip quietly
        }
      })
    );
  }

  // Step 3: Katana-style JS route extraction across all discovered same-origin bundles
  const maxJsBundles = 12;
  const scriptList = [...discoveredScripts].slice(0, maxJsBundles);
  if (scriptList.length > 0 && Date.now() - crawlStartedAt < timeBudgetMs + 4000) {
    await Promise.all(
      scriptList.map(async (jsUrl) => {
        try {
          const { res } = await safeFetch(
            jsUrl,
            { method: 'GET', signal: AbortSignal.timeout(4000), headers: fetchHeaders },
            guardOpts
          );
          if (res.status === 200) {
            const code = await readTextBounded(res, 262_144);
            for (const r of extractApiRoutesFromJs(code, 40)) {
              apiRoutes.add(r);
            }
          }
        } catch {
          // ignore script fetch errors
        }
      })
    );
  }

  // Deduplicate form findings
  const seenCsrf = new Set();
  const uniqueCsrf = allFormFindings.postFormsWithoutCsrf.filter((item) => {
    const key = `${item.page}|${item.action}`;
    if (seenCsrf.has(key)) return false;
    seenCsrf.add(key);
    return true;
  });

  return {
    pages,
    apiRoutes: [...apiRoutes].sort().slice(0, 100),
    robotsSensitivePaths,
    crawlStats: {
      pagesVisited: pages.length,
      maxPages: effectiveMaxPages,
      maxDepthReached,
      totalLinksSeen,
      scriptsInspected: scriptList.length,
      truncatedByLimit: queueIndex < queue.length,
      timeBudgetReached
    },
    formFindings: {
      postFormsWithoutCsrf: uniqueCsrf,
      httpPasswordPages: [...new Set(allFormFindings.httpPasswordPages)],
      downgradedFormActions: [...new Set(allFormFindings.downgradedFormActions)]
    },
    subpageHeaderGaps,
    subpageCookieIssues,
    subpageMixedContent: [...new Set(subpageMixedContent)],
    extraInjectionTargets
  };
}
