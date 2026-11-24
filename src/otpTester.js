/**
 * Kalasag Audit — OTP / Verification Endpoint Rate-Limit Tester
 * ---------------------------------------------------------
 * Detects the vulnerability class behind "OTP bombing" / "SMS bombing" tools:
 * an OTP / verification-code send endpoint that applies NO (or too weak)
 * rate limiting, so an attacker can flood a victim with texts or emails and
 * burn the owner's SMS/email gateway credits.
 *
 * SAFETY CONTRACT (this tool is a defensive detector, NOT a bomber):
 *   1. Opt-in only. It runs solely when the operator supplies an `otpTest`
 *      config block pointing at an endpoint and a recipient they control.
 *   2. Bounded. The probe burst is hard-capped (HARD_MAX_REQUESTS). There is
 *      no way to configure it into a flood.
 *   3. Sequential + spaced. Requests go one at a time with a delay, and the
 *      test STOPS the instant throttling is observed. This is the opposite of
 *      the parallel burst a bomber uses.
 *   4. Self-targeted. The operator must name their OWN test recipient. The
 *      tool refuses to run without one.
 *
 * The goal is to answer one question with the fewest possible real sends:
 * "Does this endpoint stop me before I can abuse it?"
 */

// Absolute ceilings — not operator-overridable. A real rate limit should trip
// well within this, so a handful of probes is enough to prove presence/absence.
const HARD_MAX_REQUESTS = 6;
const MIN_REQUESTS = 2;
const DEFAULT_REQUESTS = 4;
const INTER_REQUEST_DELAY_MS = 750;
const REQUEST_TIMEOUT_MS = 8000;

const RECIPIENT_PLACEHOLDERS = ['{{RECIPIENT}}', '{{OTP_RECIPIENT}}', '{{TARGET}}'];

// Default signals that a server is applying a limit (used if the operator does
// not supply their own throttleIndicators).
const DEFAULT_THROTTLE_INDICATORS = [
  'too many', 'try again', 'rate limit', 'rate-limit', 'ratelimit',
  'cooldown', 'cool down', 'slow down', 'please wait', 'wait before',
  'temporarily blocked', 'quota', 'limit exceeded', 'throttle',
  'resend in', 'request again in'
];

// Default signals that a send actually succeeded (an OTP really went out).
const DEFAULT_SUCCESS_INDICATORS = [
  'otp sent', 'code sent', 'sent to', 'verification sent', 'success',
  '"status":"ok"', '"success":true', 'sent successfully'
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function clampRequestCount(requested) {
  const n = Number.isFinite(requested) ? Math.floor(requested) : DEFAULT_REQUESTS;
  return Math.max(MIN_REQUESTS, Math.min(HARD_MAX_REQUESTS, n));
}

function matchesAny(haystack, needles) {
  if (!haystack) return false;
  const lower = haystack.toLowerCase();
  return needles.some((n) => n && lower.includes(String(n).toLowerCase()));
}

function renderTemplate(template, recipient) {
  if (template == null) return undefined;
  let str = typeof template === 'string' ? template : JSON.stringify(template);
  for (const ph of RECIPIENT_PLACEHOLDERS) {
    str = str.split(ph).join(recipient);
  }
  return str;
}

/**
 * Validates the operator-supplied config and returns {ok, error} or
 * {ok:true, normalized}. Keeps the safety invariants in one place.
 */
export function validateOtpConfig(raw) {
  if (!raw || typeof raw !== 'object') {
    return { ok: false, error: 'otpTest config missing or not an object.' };
  }
  if (!raw.url || typeof raw.url !== 'string') {
    return { ok: false, error: 'otpTest.url is required (the send-OTP endpoint).' };
  }
  let parsed;
  try {
    parsed = new URL(raw.url);
  } catch {
    return { ok: false, error: `otpTest.url is not a valid URL: ${raw.url}` };
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'otpTest.url must be http(s).' };
  }
  const recipient = raw.recipient != null ? String(raw.recipient).trim() : '';
  if (!recipient) {
    return {
      ok: false,
      error:
        'otpTest.recipient is required. Supply a phone/email you own and use for ' +
        'testing — this test triggers real OTP sends and must only hit your own inbox.'
    };
  }

  return {
    ok: true,
    normalized: {
      url: raw.url,
      method: (raw.method || 'POST').toUpperCase(),
      headers: raw.headers && typeof raw.headers === 'object' ? raw.headers : {},
      bodyTemplate: raw.body ?? raw.bodyTemplate ?? null,
      recipient,
      maxRequests: clampRequestCount(raw.maxRequests),
      successIndicators:
        Array.isArray(raw.successIndicators) && raw.successIndicators.length
          ? raw.successIndicators
          : DEFAULT_SUCCESS_INDICATORS,
      throttleIndicators:
        Array.isArray(raw.throttleIndicators) && raw.throttleIndicators.length
          ? raw.throttleIndicators
          : DEFAULT_THROTTLE_INDICATORS,
      label: raw.label || parsed.pathname
    }
  };
}

function classifyResponse(cfg, { status, retryAfter, bodyText }) {
  const throttledByStatus = status === 429;
  const throttledByHeader = Boolean(retryAfter);
  const throttledByBody = matchesAny(bodyText, cfg.throttleIndicators);
  const throttled = throttledByStatus || throttledByHeader || throttledByBody;

  const is2xx = status >= 200 && status < 300;
  const matchedSuccess = matchesAny(bodyText, cfg.successIndicators);

  // We deliberately do NOT assume every 2xx is a real send. An endpoint with an
  // unrecognized / custom response (the "bullshit name" case) is ACCEPTED but
  // UNCONFIRMED — we only claim a confirmed send when a success signal matches.
  const confirmedSend = !throttled && is2xx && matchedSuccess;
  const uncertainSend = !throttled && is2xx && !matchedSuccess;

  // A non-2xx, non-throttle response (403, 401, 400, 5xx, signature failure…)
  // means the probe was REJECTED by some other control — exactly the HTTP 403 /
  // "Failed to verify signature" rejections seen in real bomber logs. That is a
  // protective outcome, not a successful send.
  const rejectedByOtherControl = !throttled && !is2xx;

  return {
    throttled, throttledByStatus, throttledByHeader, throttledByBody,
    confirmedSend, uncertainSend, rejectedByOtherControl
  };
}

/**
 * Runs the bounded rate-limit probe and returns an array of Kalasag Audit findings.
 * Never throws for network issues — it reports them as findings instead.
 *
 * @param {object} rawConfig  operator-supplied otpTest block
 * @param {(line:string)=>void} [log]  optional progress logger
 */
export async function runOtpRateLimitTest(rawConfig, log = () => {}) {
  const findings = [];
  const valid = validateOtpConfig(rawConfig);
  if (!valid.ok) {
    findings.push({
      severity: 'INFO',
      category: 'OTP / Rate Limiting',
      title: 'OTP Rate-Limit Test Skipped (invalid config)',
      description: valid.error,
      remediation:
        'Provide an otpTest config with { url, recipient, method?, headers?, body? }. ' +
        'Use a recipient you own; this test triggers real sends.',
      scoreImpact: 0
    });
    return findings;
  }

  const cfg = valid.normalized;
  const attempts = [];

  log(`[*] OTP rate-limit test on ${cfg.method} ${cfg.url} (recipient: ${cfg.recipient}, max ${cfg.maxRequests} spaced probes)`);

  for (let i = 1; i <= cfg.maxRequests; i++) {
    const body = cfg.method === 'GET' || cfg.method === 'HEAD'
      ? undefined
      : renderTemplate(cfg.bodyTemplate, cfg.recipient);

    const started = Date.now();
    let status = 0;
    let retryAfter = null;
    let bodyText = '';
    let networkError = null;

    try {
      const res = await fetch(cfg.url, {
        method: cfg.method,
        headers: {
          'User-Agent': 'KalasagAudit/2.0 (authorized-self-test)',
          ...cfg.headers
        },
        body,
        redirect: 'manual',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
      });
      status = res.status;
      retryAfter = res.headers.get('retry-after');
      bodyText = (await res.text()).slice(0, 2000);
    } catch (err) {
      networkError = err.message || String(err);
    }

    const elapsed = Date.now() - started;
    const classified = networkError
      ? { throttled: false, confirmedSend: false, uncertainSend: false, rejectedByOtherControl: true, networkError }
      : classifyResponse(cfg, { status, retryAfter, bodyText });

    attempts.push({ i, status, retryAfter, elapsed, networkError, ...classified });
    log(`    [${i}/${cfg.maxRequests}] ${networkError ? `network error: ${networkError}` : `HTTP ${status}${retryAfter ? ` (Retry-After: ${retryAfter})` : ''}`}`);

    // Stop the moment a limit is observed — we have our answer and send no more.
    if (classified.throttled) break;

    if (i < cfg.maxRequests) await sleep(INTER_REQUEST_DELAY_MS);
  }

  // ---- Classify the overall result ----
  const throttledAttempt = attempts.find((a) => a.throttled);
  const confirmedCount = attempts.filter((a) => a.confirmedSend).length;
  const uncertainCount = attempts.filter((a) => a.uncertainSend).length;
  const acceptedCount = confirmedCount + uncertainCount; // any 2xx, confirmed or not
  const rejectedCount = attempts.filter((a) => a.rejectedByOtherControl && !a.networkError).length;
  const networkCount = attempts.filter((a) => a.networkError).length;
  const minToJudge = Math.min(cfg.maxRequests, 3);

  // Secondary signal: exponential/added delay instead of a 429 (some gateways
  // slow you down rather than block). Compare last vs first accepted latency.
  const acceptedAttempts = attempts.filter((a) => a.confirmedSend || a.uncertainSend);
  let delayThrottle = false;
  if (acceptedAttempts.length >= 3) {
    const first = acceptedAttempts[0].elapsed;
    const last = acceptedAttempts[acceptedAttempts.length - 1].elapsed;
    if (first > 0 && last > first * 3 && last > 2000) delayThrottle = true;
  }

  if (throttledAttempt) {
    const reason = throttledAttempt.throttledByStatus
      ? 'HTTP 429 Too Many Requests'
      : throttledAttempt.throttledByHeader
        ? `Retry-After header (${throttledAttempt.retryAfter})`
        : 'a rate-limit message in the response body';
    findings.push({
      severity: 'PASS',
      category: 'OTP / Rate Limiting',
      title: 'OTP Endpoint Enforces Rate Limiting',
      description:
        `The endpoint (${cfg.label}) began throttling at request #${throttledAttempt.i} of ${cfg.maxRequests} ` +
        `via ${reason}. This blocks OTP/SMS bombing abuse.`,
      remediation:
        'Good. Confirm the limit is keyed PER RECIPIENT (not just per IP) and pair it with a resend ' +
        'cooldown so the same code is re-sent during the window instead of generating new messages.',
      scoreImpact: 0
    });
  } else if (delayThrottle) {
    findings.push({
      severity: 'LOW',
      category: 'OTP / Rate Limiting',
      title: 'OTP Endpoint Appears to Soft-Throttle via Delay (no hard limit observed)',
      description:
        `No 429 or rate-limit response was returned across ${attempts.length} probes, but response latency ` +
        `grew sharply, suggesting a slow-down rather than a hard block. A delay alone does not stop a ` +
        `parallelized bomber.`,
      remediation:
        'Add an explicit per-recipient hard cap (e.g. 3 sends/hour) returning HTTP 429, plus a resend cooldown. ' +
        'Latency-based throttling is bypassed by sending requests in parallel.',
      scoreImpact: 6
    });
  } else if (acceptedCount === attempts.length && acceptedCount >= minToJudge && confirmedCount >= 1) {
    findings.push({
      severity: 'CRITICAL',
      category: 'OTP / Rate Limiting',
      title: 'No Rate Limiting on OTP / Verification Endpoint (OTP-Bombing Exposure)',
      description:
        `The endpoint (${cfg.label}) accepted ${acceptedCount} consecutive OTP-send requests for the same ` +
        `recipient with no 429, no Retry-After, and no cooldown message, and at least one response confirmed a ` +
        `send. An attacker can script this to flood a victim with texts/emails and drain your SMS/email gateway ` +
        `credits — the exact OTP-bombing abuse class. (Probe stopped at ${attempts.length}; a real attacker would not.)`,
      remediation:
        'Enforce a PER-RECIPIENT rate limit (e.g. 3/hour, 5/day) returning HTTP 429; add a 30–60s resend ' +
        'cooldown that re-sends the SAME code within the window; add CAPTCHA/proof-of-work after the first ' +
        'request; and set hard daily spend caps at your SMS/email provider.',
      scoreImpact: 30
    });
  } else if (acceptedCount === attempts.length && acceptedCount >= minToJudge && confirmedCount === 0) {
    // Every probe was accepted (2xx) with NO throttling, but none of the
    // responses matched a known "sent" signal — e.g. a custom/unrecognized
    // response format. We report the missing rate limit honestly, but do NOT
    // claim a confirmed send we could not detect.
    const statuses = [...new Set(attempts.map((a) => a.status))].join(', ');
    findings.push({
      severity: 'HIGH',
      category: 'OTP / Rate Limiting',
      title: 'No Rate Limiting Observed — Send Unconfirmed (no reliable detection)',
      description:
        `The endpoint (${cfg.label}) accepted ${acceptedCount} consecutive requests (HTTP ${statuses}) with no ` +
        `429, Retry-After, or cooldown — so no rate limiter was observed. However, the responses did not match ` +
        `any known success pattern, so the scanner could NOT confirm an OTP was actually sent each time. The ` +
        `absence of a rate limit is real; the send impact is unverified.`,
      remediation:
        'Add a per-recipient rate limit returning HTTP 429 regardless. To let the scanner confirm sends (and ' +
        'raise/clear this finding), set otpTest.successIndicators to a string that appears in this endpoint’s ' +
        '"sent" response, then re-run — or verify manually whether the test recipient received messages.',
      scoreImpact: 15
    });
  } else if (networkCount === attempts.length) {
    findings.push({
      severity: 'INFO',
      category: 'OTP / Rate Limiting',
      title: 'OTP Rate-Limit Test Inconclusive (endpoint unreachable)',
      description:
        `All ${attempts.length} probes failed at the network layer (e.g. ${attempts[0].networkError}). ` +
        `The endpoint could not be reached to assess rate limiting.`,
      remediation: 'Verify the otpTest.url, headers, and that the host is reachable from this scanner.',
      scoreImpact: 0
    });
  } else if (rejectedCount >= 1 && acceptedCount === 0) {
    const statuses = [...new Set(attempts.map((a) => a.networkError ? 'ERR' : a.status))].join(', ');
    findings.push({
      severity: 'INFO',
      category: 'OTP / Rate Limiting',
      title: 'OTP Probes Rejected by Another Control (likely auth/signature)',
      description:
        `The endpoint rejected the probes (statuses: ${statuses}) without sending — e.g. HTTP 401/403 or a ` +
        `signature check. This mirrors the "HTTP 403" / "Failed to verify signature" rejections seen in real ` +
        `bomber logs: a request-signing or auth gate is blocking abuse before rate limiting is even reached.`,
      remediation:
        'This is a protective outcome. To test the rate limiter itself, supply valid auth/signature headers in ' +
        'otpTest.headers so probes reach the send logic, then re-run.',
      scoreImpact: 0
    });
  } else {
    // Mixed / ambiguous result.
    findings.push({
      severity: 'MEDIUM',
      category: 'OTP / Rate Limiting',
      title: 'OTP Rate Limiting Could Not Be Confirmed (mixed responses)',
      description:
        `Across ${attempts.length} probes the endpoint neither clearly throttled nor behaved consistently ` +
        `(accepted: ${acceptedCount}, of which confirmed sends: ${confirmedCount}; rejections: ${rejectedCount}; ` +
        `network errors: ${networkCount}). Rate-limit behavior is ambiguous and should be verified manually.`,
      remediation:
        'Manually confirm a per-recipient limit returning 429 exists. Ensure success/throttle indicators in the ' +
        'config match this endpoint’s real responses, then re-run.',
      scoreImpact: 8
    });
  }

  return findings;
}
