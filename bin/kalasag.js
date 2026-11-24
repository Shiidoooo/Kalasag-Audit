#!/usr/bin/env node

import readline from 'node:readline';
import fs from 'node:fs/promises';
import path from 'node:path';
import { SecurityAuditor } from '../src/auditor.js';
import { Reporter } from '../src/reporter.js';

function promptUser(query) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => {
    rl.question(query, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Minimal flag parser. Supports:
 *   kalasag <target> [--config <path>] [--otp-config <path>] [--yes]
 */
function parseArgs(argv) {
  // probeServices defaults to on (undefined -> auditor enables it in local mode);
  // --no-services opts out.
  const opts = { target: null, configPath: null, assumeYes: false, probeServices: undefined, activeInjection: undefined, maxPages: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--config' || a === '--otp-config') {
      opts.configPath = argv[++i];
    } else if (a === '--yes' || a === '-y') {
      opts.assumeYes = true;
    } else if (a === '--services') {
      opts.probeServices = true;
    } else if (a === '--no-services') {
      opts.probeServices = false;
    } else if (a === '--no-injection') {
      opts.activeInjection = false;
    } else if (a === '--max-pages') {
      const n = parseInt(argv[++i], 10);
      if (Number.isFinite(n) && n >= 1) opts.maxPages = Math.min(100, n);
    } else if (!a.startsWith('-') && !opts.target) {
      opts.target = a;
    }
  }
  return opts;
}

async function loadConfig(explicitPath) {
  const candidates = explicitPath
    ? [explicitPath]
    : [
        path.join(process.cwd(), 'kalasag.config.json'),
        path.join(process.cwd(), 'webguard.config.json')
      ];

  for (const candidate of candidates) {
    try {
      const raw = await fs.readFile(candidate, 'utf-8');
      const parsed = JSON.parse(raw);
      const otpTest = parsed.otpTest || (parsed.url ? parsed : null);
      return { otpTest, source: candidate };
    } catch (err) {
      if (explicitPath) {
        console.error(`  \x1b[31m[!] Could not read config "${candidate}": ${err.message}\x1b[0m`);
      }
    }
  }
  return { otpTest: null, source: null };
}

async function main() {
  console.log(`
  \x1b[33m╔══════════════════════════════════════════════════════╗
  ║                  \x1b[1m\x1b[37mKALASAG AUDIT (v2)\x1b[0m\x1b[33m                  ║
  ║      Outside-In Web Security & Posture Auditor       ║
  ╚══════════════════════════════════════════════════════╝\x1b[0m
  `);

  const opts = parseArgs(process.argv.slice(2));
  let target = opts.target;

  if (!target) {
    target = await promptUser('  \x1b[1mEnter target URL (e.g. https://example.com or http://localhost:3000):\x1b[0m ');
  }

  if (!target) {
    console.error('  \x1b[31m[!] Error: No target URL provided. Exiting.\x1b[0m');
    process.exit(1);
  }

  const { otpTest, source } = await loadConfig(opts.configPath);
  let activeOtpTest = otpTest;

  if (activeOtpTest) {
    console.log(`\n  \x1b[33m[!] OTP rate-limit test is ENABLED\x1b[0m (config: ${source})`);
    console.log(`  \x1b[33m      Endpoint : ${activeOtpTest.method || 'POST'} ${activeOtpTest.url}\x1b[0m`);
    console.log(`  \x1b[33m      Recipient: ${activeOtpTest.recipient}\x1b[0m`);
    console.log(`  \x1b[31m      This sends a SMALL, bounded burst of REAL OTP requests to the recipient above.\x1b[0m`);
    console.log(`  \x1b[31m      Only run against an endpoint you own, with a recipient you control.\x1b[0m`);

    const isTty = process.stdin.isTTY;
    if (!opts.assumeYes && isTty) {
      const ans = await promptUser('  \x1b[1mProceed with the OTP test? (y/N):\x1b[0m ');
      if (!/^y(es)?$/i.test(ans)) {
        console.log('  \x1b[33m[*] OTP test declined. Running the rest of the audit without it.\x1b[0m');
        activeOtpTest = null;
      }
    } else if (!opts.assumeYes && !isTty) {
      console.log('  \x1b[33m[*] Non-interactive session without --yes; skipping the active OTP test for safety.\x1b[0m');
      activeOtpTest = null;
    }
  }

  console.log(`\n  \x1b[33m[*] Initializing security audit for:\x1b[0m \x1b[1m${target}\x1b[0m`);
  console.log('  \x1b[33m[*] Running modules (Transport, TLS, Headers, Cookies, CORS, Methods, Artifacts, Frontend, Redirects, DNS)...\x1b[0m');

  if (opts.probeServices === false) {
    console.log('  \x1b[33m[*] Service-exposure probe disabled (--no-services).\x1b[0m');
  } else {
    console.log('  \x1b[90m[*] Service-exposure probe active: will TCP-probe DB/admin ports on the target host (use --no-services to skip).\x1b[0m');
  }

  const auditor = new SecurityAuditor(target, {
    otpTest: activeOtpTest,
    probeServices: opts.probeServices,
    activeInjection: opts.activeInjection,
    maxPages: opts.maxPages,
    log: (line) => console.log(`  \x1b[90m${line}\x1b[0m`)
  });
  const startTime = Date.now();
  const report = await auditor.runAllChecks();
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log(`  \x1b[32m[✓] Scan completed in ${elapsed}s!\x1b[0m`);

  Reporter.printTerminalReport(report);

  try {
    const savedPath = await Reporter.saveMarkdownReport(report);
    console.log(`  \x1b[32m[+] Audit report saved to markdown:\x1b[0m \x1b[4m${savedPath}\x1b[0m\n`);
  } catch (err) {
    console.error(`  \x1b[31m[!] Could not save report file:\x1b[0m ${err.message}`);
  }
}

main().catch(err => {
  console.error('\n  \x1b[31m[!] Unhandled Auditor Exception:\x1b[0m', err);
  process.exit(1);
});
