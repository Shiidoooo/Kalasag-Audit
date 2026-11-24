import fs from 'node:fs/promises';
import path from 'node:path';

// ANSI color codes for clean terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m'
};

export class Reporter {
  static getBadge(severity) {
    switch (severity) {
      case 'CRITICAL':
        return `${colors.bgRed}${colors.white}${colors.bold} CRITICAL ${colors.reset}`;
      case 'HIGH':
        return `${colors.red}${colors.bold}[HIGH]${colors.reset}`;
      case 'MEDIUM':
        return `${colors.yellow}${colors.bold}[MEDIUM]${colors.reset}`;
      case 'LOW':
        return `${colors.cyan}${colors.bold}[LOW]${colors.reset}`;
      case 'INFO':
        return `${colors.blue}${colors.bold}[INFO]${colors.reset}`;
      case 'PASS':
        return `${colors.green}${colors.bold}[✓ PASS]${colors.reset}`;
      default:
        return `[${severity}]`;
    }
  }

  static getGradeColor(grade) {
    if (grade.startsWith('A')) return colors.green;
    if (grade === 'B') return colors.cyan;
    if (grade === 'C') return colors.yellow;
    return colors.red;
  }

  static printTerminalReport(report) {
    console.log('\n' + colors.cyan + '='.repeat(70) + colors.reset);
    console.log(` ${colors.bold}KALASAG AUDIT — SECURITY POSTURE REPORT${colors.reset}`);
    console.log(colors.cyan + '='.repeat(70) + colors.reset);

    const gradeColor = this.getGradeColor(report.grade);
    console.log(` Target URL : ${colors.bold}${report.targetUrl}${colors.reset}`);
    console.log(` Hostname   : ${report.hostname}`);
    console.log(` Scan Time  : ${report.scanTime}`);
    console.log(` Score      : ${gradeColor}${colors.bold}${report.score} / 100${colors.reset}`);
    console.log(` Grade      : ${gradeColor}${colors.bold}[ ${report.grade} ]${colors.reset}`);
    if (report.gradeCappedBy) {
      console.log(` ${colors.dim}Note       : Grade capped by at least one ${report.gradeCappedBy} finding (fix it to raise the ceiling).${colors.reset}`);
    }
    console.log(colors.cyan + '-'.repeat(70) + colors.reset);

    const issues = report.findings.filter(f => f.severity !== 'PASS');
    const passed = report.findings.filter(f => f.severity === 'PASS');

    if (issues.length === 0) {
      console.log(`\n ${colors.green}${colors.bold}Outstanding! No common security weaknesses or misconfigurations found.${colors.reset}\n`);
    } else {
      console.log(`\n ${colors.bold}DETECTION FINDINGS (${issues.length} Items):${colors.reset}\n`);
      issues.forEach((item, index) => {
        const badge = this.getBadge(item.severity);
        console.log(` ${index + 1}. ${badge} ${colors.bold}${item.title}${colors.reset} ${colors.dim}(${item.category})${colors.reset}`);
        console.log(`    ${colors.dim}Detail:${colors.reset} ${item.description}`);
        if (item.remediation && item.remediation !== 'No specific fix needed.') {
          console.log(`    ${colors.yellow}Fix:${colors.reset}    ${item.remediation}`);
        }
        console.log('');
      });
    }

    if (passed.length > 0) {
      console.log(colors.cyan + '-'.repeat(70) + colors.reset);
      console.log(` ${colors.bold}PASSED DEFENSIVE CHECKS (${passed.length} Items):${colors.reset}\n`);
      passed.forEach((item) => {
        console.log(`  ${colors.green}✓${colors.reset} ${colors.bold}${item.title}${colors.reset}: ${colors.dim}${item.description}${colors.reset}`);
      });
      console.log('');
    }

    console.log(colors.cyan + '='.repeat(70) + colors.reset + '\n');
  }

  static buildMarkdown(report) {
    const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, PASS: 5 };
    const findings = Array.isArray(report.findings) ? report.findings : [];
    const issues = findings
      .filter(f => f.severity !== 'PASS')
      .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || (b.scoreImpact || 0) - (a.scoreImpact || 0));
    const actionable = issues.filter(f => f.severity !== 'INFO');
    const infos = issues.filter(f => f.severity === 'INFO');
    const passed = findings.filter(f => f.severity === 'PASS');

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, PASS: 0 };
    for (const f of findings) {
      if (counts[f.severity] !== undefined) counts[f.severity] += 1;
    }

    const totalProbes = report.totalProbesExecuted || findings.length;
    const discoveredPages = Array.isArray(report.discoveredPages) ? report.discoveredPages : [];
    const discoveredApiRoutes = Array.isArray(report.discoveredApiRoutes) ? report.discoveredApiRoutes : [];

    let md = `# Kalasag Audit — AI-Ready Security Remediation Report\n\n`;

    // Direct, structured instructions so a developer can paste this whole file straight into an AI coding assistant
    md += `## Prompt / Instructions for AI Coding Assistant\n\n`;
    if (actionable.length > 0) {
      md += `> **Task:** Fix the **${actionable.length} verified security finding(s)** below for \`${report.targetUrl}\` in priority order (\`CRITICAL\` → \`HIGH\` → \`MEDIUM\` → \`LOW\`).\n`;
      md += `> **Rules:**\n`;
      md += `> 1. Inspect the actual codebase/server config before editing (e.g. \`.htaccess\`, \`web.config\`, Nginx/Apache conf, framework middleware, or layout templates).\n`;
      md += `> 2. Fix each item cleanly without breaking existing functionality or regressing any of the **Already Passing Controls** listed in Section 4.\n`;
      md += `> 3. Do not add duplicate headers if a reverse proxy or web server already sets them.\n`;
      md += `> 4. After applying fixes, summarize every changed file and provide a quick verification command for each item.\n\n`;
    } else {
      md += `> **Status:** No actionable vulnerabilities (\`CRITICAL\`/\`HIGH\`/\`MEDIUM\`/\`LOW\`) were detected on \`${report.targetUrl}\`. Review the optional informational notes below if desired.\n\n`;
    }

    md += `## 1. Scan Context\n\n`;
    md += `\`\`\`yaml\n`;
    md += `tool: Kalasag Audit v2.0\n`;
    md += `target_url: ${report.targetUrl}\n`;
    md += `hostname: ${report.hostname}\n`;
    md += `environment: ${report.isInternalHost ? 'internal_or_local' : 'public'}\n`;
    md += `scanned_at: ${report.scanTime}\n`;
    md += `checks_executed: ${totalProbes}\n`;
    md += `pages_crawled: ${discoveredPages.length || 1}\n`;
    md += `js_routes_discovered: ${discoveredApiRoutes.length}\n`;
    md += `score: ${report.score}/100\n`;
    md += `grade: ${report.grade}\n`;
    if (report.gradeCappedBy) {
      md += `grade_capped_by: ${report.gradeCappedBy}\n`;
    }
    md += `counts:\n`;
    md += `  critical: ${counts.CRITICAL}\n`;
    md += `  high: ${counts.HIGH}\n`;
    md += `  medium: ${counts.MEDIUM}\n`;
    md += `  low: ${counts.LOW}\n`;
    md += `  info: ${counts.INFO}\n`;
    md += `  passed: ${counts.PASS}\n`;
    md += `\`\`\`\n\n`;

    md += `## 2. Actionable Issues to Fix (${actionable.length})\n\n`;
    if (actionable.length === 0) {
      md += `No actionable security issues found.\n\n`;
    } else {
      actionable.forEach((issue, idx) => {
        const refId = `KLS-${String(idx + 1).padStart(3, '0')}`;
        md += `### [ ] ${refId} — [${issue.severity}] ${issue.title}\n`;
        md += `- **Category:** ${issue.category}\n`;
        md += `- **Score Impact:** -${issue.scoreImpact || 0} pts\n`;
        md += `- **Observed Evidence:** ${issue.description}\n`;
        md += `- **Required Fix:** ${issue.remediation || 'Review and harden this configuration.'}\n`;
        md += `- **Acceptance Criteria:** Re-running Kalasag Audit against \`${report.targetUrl}\` no longer reports "${issue.title}".\n\n`;
      });
    }

    if (infos.length > 0) {
      md += `## 3. Informational Notes (Optional / Zero Score Impact) (${infos.length})\n\n`;
      infos.forEach((item) => {
        md += `- **[INFO] ${item.title}** (${item.category}): ${item.description}`;
        if (item.remediation && item.remediation !== 'No specific fix needed.') {
          md += ` *Optional tidy-up:* ${item.remediation}`;
        }
        md += `\n`;
      });
      md += `\n`;
    }

    md += `## 4. Already Passing Controls — Do Not Regress (${passed.length})\n\n`;
    if (passed.length === 0) {
      md += `No passed checks recorded.\n`;
    } else {
      for (const p of passed) {
        md += `- [x] **${p.title}** (${p.category}): ${p.description}\n`;
      }
    }

    if (discoveredPages.length > 1 || discoveredApiRoutes.length > 0) {
      md += `\n## 5. Discovered Pages & API Routes\n\n`;
      if (discoveredPages.length > 0) {
        md += `### Crawled Pages (${discoveredPages.length})\n`;
        for (const p of discoveredPages) {
          md += `- \`${p.path || p.url}\` (HTTP ${p.status || 200}, source: ${p.source || 'crawl'}, forms: ${p.formsCount || 0})\n`;
        }
        md += `\n`;
      }
      if (discoveredApiRoutes.length > 0) {
        md += `### API / App Routes Found in JS Bundles (${discoveredApiRoutes.length})\n`;
        for (const r of discoveredApiRoutes) {
          md += `- \`${r}\`\n`;
        }
      }
    }

    return md;
  }

  static async saveMarkdownReport(report, outputDir = process.cwd()) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const cleanHost = (report.hostname || 'target').replace(/[^a-zA-Z0-9.-]/g, '_');
    const filename = `kalasag-report-${cleanHost}-${timestamp}.md`;
    const filepath = path.join(outputDir, filename);

    const md = this.buildMarkdown(report);
    await fs.writeFile(filepath, md, 'utf-8');
    return filepath;
  }
}
