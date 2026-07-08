// src/report.ts — Markdown report generator
import type { Finding, ScanResult } from './types.js';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

/** Group findings by repo for the agent instructions block. */
function groupFindingsByRepo(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.repo;
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push(f);
  }
  return map;
}

/** Generate a copy-paste-ready prompt for Caesar to fix the issues. */
function generateAgentInstructions(findings: Finding[]): string {
  if (findings.length === 0) return '';

  const byRepo = groupFindingsByRepo(findings);
  const lines: string[] = [];
  lines.push('## Agent Instructions (copy-paste to Caesar)');
  lines.push('');
  lines.push('```');
  lines.push('A privacy scan of your public GitHub repos found the following issues.');
  lines.push('Please fix each one. Do not delete the files — just remove the sensitive');
  lines.push('content and replace with placeholders or remove the line entirely.');
  lines.push('');

  for (const [repo, repoFindings] of byRepo) {
    const [owner, repoName] = repo.split('/');
    lines.push(`## Repo: ${repo}`);
    lines.push('');

    // Deduplicate by file+rule (same issue across commits = one fix)
    const seen = new Set<string>();
    const uniqueFindings = repoFindings.filter((f) => {
      const key = `${f.file}:${f.rule}:${f.line ?? 0}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    for (const f of uniqueFindings) {
      lines.push(`### ${f.severity.toUpperCase()}: ${f.rule} in ${f.file}${f.line ? ` (line ${f.line})` : ''}`);
      lines.push(`- What was found: ${f.redactedEvidence}`);
      lines.push(`- Action: ${f.suggestedAction}`);
      lines.push(`- Commit to check: ${f.commit?.slice(0, 7) ?? 'N/A'}`);
      lines.push('');
    }
  }

  lines.push('Once fixed, commit and push. Do not rewrite history unless instructed.');
  lines.push('```');
  lines.push('');
  return lines.join('\n');
}

export function generateReport(scanResult: ScanResult): string {
  const { findings } = scanResult;
  const severityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const f of findings) {
    severityCounts[f.severity]++;
  }

  const lines: string[] = [];

  lines.push('# Privacy Report');
  lines.push(`Generated: ${scanResult.finishedAt}`);
  lines.push('');
  lines.push('## Summary');
  lines.push(`- Accounts scanned: ${scanResult.accountsScanned}`);
  lines.push(`- Repositories scanned: ${scanResult.reposScanned}`);
  lines.push(`- New commits scanned: ${scanResult.commitsScanned}`);
  lines.push(`- Findings: ${findings.length}`);
  lines.push(`  - Critical: ${severityCounts.critical}`);
  lines.push(`  - High: ${severityCounts.high}`);
  lines.push(`  - Medium: ${severityCounts.medium}`);
  lines.push(`  - Low: ${severityCounts.low}`);
  lines.push('');

  if (findings.length === 0) {
    lines.push('No findings. All clear.');
    lines.push('');
    return lines.join('\n');
  }

  // Agent instructions block (copy-paste for Caesar)
  lines.push(generateAgentInstructions(findings));

  lines.push('## Findings');
  lines.push('');

  // Sort findings by severity (critical first)
  const sorted = [...findings].sort((a, b) => {
    return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  });

  for (const f of sorted) {
    const severityLabel = f.severity.toUpperCase();
    lines.push(`### ${severityLabel}: ${f.rule}`);
    lines.push(`- Account: ${f.account}`);
    lines.push(`- Repo: ${f.repo}`);
    lines.push(`- File: ${f.file}`);
    if (f.line) lines.push(`- Line: ${f.line}`);
    if (f.commit) lines.push(`- Commit: ${f.commit}`);
    lines.push(`- Rule: ${f.rule}`);
    lines.push(`- Redacted evidence: ${f.redactedEvidence}`);
    if (f.metadata) {
      const metaEntries = Object.entries(f.metadata);
      if (metaEntries.length > 0) {
        lines.push(`- Metadata: ${metaEntries.map(([k, v]) => `${k}=${v}`).join(', ')}`);
      }
    }
    lines.push(`- Suggested action: ${f.suggestedAction}`);
    lines.push('');
  }

  return lines.join('\n');
}

export function writeReport(report: string, outputDir?: string): string {
  const dir = outputDir ?? resolve(process.cwd(), 'reports');
  mkdirSync(dir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `privacy-report-${timestamp}.md`;
  const fullPath = resolve(dir, filename);
  writeFileSync(fullPath, report, 'utf-8');
  return fullPath;
}

export function summarizeReport(report: string): string {
  // Extract the Summary section for quick display
  const summaryMatch = report.match(/## Summary[\s\S]*?(?=\n## |\n$|$)/);
  if (summaryMatch) return summaryMatch[0].trim();
  return 'No summary available. Run `npm run scan` to generate a report.';
}