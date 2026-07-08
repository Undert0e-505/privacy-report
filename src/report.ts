// src/report.ts — Markdown report generator
import type { Finding, ScanResult } from './types.js';
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

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