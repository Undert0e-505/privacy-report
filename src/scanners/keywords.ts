// src/scanners/keywords.ts — Per-account custom keyword scanner
import type { Finding } from '../types.js';

export interface KeywordScanResult {
  rule: string;
  severity: 'medium' | 'low';
  line: number;
  match: string;
}

/**
 * Scan content for custom keywords configured per account.
 * Matches whole words only (case-insensitive).
 */
export function scanTextForKeywords(
  content: string,
  keywords: string[],
): KeywordScanResult[] {
  if (!keywords || keywords.length === 0) return [];

  const results: KeywordScanResult[] = [];
  const lines = content.split('\n');

  // Build a single regex from all keywords for efficiency
  // Escape regex special chars in keywords
  const escaped = keywords
    .map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .filter((k) => k.length > 0);

  if (escaped.length === 0) return [];

  // Use word boundaries for short keywords, substring for longer ones
  const pattern = new RegExp(`(${escaped.join('|')})`, 'gi');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(line)) !== null) {
      // Determine severity: keywords like "password", "secret", "token",
      // "private_key", "credentials" are medium; others are low
      const lower = match[0].toLowerCase();
      const severity = isHighRiskKeyword(lower) ? 'medium' : 'low';

      results.push({
        rule: 'custom-keyword',
        severity,
        line: i + 1,
        match: match[0],
      });
    }
  }

  return results;
}

function isHighRiskKeyword(keyword: string): boolean {
  const highRisk = [
    'password', 'secret', 'token', 'api_key', 'private_key',
    'credentials', '.env', 'id_rsa', 'private key',
  ];
  return highRisk.some((k) => keyword.includes(k));
}

export function scanForKeywordFindings(
  content: string,
  filePath: string,
  account: string,
  repo: string,
  commit: string,
  keywords: string[],
): Finding[] {
  const scanResults = scanTextForKeywords(content, keywords);
  const seen = new Set<string>();
  const findings: Finding[] = [];

  for (const r of scanResults) {
    // Deduplicate per line (same keyword may match multiple times)
    const key = `${r.line}:${r.match.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);

    findings.push({
      account,
      repo,
      file: filePath,
      line: r.line,
      commit,
      rule: 'custom-keyword',
      severity: r.severity,
      redactedEvidence: `Keyword match: "${r.match}"`,
      suggestedAction: 'Review this keyword occurrence. Remove if it exposes sensitive information.',
    });
  }

  return findings;
}