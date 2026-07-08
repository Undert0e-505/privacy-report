// src/scanners/pii.ts — Personal info scanner
import type { Finding } from '../types.js';

export interface PiiRule {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  pattern: RegExp;
  description: string;
}

const PII_RULES: PiiRule[] = [
  {
    name: 'email-address',
    severity: 'medium',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    description: 'Email address',
  },
  {
    name: 'uk-phone',
    severity: 'medium',
    pattern: /\b(?:\+44|0)(?:\s*\d){9,10}\b/g,
    description: 'UK phone number',
  },
  {
    name: 'us-phone',
    severity: 'medium',
    pattern: /\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    description: 'US phone number',
  },
  {
    name: 'uk-postcode',
    severity: 'medium',
    pattern: /\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b/gi,
    description: 'UK postcode',
  },
  {
    name: 'discord-handle',
    severity: 'low',
    pattern: /\bdiscord\.gg\/[A-Za-z0-9]+\b/gi,
    description: 'Discord invite link',
  },
  {
    name: 'discord-username',
    severity: 'low',
    pattern: /\b([A-Za-z0-9_]{2,32})#\d{4}\b/g,
    description: 'Discord username with discriminator',
  },
  {
    name: 'ipv4-address',
    severity: 'low',
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    description: 'IPv4 address',
  },
];

// Suspicious filenames that may contain PII
const SUSPICIOUS_FILENAMES = [
  /password/i, /credentials/i, /contact/i, /address/i, /personal/i,
  /private/i, /phone/i, /email/i, /bank/i, /passport/i,
  /license/i, /invoice/i, /statement/i, /contract/i, /lease/i,
  /medical/i, /health/i, /insurance/i,
];

const SCANNABLE_EXTENSIONS = [
  '.md', '.txt', '.json', '.yaml', '.yml', '.xml', '.html',
  '.csv', '.log', '.env', '.ts', '.js', '.py', '.rb', '.go',
  '.rs', '.java', '.c', '.cpp', '.h', '.sh', '.sql', '.conf',
  '.cfg', '.ini', '.properties', '',
];

export function isScannableFile(path: string): boolean {
  const lower = path.toLowerCase();
  // Always scannable: no extension or known text extensions
  return SCANNABLE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export function hasSuspiciousFilename(path: string): boolean {
  const basename = path.split(/[/\\]/).pop() ?? path;
  return SUSPICIOUS_FILENAMES.some((re) => re.test(basename));
}

export interface PiiScanResult {
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  line: number;
  match: string;
}

export function scanTextForPii(content: string): PiiScanResult[] {
  const results: PiiScanResult[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of PII_RULES) {
      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.pattern.exec(line)) !== null) {
        // Skip obvious false positives
        if (isPiiFalsePositive(match[0], line)) continue;
        results.push({
          rule: rule.name,
          severity: rule.severity,
          line: i + 1,
          match: match[0],
        });
      }
    }
  }

  return results;
}

function isPiiFalsePositive(match: string, line: string): boolean {
  // Skip example.com emails
  if (match.includes('@example.com') || match.includes('@test.com') || match.includes('@localhost')) {
    return true;
  }
  // Skip npm package version-like patterns
  if (match.includes('@') && match.match(/\d+\.\d+\.\d+/)) {
    return true;
  }
  // Skip common non-email @ patterns (like decorators @Component)
  if (match.startsWith('@') && !match.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\./)) {
    return true;
  }
  // Skip 127.0.0.1 and 0.0.0.0
  if (match === '127.0.0.1' || match === '0.0.0.0' || match === '255.255.255.255') {
    return true;
  }
  return false;
}

export function scanForPiiFindings(
  content: string,
  filePath: string,
  account: string,
  repo: string,
  commit: string,
): Finding[] {
  const findings: Finding[] = [];
  const scanResults = scanTextForPii(content);

  for (const r of scanResults) {
    findings.push({
      account,
      repo,
      file: filePath,
      line: r.line,
      commit,
      rule: r.rule,
      severity: r.severity,
      redactedEvidence: redactPii(r.match, r.rule),
      suggestedAction: getPiiAction(r.rule),
    });
  }

  // Also check for suspicious filenames
  if (hasSuspiciousFilename(filePath)) {
    findings.push({
      account,
      repo,
      file: filePath,
      commit,
      rule: 'suspicious-filename',
      severity: 'low',
      redactedEvidence: `Filename may contain personal data: ${filePath.split(/[/\\]/).pop()}`,
      suggestedAction: 'Review the file. If it contains personal data, remove it from the repo.',
    });
  }

  return findings;
}

function redactPii(value: string, rule: string): string {
  switch (rule) {
    case 'email-address': {
      const [user, domain] = value.split('@');
      return user.slice(0, 2) + '***@' + domain;
    }
    case 'uk-phone':
    case 'us-phone':
      return value.slice(0, 4) + '...' + value.slice(-2);
    case 'uk-postcode':
      return value.slice(0, 2) + '***' + value.slice(-2);
    case 'discord-username':
      return value.slice(0, 3) + '***' + value.slice(-3);
    default:
      return value;
  }
}

function getPiiAction(rule: string): string {
  const actions: Record<string, string> = {
    'email-address': 'Review if this email should be in a public repo. Remove if personal.',
    'uk-phone': 'Remove phone number from public repo content.',
    'us-phone': 'Remove phone number from public repo content.',
    'uk-postcode': 'Remove address information from public repo content.',
    'discord-handle': 'Review if this Discord link should be public.',
    'discord-username': 'Remove Discord handle from public repo content.',
    'ipv4-address': 'Check if this IP address should be in a public repo.',
  };
  return actions[rule] ?? 'Review and remove if personal information.';
}