// src/scanners/privacyRisk.ts — Privacy-risk scanner
import type { Finding } from '../types.js';

// Sensitive file patterns
const SENSITIVE_FILE_PATTERNS = [
  { pattern: /^\.env$/i, rule: 'env-file', severity: 'high' as const },
  { pattern: /^\.env\./i, rule: 'env-file', severity: 'high' as const },
  { pattern: /^secrets?\./i, rule: 'secrets-file', severity: 'high' as const },
  { pattern: /^credentials?\./i, rule: 'credentials-file', severity: 'high' as const },
  { pattern: /^id_rsa/i, rule: 'ssh-private-key', severity: 'critical' as const },
  { pattern: /^id_dsa/i, rule: 'ssh-private-key', severity: 'critical' as const },
  { pattern: /^id_ecdsa/i, rule: 'ssh-private-key', severity: 'critical' as const },
  { pattern: /^id_ed25519/i, rule: 'ssh-private-key', severity: 'critical' as const },
  { pattern: /\.pem$/i, rule: 'pem-file', severity: 'critical' as const },
  { pattern: /\.key$/i, rule: 'key-file', severity: 'critical' as const },
  { pattern: /^config\.json$/i, rule: 'config-file', severity: 'medium' as const },
  { pattern: /^service-account.*\.json$/i, rule: 'service-account-json', severity: 'critical' as const },
  { pattern: /\.p12$/i, rule: 'p12-file', severity: 'critical' as const },
  { pattern: /\.pfx$/i, rule: 'pfx-file', severity: 'critical' as const },
  { pattern: /\.keystore$/i, rule: 'keystore-file', severity: 'high' as const },
];

// Screenshot / photo patterns
const SCREENSHOT_PATTERNS = [
  { pattern: /screenshot/i, rule: 'screenshot-file', severity: 'medium' as const },
  { pattern: /photo/i, rule: 'photo-file', severity: 'low' as const },
  { pattern: /img_/i, rule: 'photo-file', severity: 'low' as const },
  { pattern: /image_/i, rule: 'photo-file', severity: 'low' as const },
  { pattern: /dsc_/i, rule: 'photo-file', severity: 'low' as const },
  { pattern: /img-\d/i, rule: 'photo-file', severity: 'low' as const },
];

// Log / chat export patterns
const LOG_PATTERNS = [
  { pattern: /\.log$/i, rule: 'log-file', severity: 'medium' as const },
  { pattern: /chat.*export/i, rule: 'chat-export', severity: 'medium' as const },
  { pattern: /export.*chat/i, rule: 'chat-export', severity: 'medium' as const },
  { pattern: /whatsapp.*export/i, rule: 'chat-export', severity: 'medium' as const },
  { pattern: /telegram.*export/i, rule: 'chat-export', severity: 'medium' as const },
];

export interface PrivacyRiskResult {
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  redactedEvidence: string;
  suggestedAction: string;
}

export function scanFilenameForPrivacyRisk(filePath: string): PrivacyRiskResult[] {
  const basename = filePath.split(/[/\\]/).pop() ?? filePath;
  const results: PrivacyRiskResult[] = [];

  for (const { pattern, rule, severity } of SENSITIVE_FILE_PATTERNS) {
    if (pattern.test(basename)) {
      results.push({
        rule,
        severity,
        redactedEvidence: `Sensitive file: ${basename}`,
        suggestedAction: getRiskAction(rule),
      });
    }
  }

  for (const { pattern, rule, severity } of SCREENSHOT_PATTERNS) {
    if (pattern.test(basename)) {
      results.push({
        rule,
        severity,
        redactedEvidence: `Screenshot/photo file: ${basename}`,
        suggestedAction: getRiskAction(rule),
      });
    }
  }

  for (const { pattern, rule, severity } of LOG_PATTERNS) {
    if (pattern.test(basename)) {
      results.push({
        rule,
        severity,
        redactedEvidence: `Log/chat export file: ${basename}`,
        suggestedAction: getRiskAction(rule),
      });
    }
  }

  return results;
}

/** Detect if a file looks like a log/stack trace based on content. */
export function scanContentForLogRisk(content: string): PrivacyRiskResult[] {
  const results: PrivacyRiskResult[] = [];
  const lines = content.split('\n');

  // Flag files with >100 lines that look like log output
  if (lines.length > 100) {
    const logIndicators = [
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,  // ISO timestamps
      /^\[\d{4}-\d{2}-\d{2}/,  // [2024-01-01 ...] format
      /^ERROR\s/i,
      /^WARN(?:ING)?\s/i,
      /^INFO\s/i,
      /^DEBUG\s/i,
      /at\s.+:\d+:\d+/,  // Stack trace frames
      /Traceback \(most recent call last\)/,
      /Exception in thread/,
    ];

    let logLineCount = 0;
    for (const line of lines) {
      for (const re of logIndicators) {
        if (re.test(line)) {
          logLineCount++;
          break;
        }
      }
    }

    // If >30% of lines look like log lines, flag it
    if (logLineCount > lines.length * 0.3) {
      results.push({
        rule: 'large-log-file',
        severity: 'medium',
        redactedEvidence: `Large log-like file (${lines.length} lines, ${logLineCount} log-pattern lines)`,
        suggestedAction: 'Review if this log file should be in a public repo. It may contain runtime info or errors.',
      });
    }
  }

  return results;
}

export function scanForPrivacyRiskFindings(
  content: string,
  filePath: string,
  account: string,
  repo: string,
  commit: string,
): Finding[] {
  const results: PrivacyRiskResult[] = [
    ...scanFilenameForPrivacyRisk(filePath),
    ...scanContentForLogRisk(content),
  ];

  return results.map((r) => ({
    account,
    repo,
    file: filePath,
    commit,
    rule: r.rule,
    severity: r.severity,
    redactedEvidence: r.redactedEvidence,
    suggestedAction: r.suggestedAction,
  }));
}

function getRiskAction(rule: string): string {
  const actions: Record<string, string> = {
    'env-file': 'Remove .env file from the repo. Use environment variables or a secrets manager.',
    'secrets-file': 'Remove secrets file from the repo.',
    'credentials-file': 'Remove credentials file from the repo.',
    'ssh-private-key': 'Remove SSH private key immediately. Rotate the key pair.',
    'pem-file': 'Remove .pem file from the repo. Rotate the certificate/key if it was valid.',
    'key-file': 'Remove key file from the repo. Rotate the key if it was valid.',
    'config-file': 'Review config.json for sensitive values.',
    'service-account-json': 'Remove service account JSON. Rotate the key if it was valid.',
    'p12-file': 'Remove .p12 file. Rotate the certificate if it was valid.',
    'pfx-file': 'Remove .pfx file. Rotate the certificate if it was valid.',
    'keystore-file': 'Remove keystore file. Rotate passwords if exposed.',
    'screenshot-file': 'Remove screenshot from the repo if it contains personal info.',
    'photo-file': 'Review photo for EXIF/personal data. Remove if sensitive.',
    'log-file': 'Remove log file from the repo if it contains runtime info.',
    'chat-export': 'Remove chat export from the repo if it contains personal conversations.',
    'large-log-file': 'Remove large log file from the repo.',
  };
  return actions[rule] ?? 'Review and remove if sensitive.';
}