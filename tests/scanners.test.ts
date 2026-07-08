// tests/scanners.test.ts — Tests for privacy-report scanners
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanTextForSecrets, redactSecret, scanForSecretFindings } from '../src/scanners/secrets.js';
import { parseExifOutput, exifToFindings, isImageFile } from '../src/scanners/exif.js';
import { scanTextForPii, scanForPiiFindings, hasSuspiciousFilename } from '../src/scanners/pii.js';
import { scanFilenameForPrivacyRisk, scanContentForLogRisk, scanForPrivacyRiskFindings } from '../src/scanners/privacyRisk.js';
import { generateReport, summarizeReport } from '../src/report.js';
import type { Finding, ScanResult, ScanConfig } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(__dirname, '..', 'fixtures');

function readFixture(name: string): string {
  return readFileSync(resolve(fixturesDir, name), 'utf-8');
}

const defaultScanConfig: ScanConfig = {
  includeForks: false,
  includeArchived: false,
  maxFileBytes: 1_000_000,
  redactSecrets: true,
  storeExactGps: false,
};

describe('Secret scanner', () => {
  it('detects fake Google API key', () => {
    const content = readFixture('fake-api-key.txt');
    const results = scanTextForSecrets(content, 'fixtures/fake-api-key.txt', { redactSecrets: true });
    expect(results.length).toBeGreaterThan(0);
    const googleKey = results.find((r) => r.rule === 'google-api-key');
    expect(googleKey).toBeDefined();
    expect(googleKey!.severity).toBe('high');
    // Redacted: should not contain full key
    expect(googleKey!.redactedMatch).not.toContain('FakeFakeFakeFakeFakeFake');
    expect(googleKey!.redactedMatch).toContain('...');
  });

  it('detects fake RSA private key', () => {
    const content = readFixture('fake-private-key.pem');
    const results = scanTextForSecrets(content, 'fixtures/fake-private-key.pem');
    const privateKey = results.find((r) => r.rule === 'private-key-block');
    expect(privateKey).toBeDefined();
    expect(privateKey!.severity).toBe('critical');
  });

  it('detects fake .env values', () => {
    const content = readFixture('fake-env.txt');
    const results = scanTextForSecrets(content, 'fixtures/fake-env.txt');
    // Should detect database URL and env-style secrets
    const dbUrl = results.find((r) => r.rule === 'database-url');
    expect(dbUrl).toBeDefined();
    expect(dbUrl!.severity).toBe('critical');

    const envSecret = results.find((r) => r.rule === 'env-secret-value');
    expect(envSecret).toBeDefined();
    expect(envSecret!.severity).toBe('high');
  });

  it('does NOT flag harmless code', () => {
    const content = readFixture('harmless-code.ts');
    const results = scanTextForSecrets(content, 'fixtures/harmless-code.ts');
    // Should have zero critical or high findings
    const criticalOrHigh = results.filter((r) => r.severity === 'critical' || r.severity === 'high');
    expect(criticalOrHigh.length).toBe(0);
  });

  it('redacts secrets properly', () => {
    const key = 'AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678';
    const redacted = redactSecret(key);
    expect(redacted).toContain('AIzaSy');
    expect(redacted).toContain('...');
    expect(redacted).toContain('5678');
    expect(redacted).toContain('...');
    // Full key should not appear in redacted version
    expect(redacted).not.toBe(key);
  });
});

describe('EXIF scanner', () => {
  it('detects GPS metadata from simulated exiftool output', () => {
    const exifJson = readFixture('simulated-exif-gps.json');
    const result = parseExifOutput(exifJson);
    expect(result.hasGps).toBe(true);
    expect(result.gpsLat).toBeDefined();
    expect(result.gpsLng).toBeDefined();
    expect(result.cameraModel).toBe('iPhone 14 Pro');
    expect(result.ownerName).toBe('John Doe');
    expect(result.deviceSerial).toBe('ABC123DEF456');
  });

  it('does not flag images without EXIF', () => {
    const exifJson = readFixture('simulated-exif-none.json');
    const result = parseExifOutput(exifJson);
    expect(result.hasGps).toBe(false);
    expect(result.cameraModel).toBeUndefined();
    expect(result.ownerName).toBeUndefined();
  });

  it('converts EXIF results to findings with redacted GPS by default', () => {
    const exifJson = readFixture('simulated-exif-gps.json');
    const result = parseExifOutput(exifJson);
    const findings = exifToFindings(result, 'photo.jpg', 'M', 'owner/repo', defaultScanConfig);

    const gpsFinding = findings.find((f) => f.rule === 'gps-metadata');
    expect(gpsFinding).toBeDefined();
    expect(gpsFinding!.severity).toBe('high');
    // GPS should be redacted by default
    expect(gpsFinding!.redactedEvidence).not.toMatch(/51\.5074/);
    expect(gpsFinding!.redactedEvidence).toContain('redacted');
  });

  it('stores exact GPS when configured', () => {
    const exifJson = readFixture('simulated-exif-gps.json');
    const result = parseExifOutput(exifJson);
    const config: ScanConfig = { ...defaultScanConfig, storeExactGps: true };
    const findings = exifToFindings(result, 'photo.jpg', 'M', 'owner/repo', config);
    const gpsFinding = findings.find((f) => f.rule === 'gps-metadata');
    expect(gpsFinding).toBeDefined();
    expect(gpsFinding!.redactedEvidence).toContain('51.5074');
  });

  it('identifies image files correctly', () => {
    expect(isImageFile('photo.jpg')).toBe(true);
    expect(isImageFile('photo.jpeg')).toBe(true);
    expect(isImageFile('photo.png')).toBe(true);
    expect(isImageFile('photo.webp')).toBe(true);
    expect(isImageFile('photo.heic')).toBe(true);
    expect(isImageFile('code.ts')).toBe(false);
    expect(isImageFile('readme.md')).toBe(false);
  });
});

describe('PII scanner', () => {
  it('detects email addresses', () => {
    const content = readFixture('markdown-with-email.md');
    const results = scanTextForPii(content);
    const email = results.find((r) => r.rule === 'email-address');
    expect(email).toBeDefined();
    expect(email!.severity).toBe('medium');
  });

  it('detects UK phone numbers', () => {
    const content = readFixture('markdown-with-email.md');
    const results = scanTextForPii(content);
    const phone = results.find((r) => r.rule === 'uk-phone');
    expect(phone).toBeDefined();
  });

  it('detects UK postcodes', () => {
    const content = readFixture('markdown-with-email.md');
    const results = scanTextForPii(content);
    const postcode = results.find((r) => r.rule === 'uk-postcode');
    expect(postcode).toBeDefined();
  });

  it('detects Discord handles', () => {
    const content = readFixture('markdown-with-email.md');
    const results = scanTextForPii(content);
    const discord = results.find((r) => r.rule === 'discord-username');
    expect(discord).toBeDefined();
  });

  it('flags suspicious filenames', () => {
    expect(hasSuspiciousFilename('passwords.txt')).toBe(true);
    expect(hasSuspiciousFilename('credentials.json')).toBe(true);
    expect(hasSuspiciousFilename('normal-code.ts')).toBe(false);
  });
});

describe('Privacy risk scanner', () => {
  it('flags .env filenames', () => {
    const results = scanFilenameForPrivacyRisk('.env');
    expect(results.length).toBeGreaterThan(0);
    const envResult = results.find((r) => r.rule === 'env-file');
    expect(envResult).toBeDefined();
    expect(envResult!.severity).toBe('high');
  });

  it('flags .env.local filenames', () => {
    const results = scanFilenameForPrivacyRisk('.env.local');
    expect(results.length).toBeGreaterThan(0);
    const envResult = results.find((r) => r.rule === 'env-file');
    expect(envResult).toBeDefined();
  });

  it('flags credentials files', () => {
    const results = scanFilenameForPrivacyRisk('credentials.json');
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r) => r.rule === 'credentials-file')).toBe(true);
  });

  it('flags SSH private keys', () => {
    const results = scanFilenameForPrivacyRisk('id_rsa');
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r) => r.rule === 'ssh-private-key')).toBe(true);
  });

  it('flags .pem files', () => {
    const results = scanFilenameForPrivacyRisk('cert.pem');
    expect(results.some((r) => r.rule === 'pem-file')).toBe(true);
  });

  it('flags service account JSON', () => {
    const results = scanFilenameForPrivacyRisk('service-account-prod.json');
    expect(results.some((r) => r.rule === 'service-account-json')).toBe(true);
  });

  it('flags large log-like files', () => {
    const logContent = Array.from({ length: 150 }, (_, i) =>
      `2024-06-15T10:30:${String(i % 60).padStart(2, '0')}Z ERROR Something went wrong at line ${i}`,
    ).join('\n');
    const results = scanContentForLogRisk(logContent);
    expect(results.some((r) => r.rule === 'large-log-file')).toBe(true);
  });

  it('does not flag normal code as log-like', () => {
    const code = readFixture('harmless-code.ts');
    const results = scanContentForLogRisk(code);
    expect(results.length).toBe(0);
  });

  it('generates findings with all required fields', () => {
    const findings = scanForPrivacyRiskFindings(
      'normal content',
      '.env',
      'M',
      'owner/repo',
      'abc1234',
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].account).toBe('M');
    expect(findings[0].repo).toBe('owner/repo');
    expect(findings[0].file).toBe('.env');
    expect(findings[0].commit).toBe('abc1234');
    expect(findings[0].rule).toBeDefined();
    expect(findings[0].severity).toBeDefined();
    expect(findings[0].redactedEvidence).toBeDefined();
    expect(findings[0].suggestedAction).toBeDefined();
  });
});

describe('Report generation', () => {
  it('produces valid markdown with summary', () => {
    const scanResult: ScanResult = {
      startedAt: '2024-01-01T00:00:00Z',
      finishedAt: '2024-01-01T00:05:00Z',
      accountsScanned: 1,
      reposScanned: 3,
      commitsScanned: 5,
      findings: [
        {
          account: 'M',
          repo: 'owner/repo',
          file: 'config/.env',
          line: 1,
          commit: 'abc1234',
          rule: 'env-file',
          severity: 'high',
          redactedEvidence: 'Sensitive file: .env',
          suggestedAction: 'Remove .env file from the repo.',
        },
      ],
    };

    const report = generateReport(scanResult);

    expect(report).toContain('# Privacy Report');
    expect(report).toContain('## Summary');
    expect(report).toContain('Accounts scanned: 1');
    expect(report).toContain('Repositories scanned: 3');
    expect(report).toContain('New commits scanned: 5');
    expect(report).toContain('Findings: 1');
    expect(report).toContain('High: 1');
    expect(report).toContain('## Findings');
    expect(report).toContain('### HIGH: env-file');
    expect(report).toContain('Account: M');
    expect(report).toContain('Repo: owner/repo');
    expect(report).toContain('File: config/.env');
  });

  it('handles zero findings', () => {
    const scanResult: ScanResult = {
      startedAt: '2024-01-01T00:00:00Z',
      finishedAt: '2024-01-01T00:05:00Z',
      accountsScanned: 1,
      reposScanned: 2,
      commitsScanned: 3,
      findings: [],
    };

    const report = generateReport(scanResult);
    expect(report).toContain('No findings. All clear.');
  });

  it('summarizes report', () => {
    const scanResult: ScanResult = {
      startedAt: '2024-01-01T00:00:00Z',
      finishedAt: '2024-01-01T00:05:00Z',
      accountsScanned: 2,
      reposScanned: 5,
      commitsScanned: 10,
      findings: [],
    };

    const report = generateReport(scanResult);
    const summary = summarizeReport(report);
    expect(summary).toContain('Accounts scanned: 2');
    expect(summary).toContain('Repositories scanned: 5');
  });
});

describe('Redaction', () => {
  it('full secret is not in scan output', () => {
    const content = 'API_KEY=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678';
    const findings = scanForSecretFindings(
      content,
      'fixtures/test.txt',
      'M',
      'owner/repo',
      'abc123',
      defaultScanConfig,
    );

    // Gather all redacted evidence
    const allEvidence = findings.map((f) => f.redactedEvidence).join(' ');
    // The full key should NOT appear
    expect(allEvidence).not.toContain('AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678');
    // But the redacted version should contain ...
    expect(allEvidence).toContain('...');
  });
});