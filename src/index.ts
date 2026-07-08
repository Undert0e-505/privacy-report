// src/index.ts — CLI entry point (scan/report commands)
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { loadConfig, getEnabledAccounts, getAccountById } from './config.js';
import { GitHubClient } from './github.js';
import { StateManager } from './state.js';
import { generateReport, writeReport, summarizeReport } from './report.js';
import { scanForSecretFindings } from './scanners/secrets.js';
import { scanImageExif, exifToFindings, isImageFile } from './scanners/exif.js';
import { scanForPiiFindings, isScannableFile } from './scanners/pii.js';
import { scanForPrivacyRiskFindings } from './scanners/privacyRisk.js';
import { scanForKeywordFindings } from './scanners/keywords.js';
import { sendReportEmail } from './email.js';
import type { Finding, ScanResult } from './types.js';

function parseArgs(args: string[]): { command: string; account?: string; full: boolean } {
  const command = args[0] ?? '';
  let account: string | undefined;
  let full = false;

  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--account' && i + 1 < args.length) {
      account = args[i + 1];
      i++;
    } else if (args[i] === '--full') {
      full = true;
    }
  }

  return { command, account, full };
}

async function runScan(opts: { account?: string; full: boolean }): Promise<void> {
  const config = loadConfig();
  const accounts = opts.account
    ? [getAccountById(config, opts.account)].filter((a) => a !== undefined)
    : getEnabledAccounts(config);

  if (accounts.length === 0) {
    console.error('No accounts to scan. Check config/accounts.yml or --account flag.');
    process.exit(1);
  }

  const token = process.env.GITHUB_TOKEN;
  const gh = new GitHubClient(token);
  const state = new StateManager();
  const findings: Finding[] = [];
  let reposScanned = 0;
  let commitsScanned = 0;
  const startedAt = new Date().toISOString();

  for (const account of accounts) {
    console.log(`\n=== Scanning account ${account.id} (${account.githubUser}) ===`);
    const scanRunId = state.startScanRun(account.id);

    // List repos
    const repos = await gh.listRepos(account.githubUser, config.scan);
    console.log(`Found ${repos.length} repos for ${account.githubUser}`);

    for (const repo of repos) {
      console.log(`\n  Repo: ${repo.fullName}`);
      reposScanned++;

      const [owner, repoName] = repo.fullName.split('/');
      const lastSha = opts.full ? null : state.getRepoLastSha(account.id, repo.fullName);

      // List commits
      const commits = await gh.listCommits(owner, repoName, lastSha);
      console.log(`    New commits: ${commits.length}`);

      for (const commit of commits) {
        commitsScanned++;
        console.log(`    Commit: ${commit.sha.slice(0, 7)} — ${commit.message.slice(0, 50)}`);

        // Get tree
        const tree = await gh.getCommitTree(owner, repoName, commit.sha);

        for (const file of tree) {
          // Skip files that are too large
          if (file.size > config.scan.maxFileBytes) {
            console.log(`      Skip (too large): ${file.path} (${file.size} bytes)`);
            continue;
          }

          // Image files → EXIF scan
          if (isImageFile(file.path)) {
            console.log(`      EXIF scan: ${file.path}`);
            const buf = await gh.downloadFile(owner, repoName, file.path, commit.sha);
            if (buf) {
              const exifResult = await scanImageExif(buf, file.path.split(/[/\\]/).pop() ?? 'image');
              const exifFindings = exifToFindings(exifResult, file.path, account.id, repo.fullName, config.scan);
              exifFindings.forEach((f) => (f.commit = commit.sha));
              findings.push(...exifFindings);
            }
            continue;
          }

          // Text files → secret + PII + privacy risk scan
          if (!isScannableFile(file.path)) continue;

          console.log(`      Scanning: ${file.path}`);
          const contentResult = await gh.getFileContent(owner, repoName, file.path, commit.sha);
          if (!contentResult || contentResult.isBinary) continue;
          const content = contentResult.content;

          // Secret scan
          const secretFindings = scanForSecretFindings(content, file.path, account.id, repo.fullName, commit.sha, config.scan);
          findings.push(...secretFindings);

          // PII scan
          const piiFindings = scanForPiiFindings(content, file.path, account.id, repo.fullName, commit.sha);
          findings.push(...piiFindings);

          // Privacy risk scan
          const riskFindings = scanForPrivacyRiskFindings(content, file.path, account.id, repo.fullName, commit.sha);
          findings.push(...riskFindings);

          // Custom keyword scan (per-account keywords)
          if (account.keywords && account.keywords.length > 0) {
            const keywordFindings = scanForKeywordFindings(content, file.path, account.id, repo.fullName, commit.sha, account.keywords);
            findings.push(...keywordFindings);
          }
        }
      }

      // Update state with last commit SHA
      if (commits.length > 0) {
        const lastCommit = commits[0];
        state.setRepoLastSha(account.id, repo.fullName, lastCommit.sha, new Date().toISOString());
      }
    }

    state.finishScanRun(scanRunId, reposScanned, commitsScanned, findings.length);
  }

  state.close();

  const finishedAt = new Date().toISOString();
  const scanResult: ScanResult = {
    startedAt,
    finishedAt,
    accountsScanned: accounts.length,
    reposScanned,
    commitsScanned,
    findings,
  };

  const report = generateReport(scanResult);
  const reportPath = writeReport(report);
  console.log(`\n=== Scan complete ===`);
  console.log(`Findings: ${findings.length}`);
  console.log(`Report written to: ${reportPath}`);

  // Email per-account reports to each account's contactEmail
  for (const account of accounts) {
    if (!account.contactEmail || account.contactEmail.startsWith('REPLACE_')) {
      console.log(`[Email] Account ${account.id}: no contact email configured — skipping.`);
      continue;
    }

    const accountFindings = findings.filter((f) => f.account === account.id);
    if (accountFindings.length === 0) {
      console.log(`[Email] Account ${account.id}: no findings — skipping email.`);
      continue;
    }

    const accountReport = generateReport({
      startedAt,
      finishedAt,
      accountsScanned: 1,
      reposScanned: reposScanned, // per-account not tracked separately; show total
      commitsScanned: commitsScanned,
      findings: accountFindings,
    });
    const subject = `Privacy Report for ${account.id} — ${accountFindings.length} finding${accountFindings.length === 1 ? '' : 's'} — ${new Date().toISOString().slice(0, 10)}`;
    await sendReportEmail(account.contactEmail, subject, accountReport);
  }
}

function runReport(): void {
  const state = new StateManager();
  const lastRun = state.getLastScanRun();
  state.close();

  if (!lastRun || !lastRun.finishedAt) {
    console.log('No completed scan runs found. Run `npm run scan` first.');
    return;
  }

  // Find the latest report file
  const reportsDir = resolve(process.cwd(), 'reports');
  let files: string[] = [];
  try {
    files = readdirSync(reportsDir).filter((f) => f.endsWith('.md')).sort().reverse();
  } catch {
    // reports dir doesn't exist
  }

  if (files.length === 0) {
    console.log('No report files found. Run `npm run scan` first.');
    return;
  }

  const reportContent = readFileSync(resolve(reportsDir, files[0]), 'utf-8');
  const summary = summarizeReport(reportContent);
  console.log(summary);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const { command, account, full } = parseArgs(args);

  switch (command) {
    case 'scan':
      await runScan({ account, full });
      break;
    case 'report':
      runReport();
      break;
    case 'help':
    case '--help':
    case '-h':
      console.log('Usage: npm run scan [-- --account M] [-- --full]');
      console.log('       npm run report');
      console.log('       npm run test');
      console.log('       npm run build');
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.error('Use "scan", "report", or "help"');
      process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});