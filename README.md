# privacy-report

A **defensive privacy auditing tool** that scans public GitHub content from configured accounts and produces private reports.

## Purpose

This tool helps you monitor your own public GitHub presence for accidentally committed secrets, personal information, and privacy risks. It is designed for account owners who want to audit their own repos — not for targeting third parties.

## Hard boundaries

- **Passive scanning only.** Only public GitHub content. Only accounts configured by us.
- **No exploit attempts.** No vulnerability probing. No password/API-key validation against third-party services.
- **Redact by default.** Full secrets are never printed in reports.
- **Reports stay private.** Reports are committed to this private repo, never published or shared publicly.
- **Respect GitHub API rate limits.** Uses conditional requests and ETags where possible.

## Setup

### Prerequisites

- Node.js 20+
- Optional: `exiftool` installed for EXIF scanning (gracefully skipped if not available)
- Optional: `gitleaks` or `trufflehog` installed for enhanced secret scanning

### Installation

```bash
git clone <repo-url>
cd privacy-report
npm install
```

### Configuration

Edit `config/accounts.yml` to specify which GitHub accounts to monitor:

```yaml
accounts:
  - id: M
    githubUser: "your-github-username"
    enabled: true

scan:
  includeForks: false
  includeArchived: false
  maxFileBytes: 1000000
  redactSecrets: true
  storeExactGps: false
```

Set the `GITHUB_TOKEN` environment variable for API authentication (a fine-grained PAT with read access to public repos is sufficient):

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

## Usage

### Scan configured accounts

```bash
npm run scan
```

### Scan a specific account only

```bash
npm run scan -- --account M
```

### Full rescan (ignore state, rescan everything)

```bash
npm run scan -- --full
```

### Print latest report summary

```bash
npm run report
```

### Run tests

```bash
npm run test
```

### Build

```bash
npm run build
```

## Scanners

### 1. Secret scanner (`src/scanners/secrets.ts`)

Regex-based detection for:
- Google API keys (`AIza...`)
- AWS access keys (`AKIA...`) and secret keys
- Private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- `.env`-style secret values
- Database URLs with credentials
- Discord webhook tokens
- GitHub tokens (`ghp_`, `gho_`, `ghs_`, `ghu_`)
- OpenAI keys (`sk-`)
- Anthropic keys (`sk-ant-`)
- Azure keys
- GCP service account JSON
- Bearer tokens
- Generic high-entropy strings in secret-looking context

All matches are redacted in reports: first 6 + last 4 characters shown, middle replaced with `...`.

### 2. EXIF/media scanner (`src/scanners/exif.ts`)

Scans image files (jpg, jpeg, png, webp, heic) for:
- GPS coordinates (reported but redacted by default)
- Device serial numbers
- Owner names
- Camera models
- Software metadata
- Timestamps

Uses `exiftool` if available. Downloads images to a temp directory, scans, then cleans up.

### 3. Personal info scanner (`src/scanners/pii.ts`)

Detects:
- Email addresses
- UK and US phone numbers
- UK postcodes
- Discord handles and invite links
- IPv4 addresses
- Suspicious filenames (password, credentials, contact, etc.)

### 4. Privacy-risk scanner (`src/scanners/privacyRisk.ts`)

Flags:
- Sensitive files: `.env`, `secrets.*`, `credentials.*`, `id_rsa`, `*.pem`, `*.key`, `service-account*.json`
- Screenshots and photos
- Log files and chat exports
- Large pasted logs and stack traces (>100 lines with log-like content)

## Severity levels

| Severity | Examples |
|----------|----------|
| Critical | Private key, live credential, auth token, database URL |
| High | `.env` file, service account JSON, webhook URL, GPS in image |
| Medium | Email, phone, address, school, personal metadata |
| Low | Usernames, timestamps, device model, mildly revealing filenames |

## State management

- SQLite database at `data/state.sqlite`
- Tracks last-scanned commit SHA per repo, seen gists, seen release assets
- `--full` flag ignores state and rescans everything
- Normal runs only scan new commits since last scan

## GitHub Actions

A daily scheduled workflow runs at 06:00 UTC. It:
1. Checks out the repo
2. Installs dependencies
3. Runs the scan
4. Commits the report to the private repo

Can also be triggered manually with `workflow_dispatch`.

## Reports

Reports are Markdown files written to `reports/`. They include:
- Summary with counts by severity
- Individual findings with file, line, rule, severity, redacted evidence, and suggested actions

## License

Private project. Not for distribution.