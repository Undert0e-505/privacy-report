# Security Policy

## Hard boundaries

This tool is a **defensive privacy auditing tool**. It exists to help account owners monitor their own public GitHub presence for accidentally exposed sensitive information.

### What this tool does

- Scans **public** GitHub content from **configured/approved accounts only**
- Uses passive GitHub API requests (read-only)
- Produces private reports stored in this repository
- Redacts all secrets in reports by default

### What this tool does NOT do

- **No third-party access.** Only scans accounts we own/control, configured in `config/accounts.yml`
- **No exploit attempts.** Does not probe for vulnerabilities, validate credentials, or test authentication
- **No password or API key validation** against any third-party service
- **No public disclosure.** Reports are gitignored — never published as issues, comments, or public pages
- **No scanning of unconfigured accounts.** The account list is explicit and must be manually configured

## Report handling

- Reports are Markdown files in `reports/`
- The `reports/` directory is covered by `.gitignore` for `*.md` files (except `.gitkeep`)
- In CI, report files are gitignored and never committed to the repo
- Reports contain redacted evidence only — full secrets are never written to disk in report files

## API usage

- Uses GitHub REST API via `@octokit/rest`
- Respects rate limits (checks `X-RateLimit-Remaining`, sleeps if low)
- Uses conditional requests with ETags where Octokit supports them
- Only requests read-only public data

## Disclosure

If you discover a security issue in this tool itself, please report it privately. Do not open a public issue.

## Scope

This tool is for personal/organisational self-auditing only. It is not a general-purpose security scanner and should not be used to scan accounts you do not own or have explicit permission to audit.