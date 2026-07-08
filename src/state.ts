// src/state.ts — SQLite state management
import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const DEFAULT_DB_PATH = resolve(process.cwd(), 'data', 'state.sqlite');

export class StateManager {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const path = dbPath ?? DEFAULT_DB_PATH;
    mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.init();
  }

  private init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS repos (
        account_id TEXT NOT NULL,
        repo_full_name TEXT NOT NULL,
        last_scanned_sha TEXT,
        last_scanned_at TEXT,
        PRIMARY KEY (account_id, repo_full_name)
      );

      CREATE TABLE IF NOT EXISTS gists (
        account_id TEXT NOT NULL,
        gist_id TEXT NOT NULL,
        seen_at TEXT,
        PRIMARY KEY (account_id, gist_id)
      );

      CREATE TABLE IF NOT EXISTS release_assets (
        account_id TEXT NOT NULL,
        repo_full_name TEXT NOT NULL,
        asset_id INTEGER NOT NULL,
        seen_at TEXT,
        PRIMARY KEY (account_id, asset_id)
      );

      CREATE TABLE IF NOT EXISTS scan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        account_id TEXT,
        repos_scanned INTEGER DEFAULT 0,
        commits_scanned INTEGER DEFAULT 0,
        findings_count INTEGER DEFAULT 0
      );
    `);
  }

  getRepoLastSha(accountId: string, repoFullName: string): string | null {
    const row = this.db
      .prepare('SELECT last_scanned_sha FROM repos WHERE account_id = ? AND repo_full_name = ?')
      .get(accountId, repoFullName) as { last_scanned_sha: string | null } | undefined;
    return row?.last_scanned_sha ?? null;
  }

  setRepoLastSha(accountId: string, repoFullName: string, sha: string, at: string): void {
    this.db
      .prepare(
        `INSERT INTO repos (account_id, repo_full_name, last_scanned_sha, last_scanned_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(account_id, repo_full_name)
         DO UPDATE SET last_scanned_sha = ?, last_scanned_at = ?`,
      )
      .run(accountId, repoFullName, sha, at, sha, at);
  }

  hasGist(accountId: string, gistId: string): boolean {
    const row = this.db
      .prepare('SELECT 1 FROM gists WHERE account_id = ? AND gist_id = ?')
      .get(accountId, gistId);
    return !!row;
  }

  markGistSeen(accountId: string, gistId: string, at: string): void {
    this.db
      .prepare(
        `INSERT INTO gists (account_id, gist_id, seen_at)
         VALUES (?, ?, ?)
         ON CONFLICT(account_id, gist_id)
         DO UPDATE SET seen_at = ?`,
      )
      .run(accountId, gistId, at, at);
  }

  hasReleaseAsset(accountId: string, assetId: number): boolean {
    const row = this.db
      .prepare('SELECT 1 FROM release_assets WHERE account_id = ? AND asset_id = ?')
      .get(accountId, assetId);
    return !!row;
  }

  markReleaseAssetSeen(accountId: string, repoFullName: string, assetId: number, at: string): void {
    this.db
      .prepare(
        `INSERT INTO release_assets (account_id, repo_full_name, asset_id, seen_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(account_id, asset_id)
         DO UPDATE SET seen_at = ?`,
      )
      .run(accountId, repoFullName, assetId, at, at);
  }

  startScanRun(accountId: string | null): number {
    const result = this.db
      .prepare('INSERT INTO scan_runs (started_at, account_id) VALUES (?, ?)')
      .run(new Date().toISOString(), accountId);
    return Number(result.lastInsertRowid);
  }

  finishScanRun(
    id: number,
    reposScanned: number,
    commitsScanned: number,
    findingsCount: number,
  ): void {
    this.db
      .prepare(
        'UPDATE scan_runs SET finished_at = ?, repos_scanned = ?, commits_scanned = ?, findings_count = ? WHERE id = ?',
      )
      .run(new Date().toISOString(), reposScanned, commitsScanned, findingsCount, id);
  }

  getLastScanRun(): { id: number; startedAt: string; finishedAt: string | null; findingsCount: number } | null {
    const row = this.db
      .prepare('SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1')
      .get() as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      id: row.id as number,
      startedAt: row.started_at as string,
      finishedAt: (row.finished_at as string) ?? null,
      findingsCount: row.findings_count as number,
    };
  }

  close(): void {
    this.db.close();
  }
}