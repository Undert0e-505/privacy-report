// src/types.ts — Shared TypeScript types for privacy-report

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface AccountConfig {
  id: string;
  githubUser: string;
  enabled: boolean;
}

export interface ScanConfig {
  includeForks: boolean;
  includeArchived: boolean;
  maxFileBytes: number;
  redactSecrets: boolean;
  storeExactGps: boolean;
}

export interface AppConfig {
  accounts: AccountConfig[];
  scan: ScanConfig;
  contactEmail?: string;
}

export interface Finding {
  account: string;
  repo: string;
  file: string;
  line?: number;
  commit?: string;
  rule: string;
  severity: Severity;
  redactedEvidence: string;
  metadata?: Record<string, string>;
  suggestedAction: string;
}

export interface ScanResult {
  startedAt: string;
  finishedAt: string;
  accountsScanned: number;
  reposScanned: number;
  commitsScanned: number;
  findings: Finding[];
}

export interface RepoState {
  accountId: string;
  repoFullName: string;
  lastScannedSha: string | null;
  lastScannedAt: string | null;
}

export interface ScanRunRecord {
  id: number;
  startedAt: string;
  finishedAt: string | null;
  accountId: string | null;
  reposScanned: number;
  commitsScanned: number;
  findingsCount: number;
}