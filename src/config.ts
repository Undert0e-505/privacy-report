// src/config.ts — Load config/accounts.yml
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { AppConfig } from './types.js';

const DEFAULT_CONFIG_PATH = resolve(process.cwd(), 'config', 'accounts.yml');

export function loadConfig(configPath?: string): AppConfig {
  const path = configPath ?? process.env.PRIVACY_REPORT_CONFIG ?? DEFAULT_CONFIG_PATH;
  const raw = readFileSync(path, 'utf-8');
  const parsed = parseYaml(raw) as AppConfig;

  if (!parsed || !Array.isArray(parsed.accounts)) {
    throw new Error(`Invalid config: expected "accounts" array at ${path}`);
  }
  if (!parsed.scan || typeof parsed.scan !== 'object') {
    throw new Error(`Invalid config: expected "scan" object at ${path}`);
  }

  // Validate accounts
  for (const acct of parsed.accounts) {
    if (!acct.id || !acct.githubUser) {
      throw new Error(`Invalid account config: id and githubUser are required`);
    }
    if (typeof acct.enabled !== 'boolean') {
      acct.enabled = true;
    }
  }

  // Set scan defaults
  const scan = parsed.scan;
  scan.includeForks ??= false;
  scan.includeArchived ??= false;
  scan.maxFileBytes ??= 1_000_000;
  scan.redactSecrets ??= true;
  scan.storeExactGps ??= false;

  return parsed;
}

export function getEnabledAccounts(config: AppConfig) {
  return config.accounts.filter((a) => a.enabled);
}

export function getAccountById(config: AppConfig, id: string) {
  return config.accounts.find((a) => a.id === id);
}