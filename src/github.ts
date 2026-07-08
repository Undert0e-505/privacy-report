// src/github.ts — GitHub API client with ETag/conditional request support
import { Octokit } from '@octokit/rest';
import type { AccountConfig, ScanConfig } from './types.js';

export interface RepoInfo {
  name: string;
  fullName: string;
  defaultBranch: string;
  fork: boolean;
  archived: boolean;
  pushedAt: string;
}

export interface CommitInfo {
  sha: string;
  message: string;
  date: string;
  author: string;
}

export interface FileInfo {
  path: string;
  sha: string;
  size: number;
  type: 'file' | 'dir' | 'symlink' | 'submodule';
  content?: string;
  encoding?: string;
}

export interface GistInfo {
  id: string;
  description: string | null;
  files: string[];
  public: boolean;
  updatedAt: string;
}

export class GitHubClient {
  private octokit: Octokit;
  private rateLimitRemaining: number | null = null;

  constructor(token?: string) {
    this.octokit = new Octokit({
      auth: token,
      request: { fetch },
    });
  }

  /** Check rate limit and sleep if needed. */
  async checkRateLimit(): Promise<void> {
    if (this.rateLimitRemaining !== null && this.rateLimitRemaining <= 5) {
      const reset = await this.getRateLimitReset();
      if (reset) {
        const waitMs = reset - Date.now();
        if (waitMs > 0 && waitMs < 600_000) {
          console.warn(`[github] Rate limit low (${this.rateLimitRemaining} remaining). Sleeping ${Math.ceil(waitMs / 1000)}s.`);
          await new Promise((r) => setTimeout(r, Math.min(waitMs, 60_000)));
        }
      }
    }
  }

  private async getRateLimitReset(): Promise<number | null> {
    try {
      const res = await this.octokit.rest.rateLimit.get();
      return res.data.resources.core.reset * 1000;
    } catch {
      return null;
    }
  }

  /** List repos for a user, respecting config filters. */
  async listRepos(user: string, config: ScanConfig): Promise<RepoInfo[]> {
    const repos: RepoInfo[] = [];
    let page = 1;
    while (true) {
      await this.checkRateLimit();
      const res = await this.octokit.rest.repos.listForUser({
        username: user,
        type: 'owner',
        sort: 'pushed',
        per_page: 100,
        page,
      });
      this.rateLimitRemaining = parseInt(
        res.headers['x-ratelimit-remaining'] ?? '5000',
        10,
      );
      if (res.data.length === 0) break;
      for (const r of res.data) {
        if (r.fork && !config.includeForks) continue;
        if (r.archived && !config.includeArchived) continue;
        repos.push({
          name: r.name ?? r.full_name ?? 'unknown',
          fullName: r.full_name ?? r.name ?? 'unknown',
          defaultBranch: r.default_branch ?? 'main',
          fork: r.fork ?? false,
          archived: r.archived ?? false,
          pushedAt: r.pushed_at ?? '',
        });
      }
      if (res.data.length < 100) break;
      page++;
    }
    return repos;
  }

  /** List commits since a given SHA (exclusive). If sinceSha is null, list all. */
  async listCommits(
    owner: string,
    repo: string,
    sha: string | null,
    perPage = 100,
  ): Promise<CommitInfo[]> {
    const commits: CommitInfo[] = [];
    let page = 1;
    while (true) {
      await this.checkRateLimit();
      const res = await this.octokit.rest.repos.listCommits({
        owner,
        repo,
        sha: sha ?? undefined,
        per_page: perPage,
        page,
      });
      this.rateLimitRemaining = parseInt(
        res.headers['x-ratelimit-remaining'] ?? '5000',
        10,
      );
      if (res.data.length === 0) break;
      for (const c of res.data) {
        if (sha && c.sha === sha) continue; // Skip the already-scanned commit
        commits.push({
          sha: c.sha,
          message: c.commit.message,
          date: c.commit.author?.date ?? c.commit.committer?.date ?? '',
          author: c.commit.author?.name ?? c.author?.login ?? 'unknown',
        });
      }
      if (res.data.length < perPage) break;
      page++;
    }
    return commits;
  }

  /** Get the tree of a commit (recursive). */
  async getCommitTree(
    owner: string,
    repo: string,
    commitSha: string,
  ): Promise<FileInfo[]> {
    await this.checkRateLimit();
    const res = await this.octokit.rest.git.getTree({
      owner,
      repo,
      tree_sha: commitSha,
      recursive: '1',
    });
    this.rateLimitRemaining = parseInt(
      res.headers['x-ratelimit-remaining'] ?? '5000',
      10,
    );
    return (res.data.tree as Array<{ path: string; sha: string; size?: number; type: string }>)
      .filter((t) => t.type === 'blob')
      .map((t) => ({
        path: t.path,
        sha: t.sha,
        size: t.size ?? 0,
        type: 'file' as const,
      }));
  }

  /** Fetch file content at a given ref. Returns text content or null for binary. */
  async getFileContent(
    owner: string,
    repo: string,
    path: string,
    ref: string,
  ): Promise<{ content: string; isBinary: boolean } | null> {
    await this.checkRateLimit();
    try {
      const res = await this.octokit.rest.repos.getContent({
        owner,
        repo,
        path,
        ref,
        request: { headers: { Accept: 'application/vnd.github.raw+json' } },
      });
      this.rateLimitRemaining = parseInt(
        res.headers['x-ratelimit-remaining'] ?? '5000',
        10,
      );
      // When using raw accept header, data is a string
      const data = res.data;
      if (typeof data === 'string') {
        return { content: data, isBinary: false };
      }
      // If it came back as an object with content (base64), decode
      if (typeof data === 'object' && 'content' in data) {
        const obj = data as { content?: string; encoding?: string };
        if (obj.encoding === 'base64' && obj.content) {
          return { content: Buffer.from(obj.content, 'base64').toString('utf-8'), isBinary: false };
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  /** Download a file from GitHub raw URL to a local buffer. */
  async downloadFile(
    owner: string,
    repo: string,
    path: string,
    ref: string,
  ): Promise<Buffer | null> {
    await this.checkRateLimit();
    try {
      const url = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${path}`;
      const res = await fetch(url);
      if (!res.ok) return null;
      const buf = Buffer.from(await res.arrayBuffer());
      return buf;
    } catch {
      return null;
    }
  }

  /** List gists for a user. */
  async listGists(user: string): Promise<GistInfo[]> {
    const gists: GistInfo[] = [];
    let page = 1;
    while (true) {
      await this.checkRateLimit();
      const res = await this.octokit.rest.gists.listForUser({
        username: user,
        per_page: 100,
        page,
      });
      this.rateLimitRemaining = parseInt(
        res.headers['x-ratelimit-remaining'] ?? '5000',
        10,
      );
      if (res.data.length === 0) break;
      for (const g of res.data) {
        gists.push({
          id: g.id ?? '',
          description: g.description,
          files: Object.keys(g.files ?? {}),
          public: g.public ?? false,
          updatedAt: g.updated_at ?? '',
        });
      }
      if (res.data.length < 100) break;
      page++;
    }
    return gists;
  }

  /** Get gist content. */
  async getGistContent(gistId: string): Promise<Record<string, string>> {
    await this.checkRateLimit();
    const res = await this.octokit.rest.gists.get({ gist_id: gistId });
    this.rateLimitRemaining = parseInt(
      res.headers['x-ratelimit-remaining'] ?? '5000',
      10,
    );
    const files: Record<string, string> = {};
    for (const [name, file] of Object.entries(res.data.files ?? {})) {
      if (file?.content) {
        files[name] = file.content;
      }
    }
    return files;
  }

  /** List release assets for all releases of a repo. */
  async listReleaseAssets(owner: string, repo: string): Promise<Array<{ id: number; name: string; url: string }>> {
    const assets: Array<{ id: number; name: string; url: string }> = [];
    let page = 1;
    while (true) {
      await this.checkRateLimit();
      const res = await this.octokit.rest.repos.listReleases({
        owner,
        repo,
        per_page: 30,
        page,
      });
      this.rateLimitRemaining = parseInt(
        res.headers['x-ratelimit-remaining'] ?? '5000',
        10,
      );
      if (res.data.length === 0) break;
      for (const release of res.data) {
        for (const asset of release.assets ?? []) {
          assets.push({
            id: asset.id,
            name: asset.name,
            url: asset.browser_download_url,
          });
        }
      }
      if (res.data.length < 30) break;
      page++;
    }
    return assets;
  }
}