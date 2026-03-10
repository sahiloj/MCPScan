import path from 'node:path';
import { execSync } from 'node:child_process';
import { connectStdio } from './transport/stdio-client.js';
import { connectHttp } from './transport/http-client.js';
import { check as toolPoisoningCheck } from './checks/tool-poisoning.js';
import { check as credentialLeakCheck } from './checks/credential-leak.js';
import { check as overprivilegedCheck } from './checks/overprivileged.js';
import { check as authMissingCheck } from './checks/auth-missing.js';
import { check as sessionHijackCheck } from './checks/session-hijack.js';
import { check as ssrfCheck } from './checks/ssrf.js';
import { check as rceVectorsCheck } from './checks/rce-vectors.js';
import { check as supplyChainCheck } from './checks/supply-chain.js';
import type {
  CheckCategory,
  CheckFn,
  Finding,
  ScanOptions,
  ScanResult,
  ServerConfig,
  ServerData,
  ServerInfo,
  Severity,
  StdioServerConfig,
  HttpServerConfig,
} from './types.js';
import { SEVERITY_RANK } from './types.js';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';

// ─── Check registry ───────────────────────────────────────────────────────────

const ALL_CHECKS: Record<CheckCategory, CheckFn> = {
  'tool-poisoning': toolPoisoningCheck,
  'credential-leak': credentialLeakCheck,
  'overprivileged': overprivilegedCheck,
  'auth-missing': authMissingCheck,
  'session-hijack': sessionHijackCheck,
  'ssrf': ssrfCheck,
  'rce-vectors': rceVectorsCheck,
  'supply-chain': supplyChainCheck,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function resolveExecutablePath(command: string): string | undefined {
  if (path.isAbsolute(command)) return command;
  try {
    return execSync(`which ${JSON.stringify(command)} 2>/dev/null`, { encoding: 'utf-8' }).trim() || undefined;
  } catch {
    return undefined;
  }
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.category}:${f.location}:${f.evidence.slice(0, 100)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function filterBySeverity(findings: Finding[], minSeverity: Severity): Finding[] {
  const minRank = SEVERITY_RANK[minSeverity];
  return findings.filter(f => SEVERITY_RANK[f.severity] >= minRank);
}

// ─── Enumeration ──────────────────────────────────────────────────────────────

async function enumerateServer(
  name: string,
  config: ServerConfig,
  timeoutMs: number,
): Promise<{ serverData: ServerData; client: Client; cleanup: () => Promise<void> }> {
  let client: Client;
  let cleanup: () => Promise<void>;
  let responseHeaders: Record<string, string> | undefined;

  if (config.type === 'stdio') {
    const conn = await connectStdio(config as StdioServerConfig, timeoutMs);
    client = conn.client;
    cleanup = conn.cleanup;
  } else {
    const conn = await connectHttp(config as HttpServerConfig, timeoutMs);
    client = conn.client;
    cleanup = conn.cleanup;
    responseHeaders = conn.responseHeaders;
  }

  // Enumerate in parallel — use allSettled so partial failures don't abort everything
  const [toolsResult, resourcesResult, promptsResult] = await Promise.allSettled([
    client.listTools(),
    client.listResources(),
    client.listPrompts(),
  ]);

  const serverVersion = (client as unknown as { getServerVersion?: () => { version?: string } | undefined }).getServerVersion?.();

  const serverInfo: ServerInfo = {
    name,
    version: serverVersion?.version,
    transport: config.type,
    config,
  };

  const executablePath =
    config.type === 'stdio'
      ? resolveExecutablePath((config as StdioServerConfig).command)
      : undefined;

  const serverData: ServerData = {
    serverInfo,
    tools: toolsResult.status === 'fulfilled' ? (toolsResult.value.tools ?? []) : [],
    resources: resourcesResult.status === 'fulfilled' ? (resourcesResult.value.resources ?? []) : [],
    prompts: promptsResult.status === 'fulfilled' ? (promptsResult.value.prompts ?? []) : [],
    rawCapabilities: (client as unknown as { getServerCapabilities?: () => unknown }).getServerCapabilities?.(),
    httpHeaders: responseHeaders,
    executablePath,
    enumerated: true,
  } as ServerData & { enumerated: boolean };

  return { serverData, client, cleanup };
}

// ─── Main scan function ───────────────────────────────────────────────────────

export async function scanServer(
  name: string,
  config: ServerConfig,
  options: ScanOptions,
): Promise<ScanResult> {
  const start = Date.now();

  let serverData: ServerData;
  let cleanup: (() => Promise<void>) | undefined;

  try {
    const result = await enumerateServer(name, config, options.timeout);
    serverData = result.serverData;
    cleanup = result.cleanup;
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const serverInfo: ServerInfo = { name, transport: config.type, config };
    return {
      server: serverInfo,
      findings: [],
      scanDuration: Date.now() - start,
      error: errorMsg,
      enumerated: false,
    };
  }

  // Run enabled checks in parallel
  const enabledChecks = options.checks
    .filter(cat => cat in ALL_CHECKS)
    .map(cat => ALL_CHECKS[cat]!(serverData));

  const results = await Promise.allSettled(enabledChecks);

  if (cleanup) {
    await cleanup().catch(() => undefined);
  }

  const allFindings = results.flatMap(r => {
    if (r.status === 'fulfilled') return r.value;
    if (options.verbose) {
      console.error(`[mcpscan] Check error: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`);
    }
    return [];
  });

  const findings = filterBySeverity(deduplicateFindings(allFindings), options.minSeverity);

  // Sort findings: critical first, then by ID
  findings.sort((a, b) => {
    const sevDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return a.id.localeCompare(b.id);
  });

  return {
    server: serverData.serverInfo,
    findings,
    scanDuration: Date.now() - start,
    enumerated: true,
  };
}

export async function scanAll(
  servers: Map<string, ServerConfig>,
  options: ScanOptions,
  onProgress?: (name: string, result: ScanResult) => void,
): Promise<ScanResult[]> {
  const results: ScanResult[] = [];

  for (const [name, config] of servers) {
    const result = await scanServer(name, config, options);
    results.push(result);
    onProgress?.(name, result);
  }

  return results;
}
