import type { Tool, Resource, Prompt } from '@modelcontextprotocol/sdk/types.js';

export type { Tool, Resource, Prompt };

// ─── Severity ────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

// ─── Check categories ────────────────────────────────────────────────────────

export type CheckCategory =
  | 'tool-poisoning'
  | 'credential-leak'
  | 'overprivileged'
  | 'auth-missing'
  | 'session-hijack'
  | 'ssrf'
  | 'rce-vectors'
  | 'supply-chain';

export const ALL_CATEGORIES: CheckCategory[] = [
  'tool-poisoning',
  'credential-leak',
  'overprivileged',
  'auth-missing',
  'session-hijack',
  'ssrf',
  'rce-vectors',
  'supply-chain',
];

// ─── Finding ─────────────────────────────────────────────────────────────────

export interface Finding {
  id: string;           // e.g. "MCP-101"
  title: string;
  severity: Severity;
  category: CheckCategory;
  description: string;
  evidence: string;     // the text/value that triggered the finding
  location: string;     // e.g. "tool: bash_exec > description"
  cve?: string;
  cvss?: number;
  remediation: string;
}

// ─── Server configs ───────────────────────────────────────────────────────────

export interface StdioServerConfig {
  type: 'stdio';
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

export interface HttpServerConfig {
  type: 'http' | 'sse';
  url: string;
  headers?: Record<string, string>;
}

export type ServerConfig = StdioServerConfig | HttpServerConfig;

// ─── Server info ──────────────────────────────────────────────────────────────

export interface ServerInfo {
  name: string;
  version?: string;
  transport: 'stdio' | 'http' | 'sse';
  config: ServerConfig;
}

// ─── Server data (post-enumeration) ──────────────────────────────────────────

export interface ServerData {
  serverInfo: ServerInfo;
  tools: Tool[];
  resources: Resource[];
  prompts: Prompt[];
  rawCapabilities?: unknown;
  /** Response headers captured from the initial HTTP connection */
  httpHeaders?: Record<string, string>;
  /** Resolved path to the stdio server executable (for supply-chain checks) */
  executablePath?: string;
}

// ─── Scan result ─────────────────────────────────────────────────────────────

export interface ScanResult {
  server: ServerInfo;
  findings: Finding[];
  scanDuration: number;   // milliseconds
  error?: string;
  enumerated: boolean;
}

// ─── Scan options ─────────────────────────────────────────────────────────────

export interface ScanOptions {
  checks: CheckCategory[];
  outputFormat: 'terminal' | 'json' | 'sarif';
  minSeverity: Severity;
  timeout: number;        // milliseconds per server
  verbose: boolean;
}

// ─── Check function contract ──────────────────────────────────────────────────

export type CheckFn = (serverData: ServerData) => Promise<Finding[]>;
