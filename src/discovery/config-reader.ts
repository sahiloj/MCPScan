import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { z } from 'zod';
import type { ServerConfig, StdioServerConfig, HttpServerConfig } from '../types.js';

// ─── Schema ───────────────────────────────────────────────────────────────────

const RawServerEntrySchema = z.object({
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string()).optional(),
  cwd: z.string().optional(),
  url: z.string().optional(),
  type: z.enum(['stdio', 'http', 'sse']).optional(),
});

const ClaudeConfigSchema = z.object({
  mcpServers: z.record(RawServerEntrySchema).default({}),
});

// ─── Config paths ─────────────────────────────────────────────────────────────

export function getDefaultConfigPaths(): string[] {
  const home = os.homedir();
  const platform = process.platform;

  const paths: string[] = [];

  if (platform === 'darwin') {
    paths.push(path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
  } else if (platform === 'win32') {
    const appData = process.env['APPDATA'] ?? path.join(home, 'AppData', 'Roaming');
    paths.push(path.join(appData, 'Claude', 'claude_desktop_config.json'));
  } else {
    paths.push(path.join(home, '.config', 'claude', 'claude_desktop_config.json'));
  }

  // Additional locations regardless of platform
  paths.push(
    path.join(process.cwd(), '.mcp.json'),
    path.join(process.cwd(), '.cursor', 'mcp.json'),
    path.join(home, '.config', 'mcp', 'config.json'),
  );

  return paths;
}

// ─── Parser ───────────────────────────────────────────────────────────────────

function normalizeEntry(name: string, raw: z.infer<typeof RawServerEntrySchema>): ServerConfig | null {
  // HTTP/SSE server
  if (raw.url) {
    const cfg: HttpServerConfig = {
      type: raw.type === 'sse' ? 'sse' : 'http',
      url: raw.url,
    };
    return cfg;
  }

  // Stdio server
  if (raw.command) {
    const cfg: StdioServerConfig = {
      type: 'stdio',
      command: raw.command,
      args: raw.args,
      env: raw.env,
      cwd: raw.cwd,
    };
    return cfg;
  }

  console.warn(`[mcpscan] Skipping server "${name}": no command or url field`);
  return null;
}

export async function readConfigFile(
  configPath: string,
): Promise<Map<string, ServerConfig>> {
  const servers = new Map<string, ServerConfig>();

  let raw: unknown;
  try {
    const text = await fs.readFile(configPath, 'utf-8');
    raw = JSON.parse(text);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Cannot read config at ${configPath}: ${msg}`);
  }

  const result = ClaudeConfigSchema.safeParse(raw);
  if (!result.success) {
    throw new Error(`Invalid config format at ${configPath}: ${result.error.message}`);
  }

  for (const [name, entry] of Object.entries(result.data.mcpServers)) {
    const cfg = normalizeEntry(name, entry);
    if (cfg) servers.set(name, cfg);
  }

  return servers;
}

export async function discoverConfigs(): Promise<Map<string, ServerConfig>> {
  const all = new Map<string, ServerConfig>();
  const paths = getDefaultConfigPaths();

  for (const configPath of paths) {
    try {
      await fs.access(configPath);
    } catch {
      continue; // File doesn't exist
    }

    try {
      const servers = await readConfigFile(configPath);
      for (const [name, cfg] of servers) {
        // Prefix with config source to avoid name collisions
        const key = servers.size > 0 ? name : name;
        all.set(key, cfg);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[mcpscan] Warning: ${msg}`);
    }
  }

  return all;
}
