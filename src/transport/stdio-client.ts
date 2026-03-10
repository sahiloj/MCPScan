import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { StdioServerConfig } from '../types.js';

export interface StdioConnection {
  client: Client;
  cleanup: () => Promise<void>;
}

export async function connectStdio(
  config: StdioServerConfig,
  timeoutMs: number,
): Promise<StdioConnection> {
  const transport = new StdioClientTransport({
    command: config.command,
    args: config.args ?? [],
    env: { ...process.env, ...(config.env ?? {}) } as Record<string, string>,
    cwd: config.cwd,
    stderr: 'pipe',
  });

  const client = new Client(
    { name: 'mcpscan', version: '0.1.0' },
    { capabilities: {} },
  );

  await Promise.race([
    client.connect(transport),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`Connection timeout after ${timeoutMs}ms`)), timeoutMs),
    ),
  ]);

  return {
    client,
    cleanup: async () => {
      try {
        await client.close();
      } catch {
        // Ignore cleanup errors
      }
    },
  };
}
