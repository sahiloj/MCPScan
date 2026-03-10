import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import type { HttpServerConfig } from '../types.js';

export interface HttpConnection {
  client: Client;
  cleanup: () => Promise<void>;
  responseHeaders: Record<string, string>;
}

export async function connectHttp(
  config: HttpServerConfig,
  timeoutMs: number,
): Promise<HttpConnection> {
  const url = new URL(config.url);
  const capturedHeaders: Record<string, string> = {};

  // Wrap fetch to capture response headers for auth/session analysis
  const capturingFetch: typeof fetch = async (input, init) => {
    const response = await fetch(input, {
      ...init,
      headers: { ...(init?.headers as Record<string, string> | undefined), ...(config.headers ?? {}) },
    });
    response.headers.forEach((value, key) => {
      capturedHeaders[key.toLowerCase()] = value;
    });
    return response;
  };

  const client = new Client(
    { name: 'mcpscan', version: '0.1.0' },
    { capabilities: {} },
  );

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error(`Connection timeout after ${timeoutMs}ms`)), timeoutMs),
  );

  // Try StreamableHTTP first (current spec), fall back to SSE (legacy)
  if (config.type === 'sse') {
    const transport = new SSEClientTransport(url, { fetch: capturingFetch });
    await Promise.race([client.connect(transport), timeout]);
  } else {
    try {
      const transport = new StreamableHTTPClientTransport(url, { fetch: capturingFetch });
      await Promise.race([client.connect(transport), timeout]);
    } catch {
      // Fall back to SSE for legacy servers
      const fallback = new SSEClientTransport(url, { fetch: capturingFetch });
      await Promise.race([client.connect(fallback), timeout]);
    }
  }

  return {
    client,
    cleanup: async () => {
      try {
        await client.close();
      } catch {
        // Ignore cleanup errors
      }
    },
    responseHeaders: capturedHeaders,
  };
}
