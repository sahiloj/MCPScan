import type { HttpServerConfig } from '../types.js';

const DEFAULT_PORTS = [3000, 3001, 4000, 5000, 8000, 8080, 8888, 9000, 9090];

const MCP_INIT_REQUEST = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'mcpscan', version: '0.1.0' },
  },
});

async function probePort(port: number, timeoutMs = 2000): Promise<HttpServerConfig | null> {
  const url = `http://localhost:${port}/mcp`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: MCP_INIT_REQUEST,
      signal: AbortSignal.timeout(timeoutMs),
    });

    // Any response that isn't a plain 404 is suspicious
    if (response.status !== 404) {
      return { type: 'http', url };
    }

    return null;
  } catch {
    return null;
  }
}

export async function scanLocalPorts(
  ports: number[] = DEFAULT_PORTS,
): Promise<HttpServerConfig[]> {
  const results = await Promise.allSettled(ports.map(p => probePort(p)));

  return results
    .filter((r): r is PromiseFulfilledResult<HttpServerConfig> =>
      r.status === 'fulfilled' && r.value !== null,
    )
    .map(r => r.value);
}
