import type { CheckFn, Finding, HttpServerConfig } from '../types.js';

// UUID v1 has timestamp in the first component — time-based = predictable
const UUID_V1_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
// Sequential or very short IDs
const SHORT_ID_RE = /^[0-9a-f]{1,15}$/i;

function isLikelyPredictable(sessionId: string): boolean {
  if (sessionId.length < 16) return true;
  if (UUID_V1_RE.test(sessionId)) return true;
  if (SHORT_ID_RE.test(sessionId)) return true;
  // All same character
  if (new Set(sessionId).size < 3) return true;
  return false;
}

function extractMaxAge(setCookieHeader: string): number {
  const match = setCookieHeader.match(/max-age=(\d+)/i);
  return match ? parseInt(match[1]!, 10) : 0;
}

export const check: CheckFn = async (serverData) => {
  if (serverData.serverInfo.transport === 'stdio') return [];

  const findings: Finding[] = [];
  const config = serverData.serverInfo.config as HttpServerConfig;
  const headers = serverData.httpHeaders ?? {};

  let url: URL;
  try {
    url = new URL(config.url);
  } catch {
    return findings;
  }

  // ── MCP-501: Session ID in URL query parameters ────────────────────────────
  const sensitiveParams = ['session', 'sessionid', 'sessiontoken', 'token', 'sid', 'auth', 'key', 'apikey'];
  const urlParams = [...url.searchParams.keys()].map(k => k.toLowerCase());
  const exposedParams = urlParams.filter(p => sensitiveParams.includes(p));

  if (exposedParams.length > 0) {
    findings.push({
      id: 'MCP-501',
      title: 'Session Hijack: Session Identifier in URL',
      severity: 'high',
      category: 'session-hijack',
      description: 'Session tokens or API keys appear in the URL query string. URLs are logged by web servers, proxies, and browsers — exposing these values to log aggregators and browser history.',
      evidence: `URL params: ${exposedParams.join(', ')} in ${config.url}`,
      location: `server URL: ${config.url}`,
      remediation: 'Move session identifiers and API keys to HTTP headers (Authorization or X-API-Key). Never include secrets in URLs per RFC 6749.',
    });
  }

  // ── MCP-502: Predictable session ID ──────────────────────────────────────
  const sessionId = headers['mcp-session-id'];
  if (sessionId && isLikelyPredictable(sessionId)) {
    findings.push({
      id: 'MCP-502',
      title: 'Session Hijack: Predictable Session Identifier',
      severity: 'medium',
      category: 'session-hijack',
      description: `The server issued a session ID that appears predictable or insufficiently random: "${sessionId.slice(0, 40)}". Predictable IDs can be guessed or brute-forced.`,
      evidence: `Mcp-Session-Id: ${sessionId.slice(0, 60)}`,
      location: `server: ${config.url} > Mcp-Session-Id header`,
      remediation: 'Use cryptographically secure random session IDs of at least 128 bits (32 hex chars / UUID v4). Avoid UUID v1 (time-based).',
    });
  }

  // ── MCP-503: Overly long session lifetime ────────────────────────────────
  const setCookie = headers['set-cookie'];
  if (setCookie) {
    const maxAge = extractMaxAge(setCookie);
    const thirtyDaysSeconds = 30 * 24 * 3600;
    if (maxAge > thirtyDaysSeconds) {
      const days = Math.round(maxAge / 86400);
      findings.push({
        id: 'MCP-503',
        title: 'Session Hijack: Excessive Session Lifetime',
        severity: 'low',
        category: 'session-hijack',
        description: `Session cookie has a max-age of ${days} days. Long-lived sessions increase the window of opportunity after credential theft.`,
        evidence: `Set-Cookie max-age=${maxAge} (${days} days)`,
        location: `server: ${config.url} > Set-Cookie header`,
        remediation: 'Limit session lifetime to 24 hours for MCP server contexts. Implement session refresh tokens for longer user sessions.',
      });
    }

    // Check for missing Secure and HttpOnly flags
    const missingFlags: string[] = [];
    if (!/;\s*secure/i.test(setCookie)) missingFlags.push('Secure');
    if (!/;\s*httponly/i.test(setCookie)) missingFlags.push('HttpOnly');
    if (!/;\s*samesite/i.test(setCookie)) missingFlags.push('SameSite');

    if (missingFlags.length > 0) {
      findings.push({
        id: 'MCP-504',
        title: 'Session Hijack: Cookie Missing Security Flags',
        severity: 'medium',
        category: 'session-hijack',
        description: `Session cookie is missing security flags: ${missingFlags.join(', ')}. Missing Secure allows interception over HTTP; missing HttpOnly allows JavaScript theft; missing SameSite enables CSRF.`,
        evidence: `Set-Cookie header missing: ${missingFlags.join(', ')}`,
        location: `server: ${config.url} > Set-Cookie header`,
        remediation: `Set all cookie security flags: Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict`,
      });
    }
  }

  return findings;
};
