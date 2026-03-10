import type { CheckFn, Finding, HttpServerConfig } from '../types.js';

export const check: CheckFn = async (serverData) => {
  // Only applies to HTTP/SSE servers
  if (serverData.serverInfo.transport === 'stdio') return [];

  const findings: Finding[] = [];
  const config = serverData.serverInfo.config as HttpServerConfig;
  const headers = serverData.httpHeaders ?? {};

  // ── MCP-401: Unauthenticated access ────────────────────────────────────────
  // We successfully connected and enumerated without providing any auth credentials
  // Check functions are only called after successful enumeration, so reaching here means
  // we connected and got data without credentials
  if (!config.headers?.['Authorization'] && !config.headers?.['authorization']) {
    const toolCount = serverData.tools.length;
    const resourceCount = serverData.resources.length;

    findings.push({
      id: 'MCP-401',
      title: 'Auth Missing: Unauthenticated MCP Server',
      severity: 'high',
      category: 'auth-missing',
      description: `The MCP server responded to unauthenticated requests and exposed ${toolCount} tool(s) and ${resourceCount} resource(s). Anyone who can reach this server can enumerate and invoke its capabilities.`,
      evidence: `Connected to ${config.url} without credentials. Got ${toolCount} tools, ${resourceCount} resources.`,
      location: `server: ${config.url}`,
      remediation: 'Implement authentication (API key, OAuth 2.0, or mTLS). Require the Authorization header on all MCP endpoints.',
    });
  }

  // ── MCP-402: CORS wildcard ────────────────────────────────────────────────
  const corsOrigin = headers['access-control-allow-origin'];
  if (corsOrigin === '*') {
    findings.push({
      id: 'MCP-402',
      title: 'Auth Missing: CORS Wildcard (Access-Control-Allow-Origin: *)',
      severity: 'high',
      category: 'auth-missing',
      description: 'The server allows cross-origin requests from any origin. Malicious web pages can make cross-origin requests to this MCP server on behalf of users.',
      evidence: 'Access-Control-Allow-Origin: *',
      location: `server: ${config.url} > response headers`,
      remediation: 'Restrict CORS to specific trusted origins. Never use wildcard (*) on authenticated endpoints.',
    });
  }

  // ── MCP-403: Server exposed on 0.0.0.0 ───────────────────────────────────
  const urlHost = new URL(config.url).hostname;
  if (urlHost === '0.0.0.0') {
    findings.push({
      id: 'MCP-403',
      title: 'Auth Missing: Server Bound to All Interfaces (0.0.0.0)',
      severity: 'critical',
      category: 'auth-missing',
      description: 'The MCP server is bound to 0.0.0.0, exposing it to all network interfaces including potentially public ones. Research has found thousands of such servers accessible from the internet.',
      evidence: `Server URL: ${config.url}`,
      location: `server config: ${config.url}`,
      remediation: 'Bind the server to 127.0.0.1 (localhost only) or a specific internal IP. Place behind a reverse proxy with authentication.',
    });
  }

  // ── MCP-404: Missing security headers ────────────────────────────────────
  const missingSecurityHeaders: string[] = [];
  if (!headers['x-content-type-options']) missingSecurityHeaders.push('X-Content-Type-Options');
  if (!headers['x-frame-options']) missingSecurityHeaders.push('X-Frame-Options');
  if (!headers['content-security-policy']) missingSecurityHeaders.push('Content-Security-Policy');

  if (missingSecurityHeaders.length >= 2) {
    findings.push({
      id: 'MCP-404',
      title: 'Auth Missing: Security Headers Not Set',
      severity: 'low',
      category: 'auth-missing',
      description: `The server response is missing standard security headers, suggesting a lack of security hardening.`,
      evidence: `Missing: ${missingSecurityHeaders.join(', ')}`,
      location: `server: ${config.url} > response headers`,
      remediation: `Add security headers: ${missingSecurityHeaders.map(h => `${h}: <appropriate-value>`).join(', ')}`,
    });
  }

  // ── MCP-405: Mcp-Session-Id exposed in response ──────────────────────────
  // If the server is leaking session IDs in response headers without auth, those IDs can be stolen
  const sessionHeader = headers['mcp-session-id'];
  if (sessionHeader && !config.headers?.['Authorization']) {
    findings.push({
      id: 'MCP-405',
      title: 'Auth Missing: Session ID Issued Without Authentication',
      severity: 'medium',
      category: 'auth-missing',
      description: 'The server issued an MCP session ID to an unauthenticated client. Sessions without authentication provide no meaningful access control.',
      evidence: `Mcp-Session-Id: ${sessionHeader.slice(0, 40)}`,
      location: `server: ${config.url} > response headers`,
      remediation: 'Require authentication before issuing session identifiers.',
    });
  }

  return findings;
};
