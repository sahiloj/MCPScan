import type { CheckFn, Finding, Tool } from '../types.js';

// Parameter names that suggest URL/endpoint input
const URL_PARAM_NAMES = new Set([
  'url', 'uri', 'endpoint', 'target', 'host', 'address',
  'callback', 'webhook', 'redirect', 'proxy', 'forward', 'fetch',
  'href', 'link', 'server', 'api', 'base_url',
  'base_uri', 'remote', 'domain', 'site', 'website', 'service',
  'api_url', 'api_endpoint', 'server_url', 'host_url', 'backend',
  'request_url', 'fetch_url', 'remote_url',
]);

// Description patterns suggesting the tool fetches remote content
const FETCH_DESCRIPTION_RE = /\b(?:fetch(?:es)?|request(?:s)?|download(?:s)?|retriev(?:e|es)|call(?:s)?\s+(?:a|an|the)?\s*(?:url|api|endpoint|webhook)|send(?:s)?\s+(?:a|an|the)?\s*(?:http|request)|scrape(?:s)?|crawl(?:s)?)\b/i;

// URI template variable detection: {variable} or {+variable}
const URI_TEMPLATE_VAR_RE = /\{[+#./;?&=,!@|]?[a-zA-Z_][a-zA-Z0-9_]*[*]?\}/;

function getParamInfo(tool: Tool): Array<{ name: string; description?: string }> {
  const params: Array<{ name: string; description?: string }> = [];
  const schema = tool.inputSchema as Record<string, unknown> | undefined;
  if (!schema?.['properties'] || typeof schema['properties'] !== 'object') return params;

  for (const [propName, propDef] of Object.entries(schema['properties'] as Record<string, unknown>)) {
    const desc =
      typeof propDef === 'object' && propDef !== null && typeof (propDef as Record<string, unknown>)['description'] === 'string'
        ? (propDef as Record<string, unknown>)['description'] as string
        : undefined;
    params.push({ name: propName, description: desc });
  }
  return params;
}

export const check: CheckFn = async (serverData) => {
  const findings: Finding[] = [];

  // ── Per-tool SSRF checks ──────────────────────────────────────────────────

  for (const tool of serverData.tools) {
    const params = getParamInfo(tool);
    const toolDesc = tool.description ?? '';

    const urlParams = params.filter(p => URL_PARAM_NAMES.has(p.name.toLowerCase()));

    if (urlParams.length === 0) continue;

    const hasFetchIntent =
      FETCH_DESCRIPTION_RE.test(toolDesc) ||
      urlParams.some(p => p.description && FETCH_DESCRIPTION_RE.test(p.description));

    const isWebhookOrCallback = urlParams.some(p =>
      ['callback', 'webhook', 'redirect'].includes(p.name.toLowerCase()),
    );

    if (hasFetchIntent) {
      findings.push({
        id: 'MCP-601',
        title: 'SSRF Vector: Tool Fetches User-Supplied URL',
        severity: 'high',
        category: 'ssrf',
        description: `Tool "${tool.name}" accepts a URL/endpoint parameter and fetches remote content. Without strict allowlisting, an attacker can probe internal services (SSRF) or exfiltrate data.`,
        evidence: `Params: ${urlParams.map(p => p.name).join(', ')} | Description: ${toolDesc.slice(0, 150)}`,
        location: `tool: ${tool.name} > inputSchema`,
        remediation: 'Implement a strict URL allowlist (approved domains only). Block private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x, ::1). Validate and normalize URLs before fetching.',
      });
    } else if (isWebhookOrCallback) {
      findings.push({
        id: 'MCP-602',
        title: 'SSRF Vector: Webhook/Callback URL Parameter',
        severity: 'medium',
        category: 'ssrf',
        description: `Tool "${tool.name}" accepts a webhook or callback URL. Blind SSRF is possible if the server makes a request to this URL without allowlist validation.`,
        evidence: `Params: ${urlParams.map(p => p.name).join(', ')}`,
        location: `tool: ${tool.name} > inputSchema`,
        remediation: 'Validate callback URLs against an allowlist. Consider using a dedicated webhook delivery service rather than making direct server-to-server requests.',
      });
    } else {
      findings.push({
        id: 'MCP-603',
        title: 'SSRF Vector: URL Parameter Without Fetch Context',
        severity: 'low',
        category: 'ssrf',
        description: `Tool "${tool.name}" has a URL/endpoint parameter. Confirm whether the server makes outbound requests to this value; if so, SSRF mitigation is required.`,
        evidence: `Params: ${urlParams.map(p => p.name).join(', ')}`,
        location: `tool: ${tool.name} > inputSchema`,
        remediation: 'Audit whether this URL parameter is used in outbound requests. If so, apply an allowlist.',
      });
    }
  }

  // ── Resource URI template checks ──────────────────────────────────────────

  for (const resource of serverData.resources) {
    if (URI_TEMPLATE_VAR_RE.test(resource.uri)) {
      // Check if URI template is HTTP-based with user-controlled components
      if (/^https?:\/\//.test(resource.uri)) {
        findings.push({
          id: 'MCP-604',
          title: 'SSRF Vector: HTTP Resource URI Template with Variables',
          severity: 'medium',
          category: 'ssrf',
          description: `Resource "${resource.name}" uses an HTTP URI template with variable components. User-controlled values in HTTP URIs can be used for SSRF.`,
          evidence: `URI: ${resource.uri}`,
          location: `resource: ${resource.name} > uri`,
          remediation: 'Restrict URI template variables to known-safe values. Use an allowlist of approved hosts.',
        });
      }
    }
  }

  return findings;
};
