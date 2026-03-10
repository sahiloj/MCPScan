import type { CheckFn, Finding, Severity } from '../types.js';

// ─── Pattern registry ─────────────────────────────────────────────────────────

interface CredPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: Severity;
  cve?: string;
}

const PATTERNS: CredPattern[] = [
  {
    id: 'MCP-201',
    name: 'AWS Access Key ID',
    pattern: /AKIA[A-Z0-9]{16}/g,
    severity: 'critical',
  },
  {
    id: 'MCP-202',
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?/gi,
    severity: 'critical',
  },
  {
    id: 'MCP-203',
    name: 'Anthropic API Key',
    pattern: /sk-ant-(?:api\d{2}-)?[A-Za-z0-9\-_]{32,}/g,
    severity: 'critical',
  },
  {
    id: 'MCP-204',
    name: 'OpenAI API Key',
    pattern: /sk-(?:proj-)?[A-Za-z0-9\-_T]{32,}/g,
    severity: 'critical',
  },
  {
    id: 'MCP-205',
    name: 'GitHub Personal Access Token',
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}/g,
    severity: 'critical',
  },
  {
    id: 'MCP-206',
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g,
    severity: 'high',
  },
  {
    id: 'MCP-207',
    name: 'Private Key Material',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
  },
  {
    id: 'MCP-208',
    name: 'MongoDB Connection String',
    pattern: /mongodb(?:\+srv)?:\/\/[^\s"'<>]{8,}/g,
    severity: 'high',
  },
  {
    id: 'MCP-209',
    name: 'PostgreSQL Connection String',
    pattern: /postgres(?:ql)?:\/\/[^\s"'<>]{8,}/g,
    severity: 'high',
  },
  {
    id: 'MCP-210',
    name: 'MySQL Connection String',
    pattern: /mysql:\/\/[^\s"'<>]{8,}/g,
    severity: 'high',
  },
  {
    id: 'MCP-211',
    name: 'Slack Token',
    pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    severity: 'high',
  },
  {
    id: 'MCP-212',
    name: 'Stripe API Key',
    pattern: /(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}/g,
    severity: 'critical',
  },
  {
    id: 'MCP-213',
    name: 'Bearer Token',
    pattern: /Bearer\s+([A-Za-z0-9\-._~+/]{20,}={0,2})/g,
    severity: 'medium',
  },
  {
    id: 'MCP-214',
    name: 'SendGrid API Key',
    pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
    severity: 'high',
  },
  {
    id: 'MCP-215',
    name: 'Twilio API Key',
    pattern: /SK[a-f0-9]{32}/g,
    severity: 'high',
  },
  {
    id: 'MCP-216',
    name: 'Google API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'high',
  },
];

// Placeholder patterns — suppress false positives
const PLACEHOLDER_RE = /(?:YOUR[_-]|REPLACE[_-]|INSERT[_-]|EXAMPLE[_-]|SAMPLE[_-]|<[A-Z_]+>|xxx|XXXX|placeholder|your_key|your_token|your_secret)/i;

// ─── Scan all text fields ─────────────────────────────────────────────────────

function collectTexts(serverData: Parameters<CheckFn>[0]): Array<{ label: string; text: string }> {
  const texts: Array<{ label: string; text: string }> = [];

  // Server info
  texts.push({ label: 'serverInfo.name', text: serverData.serverInfo.name });
  if (serverData.serverInfo.version) {
    texts.push({ label: 'serverInfo.version', text: serverData.serverInfo.version });
  }

  // Tools
  for (const tool of serverData.tools) {
    if (tool.description) texts.push({ label: `tool: ${tool.name} > description`, text: tool.description });
    const schema = tool.inputSchema as Record<string, unknown> | undefined;
    if (schema?.['properties'] && typeof schema['properties'] === 'object') {
      for (const [propName, propDef] of Object.entries(schema['properties'] as Record<string, unknown>)) {
        if (typeof propDef === 'object' && propDef !== null) {
          const def = propDef as Record<string, unknown>;
          if (typeof def['default'] === 'string') {
            texts.push({ label: `tool: ${tool.name} > inputSchema.properties.${propName}.default`, text: def['default'] });
          }
        }
      }
    }
  }

  // Resources
  for (const resource of serverData.resources) {
    texts.push({ label: `resource: ${resource.uri}`, text: resource.uri });
    if (resource.description) texts.push({ label: `resource: ${resource.name} > description`, text: resource.description });
  }

  // Prompts
  for (const prompt of serverData.prompts) {
    if (prompt.description) texts.push({ label: `prompt: ${prompt.name} > description`, text: prompt.description });
  }

  return texts;
}

// ─── Check ────────────────────────────────────────────────────────────────────

export const check: CheckFn = async (serverData) => {
  const findings: Finding[] = [];
  const seen = new Set<string>(); // Deduplicate on (id + match)

  const texts = collectTexts(serverData);

  for (const { label, text } of texts) {
    for (const cred of PATTERNS) {
      cred.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = cred.pattern.exec(text)) !== null) {
        const evidence = match[0];

        // Skip placeholder-looking values
        if (PLACEHOLDER_RE.test(evidence)) continue;

        const dedupeKey = `${cred.id}:${evidence.slice(0, 40)}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        findings.push({
          id: cred.id,
          title: `Credential Leak: ${cred.name}`,
          severity: cred.severity,
          category: 'credential-leak',
          description: `The server exposes a ${cred.name} in its metadata. This credential may be usable by anyone who can enumerate this MCP server.`,
          evidence: evidence.slice(0, 80) + (evidence.length > 80 ? '…' : ''),
          location: label,
          ...(cred.cve ? { cve: cred.cve } : {}),
          remediation: `Rotate the exposed credential immediately. Remove secrets from tool/resource metadata — use environment variables instead and never embed them in descriptions.`,
        });
      }
    }
  }

  return findings;
};
