import type { CheckFn, Finding, Tool } from '../types.js';

// ─── Capability detection ─────────────────────────────────────────────────────

type Capability =
  | 'shell-exec'
  | 'fs-write'
  | 'fs-read'
  | 'net-fetch'
  | 'code-eval'
  | 'db-write'
  | 'messaging'
  | 'auth-manip'
  | 'process-mgmt';

const CAP_PATTERNS: Record<Capability, RegExp> = {
  'shell-exec':   /\b(?:exec(?:ute)?|shell|bash|sh|zsh|cmd|powershell|spawn|subprocess|popen|system\s*call)\b/i,
  'fs-write':     /\b(?:write|overwrite|append|creat(?:e|ing)|delet(?:e|ing)|remov(?:e|ing)|mov(?:e|ing)|renam(?:e|ing)|mkdir|rmdir|truncat(?:e|ing)|chmod|chown)\b/i,
  'fs-read':      /\b(?:read|open|list|glob|find|search|scan|watch)\s+(?:file|dir|folder|path|disk|filesystem)\b/i,
  'net-fetch':    /\b(?:fetch|request|download|upload|http|curl|get\s+url|post\s+to|send\s+request|web\s*hook|call\s+api)\b/i,
  'code-eval':    /\b(?:eval(?:uate)?|interpret|execut(?:e|ing)\s+code|run\s+(?:code|script)|sandbox|repl|compile)\b/i,
  'db-write':     /\b(?:insert|update|delete|drop|truncate|alter|create\s+table|upsert|write\s+to\s+(?:db|database))\b/i,
  'messaging':    /\b(?:send\s+(?:email|message|sms|slack|notification|alert)|email\s+to|notify|post\s+to\s+(?:slack|teams|discord))\b/i,
  'auth-manip':   /\b(?:creat(?:e|ing)\s+(?:user|token|key|api\s*key|credential)|delet(?:e|ing)\s+(?:user|account)|grant\s+(?:permission|access|role)|revok(?:e|ing))\b/i,
  'process-mgmt': /\b(?:kill\s+process|start\s+process|restart|daemon|service\s+(?:start|stop|restart)|signal\s+process)\b/i,
};

const SENSITIVE_PATHS = ['/etc/', '~/.ssh', '~/.aws', '/proc/', '/sys/', '/root/', '~/.config/'];

function getToolCapabilities(tool: Tool): Set<Capability> {
  const caps = new Set<Capability>();
  const combined =
    (tool.name + ' ' + (tool.description ?? '')).toLowerCase();

  for (const [cap, re] of Object.entries(CAP_PATTERNS) as [Capability, RegExp][]) {
    if (re.test(combined)) caps.add(cap);
  }

  // Also check parameter names
  const schema = tool.inputSchema as Record<string, unknown> | undefined;
  if (schema?.['properties'] && typeof schema['properties'] === 'object') {
    const propNames = Object.keys(schema['properties'] as object).join(' ');
    for (const [cap, re] of Object.entries(CAP_PATTERNS) as [Capability, RegExp][]) {
      if (re.test(propNames)) caps.add(cap);
    }
  }

  return caps;
}

function hasUnrestrictedPath(tool: Tool): boolean {
  const schema = tool.inputSchema as Record<string, unknown> | undefined;
  if (!schema?.['properties'] || typeof schema['properties'] !== 'object') return false;

  const pathParamNames = ['path', 'directory', 'dir', 'folder', 'file', 'filename', 'filepath'];
  for (const [propName, propDef] of Object.entries(schema['properties'] as Record<string, unknown>)) {
    if (!pathParamNames.some(n => propName.toLowerCase().includes(n))) continue;
    if (typeof propDef !== 'object' || propDef === null) continue;
    const def = propDef as Record<string, unknown>;
    // No pattern or enum = unrestricted
    if (!def['pattern'] && !def['enum']) return true;
  }
  return false;
}

function touchesSensitivePaths(tool: Tool): boolean {
  const text = (tool.name + ' ' + (tool.description ?? '')).toLowerCase();
  return SENSITIVE_PATHS.some(p => text.includes(p.toLowerCase()));
}

// ─── Check ────────────────────────────────────────────────────────────────────

export const check: CheckFn = async (serverData) => {
  const findings: Finding[] = [];

  // Gather capabilities across all tools
  const toolCaps = new Map<string, Set<Capability>>();
  for (const tool of serverData.tools) {
    toolCaps.set(tool.name, getToolCapabilities(tool));
  }

  const serverCaps = new Set<Capability>(
    [...toolCaps.values()].flatMap(s => [...s]),
  );

  // ── Critical combinations across the server ──────────────────────────────

  if (serverCaps.has('shell-exec') && serverCaps.has('fs-write')) {
    findings.push({
      id: 'MCP-301',
      title: 'Overprivileged: Shell Execution + Filesystem Write',
      severity: 'critical',
      category: 'overprivileged',
      description: 'This server exposes both shell command execution and filesystem write capabilities. A compromised or malicious actor can trivially achieve full host compromise.',
      evidence: `shell-exec tools: ${[...toolCaps.entries()].filter(([, c]) => c.has('shell-exec')).map(([n]) => n).join(', ')} | fs-write tools: ${[...toolCaps.entries()].filter(([, c]) => c.has('fs-write')).map(([n]) => n).join(', ')}`,
      location: 'server-level capability combination',
      remediation: 'Separate shell and filesystem operations into distinct, minimal-privilege MCP servers. Apply path allow-lists and command allow-lists.',
    });
  }

  if (serverCaps.has('shell-exec') && serverCaps.has('net-fetch')) {
    findings.push({
      id: 'MCP-302',
      title: 'Overprivileged: Shell Execution + Network Access',
      severity: 'critical',
      category: 'overprivileged',
      description: 'The server combines shell execution with outbound network access, enabling an attacker to exfiltrate data or download and run arbitrary code.',
      evidence: `shell-exec + net-fetch present`,
      location: 'server-level capability combination',
      remediation: 'Restrict network access to specific approved domains. Avoid combining shell execution with network fetch in the same server.',
    });
  }

  if (serverCaps.has('code-eval')) {
    findings.push({
      id: 'MCP-303',
      title: 'Overprivileged: Code Evaluation Capability',
      severity: 'critical',
      category: 'overprivileged',
      description: 'The server can evaluate or execute arbitrary code. Any user input reaching this tool is a potential RCE vector.',
      evidence: `code-eval tools: ${[...toolCaps.entries()].filter(([, c]) => c.has('code-eval')).map(([n]) => n).join(', ')}`,
      location: 'server-level capability',
      remediation: 'Sandbox code execution with strict resource limits and no filesystem or network access. Prefer allowlisted operations over arbitrary eval.',
    });
  }

  // ── Per-tool checks ───────────────────────────────────────────────────────

  for (const tool of serverData.tools) {
    const caps = toolCaps.get(tool.name) ?? new Set();

    // Unrestricted filesystem access
    if ((caps.has('fs-write') || caps.has('fs-read')) && hasUnrestrictedPath(tool)) {
      findings.push({
        id: 'MCP-304',
        title: 'Overprivileged: Unrestricted Filesystem Path Parameter',
        severity: 'high',
        category: 'overprivileged',
        description: `Tool "${tool.name}" accepts a filesystem path parameter with no pattern or enum constraint, allowing access to arbitrary locations.`,
        evidence: `Tool: ${tool.name}, capabilities: ${[...caps].join(', ')}`,
        location: `tool: ${tool.name} > inputSchema`,
        remediation: 'Add a path allow-list (JSON Schema "pattern" or "enum") restricting access to approved directories only.',
      });
    }

    // Sensitive path access
    if (touchesSensitivePaths(tool)) {
      findings.push({
        id: 'MCP-305',
        title: 'Overprivileged: Sensitive System Path Access',
        severity: 'high',
        category: 'overprivileged',
        description: `Tool "${tool.name}" references sensitive system paths (e.g., /etc/, ~/.ssh, ~/.aws) in its description, suggesting broad filesystem access.`,
        evidence: (tool.description ?? tool.name).slice(0, 200),
        location: `tool: ${tool.name} > description`,
        remediation: 'Restrict tool access to application-specific directories. Do not expose credential or system config paths.',
      });
    }

    // Messaging + auth combo
    if (caps.has('messaging') && caps.has('auth-manip')) {
      findings.push({
        id: 'MCP-306',
        title: 'Overprivileged: Messaging + Auth Manipulation',
        severity: 'high',
        category: 'overprivileged',
        description: `Tool "${tool.name}" appears to combine sending messages with user/token management — a high-impact combination for social engineering attacks.`,
        evidence: `Tool: ${tool.name}, capabilities: messaging, auth-manip`,
        location: `tool: ${tool.name}`,
        remediation: 'Separate messaging and authentication management into distinct, independently-authorized servers.',
      });
    }
  }

  return findings;
};
