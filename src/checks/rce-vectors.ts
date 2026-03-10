import type { CheckFn, Finding } from '../types.js';

// Parameter names that directly suggest shell/code execution
const RCE_PARAM_NAMES = new Set([
  'command', 'cmd', 'shell', 'exec', 'execute', 'run',
  'script', 'code', 'eval', 'expression', 'input',
  'program', 'binary', 'executable', 'process', 'args',
  'argv', 'cmdline', 'cmdargs', 'bash', 'sh',
]);

// Tool description patterns indicating execution intent
const RCE_DESCRIPTION_PATTERNS: RegExp[] = [
  /execut(?:e|es|ing)\s+(?:arbitrary\s+)?(?:command|script|code|shell|program)/i,
  /run(?:s|ning)?\s+(?:arbitrary\s+)?(?:command|script|code|shell|program)/i,
  /spawn(?:s|ing)?\s+(?:a\s+)?(?:process|subprocess|child\s+process)/i,
  /eval(?:uate)?s?\s+(?:arbitrary\s+)?(?:code|expression|javascript|python|ruby)/i,
  /(?:invoke|call)\s+(?:system|os|subprocess|shell)/i,
  /(?:arbitrary|user.provided|custom)\s+(?:code|command|script)/i,
  /bash\s+(?:command|script|one.liner)/i,
  /shell\s+(?:command|script|injection|execution)/i,
];

// Patterns suggesting the tool knows it handles shell commands (sanitization claims)
// Paradoxically, these confirm the tool handles shell input
const SANITIZATION_CLAIM_PATTERNS: RegExp[] = [
  /(?:sanitize|sanitized|escaped|safe\s+from|protected\s+against|prevent(?:ing)?)\s+(?:injection|shell|command)/i,
  /shell\s+(?:characters?\s+are|metacharacters?\s+are|input\s+is)\s+(?:escaped|sanitized|safe)/i,
  /no\s+(?:shell|command)\s+injection/i,
];

export const check: CheckFn = async (serverData) => {
  const findings: Finding[] = [];

  for (const tool of serverData.tools) {
    const desc = tool.description ?? '';
    const schema = tool.inputSchema as Record<string, unknown> | undefined;
    const props = (schema?.['properties'] && typeof schema['properties'] === 'object')
      ? schema['properties'] as Record<string, unknown>
      : {};
    const paramNames = Object.keys(props).map(k => k.toLowerCase());

    // ── MCP-701: RCE parameter names ────────────────────────────────────────
    const dangerousParams = paramNames.filter(p => RCE_PARAM_NAMES.has(p));
    if (dangerousParams.length > 0) {
      // Determine severity by param specificity
      const isCritical = dangerousParams.some(p =>
        ['command', 'cmd', 'shell', 'exec', 'execute', 'eval', 'code', 'script', 'bash', 'sh'].includes(p),
      );

      findings.push({
        id: 'MCP-701',
        title: 'RCE Vector: Shell/Execution Parameter Name',
        severity: isCritical ? 'critical' : 'high',
        category: 'rce-vectors',
        description: `Tool "${tool.name}" has parameter(s) whose names strongly suggest shell command or code execution: ${dangerousParams.join(', ')}. If user input reaches a shell, this is an RCE vulnerability. References CVE-2025-6514 (mcp-remote, CVSS 9.6) and CVE-2025-53967 (Framelink, CVSS 8.2).`,
        evidence: `Dangerous params: ${dangerousParams.join(', ')}`,
        location: `tool: ${tool.name} > inputSchema`,
        cve: 'CVE-2025-6514',
        cvss: 9.6,
        remediation: 'Use an allowlist of permitted commands/operations rather than passing raw user input to shell functions. Use subprocess APIs with argument arrays, never string interpolation.',
      });
    }

    // ── MCP-702: RCE description patterns ────────────────────────────────────
    for (const pattern of RCE_DESCRIPTION_PATTERNS) {
      const match = desc.match(pattern);
      if (match) {
        findings.push({
          id: 'MCP-702',
          title: 'RCE Vector: Tool Description Indicates Execution Capability',
          severity: 'high',
          category: 'rce-vectors',
          description: `Tool "${tool.name}" description explicitly mentions executing commands, scripts, or arbitrary code.`,
          evidence: match[0].slice(0, 200),
          location: `tool: ${tool.name} > description`,
          cve: 'CVE-2025-53967',
          cvss: 8.2,
          remediation: 'Restrict execution to a predefined set of safe operations. Never execute strings from LLM output without strict validation.',
        });
        break;
      }
    }

    // ── MCP-703: Sanitization claims (paradoxical signal) ──────────────────
    for (const pattern of SANITIZATION_CLAIM_PATTERNS) {
      const match = desc.match(pattern);
      if (match) {
        findings.push({
          id: 'MCP-703',
          title: 'RCE Vector: Tool Claims Sanitization (Shell Handling Confirmed)',
          severity: 'medium',
          category: 'rce-vectors',
          description: `Tool "${tool.name}" explicitly claims to sanitize shell input, confirming it handles shell commands. Sanitization bypass vulnerabilities are common; this warrants manual review.`,
          evidence: match[0].slice(0, 200),
          location: `tool: ${tool.name} > description`,
          remediation: 'Review the sanitization implementation. Shell escaping is error-prone — prefer allowlisting safe commands over blocklisting dangerous characters.',
        });
        break;
      }
    }

    // ── MCP-704: Tool name is a shell command ──────────────────────────────
    const shellCommandNames = ['exec', 'eval', 'shell', 'bash', 'sh', 'cmd', 'run_code', 'execute_code', 'run_command', 'execute_command'];
    if (shellCommandNames.includes(tool.name.toLowerCase())) {
      findings.push({
        id: 'MCP-704',
        title: 'RCE Vector: Tool Name Indicates Direct Shell Access',
        severity: 'critical',
        category: 'rce-vectors',
        description: `Tool is named "${tool.name}" — a name that directly implies shell or code execution access. This is the highest-risk tool category in MCP ecosystems.`,
        evidence: `Tool name: ${tool.name}`,
        location: `tool: ${tool.name}`,
        remediation: 'Remove or heavily restrict this tool. If required, implement strict allowlisting, sandboxing, and audit logging for all invocations.',
      });
    }
  }

  return findings;
};
