import type { CheckFn, Finding, Tool } from '../types.js';

// ─── Patterns ─────────────────────────────────────────────────────────────────

// Zero-width chars, RTL/LTR overrides, Braille blank, BOM, invisible formatters
const HIDDEN_UNICODE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\u2800\uFEFF\u180E]/u;

const HTML_INJECTION_RE = /<(?:SYSTEM|system|script|iframe|img|style|link|meta|object|embed|form)[>\s/]|<!--[\s\S]*?-->|<\/(?:system|script|style)>/i;

const PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i,
  /disregard\s+(?:all\s+)?(?:previous|prior|above)/i,
  /override\s+(?:your\s+)?(?:instructions?|directives?|rules?|constraints?)/i,
  /\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>>/i,
  /you\s+are\s+now\s+(?:a|an)\s+\w/i,
  /new\s+(?:primary\s+)?(?:instruction|directive|rule|task)\s*:/i,
  /(?:from\s+now\s+on|henceforth)[,:]?\s+(?:you|act|behave|respond)/i,
  /pretend\s+(?:you\s+are|to\s+be)\s+(?:a|an|the)/i,
  /(?:act|behave)\s+as\s+(?:if\s+you\s+(?:are|were)|a|an)\s+\w/i,
  /do\s+not\s+(?:follow|obey|adhere\s+to)\s+(?:your|any|the)\s+(?:previous|prior|original|system)/i,
  /jailbreak|DAN\s+mode|developer\s+mode\s+enabled/i,
];

// Base64 strings of suspicious length
const BASE64_RE = /(?:[A-Za-z0-9+/]{48,}={0,2})/g;
// Keywords that would indicate a decoded payload is a shell command or injection
const PAYLOAD_KEYWORDS = /\b(?:curl|wget|bash|sh|python|perl|ruby|nc|netcat|chmod|eval|exec|import|require|\/etc\/|\.ssh|\.aws|passwd|shadow)\b/i;

// External URLs in markdown image/link syntax (not localhost/127.0.0.1)
const MARKDOWN_EXFIL_RE = /(?:!\[.*?\]|\[.*?\])\(https?:\/\/(?!localhost|127\.\d+\.\d+\.\d+|::1)[^)]+\)/gi;

const OVERLONG_THRESHOLD = 2000;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeId(seq: number): string {
  return `MCP-1${String(seq).padStart(2, '0')}`;
}

function extractTextFields(tool: Tool): Array<{ field: string; text: string }> {
  const fields: Array<{ field: string; text: string }> = [];

  fields.push({ field: 'name', text: tool.name });
  if (tool.description) fields.push({ field: 'description', text: tool.description });

  // Recurse through inputSchema property descriptions
  const schema = tool.inputSchema as Record<string, unknown> | undefined;
  if (schema?.['properties'] && typeof schema['properties'] === 'object') {
    for (const [propName, propDef] of Object.entries(schema['properties'] as Record<string, unknown>)) {
      if (typeof propDef === 'object' && propDef !== null) {
        const def = propDef as Record<string, unknown>;
        if (typeof def['description'] === 'string') {
          fields.push({ field: `inputSchema.properties.${propName}.description`, text: def['description'] });
        }
        if (typeof def['title'] === 'string') {
          fields.push({ field: `inputSchema.properties.${propName}.title`, text: def['title'] });
        }
      }
    }
  }

  return fields;
}

function tryDecodeBase64(s: string): string | null {
  try {
    return Buffer.from(s, 'base64').toString('utf-8');
  } catch {
    return null;
  }
}

// ─── Check ────────────────────────────────────────────────────────────────────

export const check: CheckFn = async (serverData) => {
  const findings: Finding[] = [];
  let seq = 1;

  for (const tool of serverData.tools) {
    const fields = extractTextFields(tool);
    const loc = (field: string) => `tool: ${tool.name} > ${field}`;

    for (const { field, text } of fields) {
      // 1. Hidden Unicode
      if (HIDDEN_UNICODE_RE.test(text)) {
        const chars = [...text].filter(c => HIDDEN_UNICODE_RE.test(c));
        findings.push({
          id: makeId(seq++),
          title: 'Tool Poisoning: Hidden Unicode Characters',
          severity: 'high',
          category: 'tool-poisoning',
          description: 'Tool metadata contains invisible Unicode characters commonly used to hide malicious instructions from human reviewers while LLMs process them.',
          evidence: `Found ${chars.length} hidden char(s): ${chars.map(c => `U+${c.codePointAt(0)!.toString(16).toUpperCase()}`).join(', ')}`,
          location: loc(field),
          remediation: 'Sanitize all tool metadata to remove invisible Unicode. Validate inputs server-side.',
        });
      }

      // 2. HTML/XML injection
      const htmlMatch = text.match(HTML_INJECTION_RE);
      if (htmlMatch) {
        findings.push({
          id: makeId(seq++),
          title: 'Tool Poisoning: HTML/XML Tag Injection',
          severity: 'high',
          category: 'tool-poisoning',
          description: 'Tool metadata contains HTML or XML tags that can be interpreted as special instructions by some LLMs.',
          evidence: htmlMatch[0].slice(0, 200),
          location: loc(field),
          remediation: 'Strip all HTML/XML tags from tool names, descriptions, and parameter definitions.',
        });
      }

      // 3. Prompt injection keywords
      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        const piMatch = text.match(pattern);
        if (piMatch) {
          findings.push({
            id: makeId(seq++),
            title: 'Tool Poisoning: Prompt Injection Instruction',
            severity: 'critical',
            category: 'tool-poisoning',
            description: 'Tool metadata contains explicit prompt injection language designed to override LLM system instructions.',
            evidence: piMatch[0].slice(0, 200),
            location: loc(field),
            remediation: 'Remove all instruction-like language from tool metadata. Tool descriptions should only explain functionality.',
          });
          break; // One finding per field for prompt injection
        }
      }

      // 4. Base64 encoded payloads
      BASE64_RE.lastIndex = 0;
      let b64Match: RegExpExecArray | null;
      while ((b64Match = BASE64_RE.exec(text)) !== null) {
        const decoded = tryDecodeBase64(b64Match[0]);
        if (decoded && PAYLOAD_KEYWORDS.test(decoded)) {
          findings.push({
            id: makeId(seq++),
            title: 'Tool Poisoning: Encoded Payload in Metadata',
            severity: 'high',
            category: 'tool-poisoning',
            description: 'Tool metadata contains a base64-encoded string that decodes to what appears to be a shell command or injection payload.',
            evidence: `Encoded: ${b64Match[0].slice(0, 60)}… → Decoded: ${decoded.slice(0, 120)}`,
            location: loc(field),
            remediation: 'Audit why base64 payloads appear in tool metadata. Remove obfuscated content.',
          });
        }
      }

      // 5. Overlong description
      if (field === 'description' && text.length > OVERLONG_THRESHOLD) {
        findings.push({
          id: makeId(seq++),
          title: 'Tool Poisoning: Suspiciously Long Description',
          severity: 'medium',
          category: 'tool-poisoning',
          description: `Tool description is ${text.length} characters — significantly above normal. Attackers embed hidden instructions in lengthy descriptions to evade quick reviews.`,
          evidence: `Length: ${text.length} chars (first 200): ${text.slice(0, 200)}`,
          location: loc(field),
          remediation: 'Keep tool descriptions concise. Audit any description exceeding 500 characters.',
        });
      }

      // 6. Markdown exfiltration URLs
      MARKDOWN_EXFIL_RE.lastIndex = 0;
      const exfilMatch = MARKDOWN_EXFIL_RE.exec(text);
      if (exfilMatch) {
        findings.push({
          id: makeId(seq++),
          title: 'Tool Poisoning: Markdown Exfiltration Link',
          severity: 'high',
          category: 'tool-poisoning',
          description: 'Tool metadata contains a markdown link/image pointing to an external URL, which could be used to exfiltrate context when rendered by an LLM.',
          evidence: exfilMatch[0].slice(0, 200),
          location: loc(field),
          remediation: 'Remove all external URLs from tool metadata. Tool descriptions should not contain links.',
        });
      }
    }
  }

  return findings;
};
