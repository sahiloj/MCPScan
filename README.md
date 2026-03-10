<p align="center">
  <img src="mcpscan-logo.svg" alt="MCPScan" width="560" />
</p>

<p align="center">
  <strong>Offensive MCP Server Security Auditor</strong><br>
  <a href="#checks">Checks</a> · <a href="#install">Install</a> · <a href="#usage">Usage</a> · <a href="#cve-references">CVEs</a>
</p>

---

# MCPScan

An offensive security auditor for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers. Connects to servers, enumerates their tools, resources, and prompts, then runs a battery of security checks covering tool poisoning, credential leakage, RCE vectors, supply chain vulnerabilities, and more.

```
  MCPScan — Offensive MCP Server Auditor
  ──────────────────────────────────────────────────────────

Server: filesystem-server (STDIO: npx @modelcontextprotocol/server-filesystem /home)

   CRITICAL   MCP-701  RCE Vector: Shell/Execution Parameter Name
              Location:  tool: bash_exec > inputSchema
              Evidence:  Dangerous params: command, args
              CVE:       CVE-2025-6514 (CVSS 9.6)
              Fix:       Use allowlists; never pass raw input to shell functions

   HIGH       MCP-304  Overprivileged: Unrestricted Filesystem Path Parameter
              Location:  tool: write_file > inputSchema
              Evidence:  Tool: write_file, capabilities: fs-write
              Fix:       Add a path allow-list restricting access to approved directories

╭─────────── MCPScan Results ────────────╮
│                                        │
│   Scanned 3 servers                    │
│   2 critical  ·  5 high  ·  1 medium   │
│                                        │
╰────────────────────────────────────────╯
```

## Background

The MCP ecosystem has a serious security problem. Researchers have documented:

- **Tool poisoning** — hidden instructions in tool descriptions manipulate LLM behavior ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), >72% success rate)
- **RCE via MCP infrastructure** — CVE-2025-6514 (CVSS 9.6) in `mcp-remote`, used by ~500,000 developers
- **492+ unauthenticated servers** — publicly exposed, offering direct data access with no auth
- **Credential leakage** — API keys, JWTs, and connection strings embedded in tool metadata
- **Supply chain attacks** — compromised npm packages creating malicious MCP modules

No dedicated offensive scanner existed. MCPScan fills that gap.

## Checks

| ID Range | Category | What It Finds |
|---|---|---|
| MCP-1xx | `tool-poisoning` | Hidden Unicode, HTML/XML injection, prompt injection keywords, base64 payloads, overlong descriptions, markdown exfiltration links |
| MCP-2xx | `credential-leak` | AWS keys, Anthropic/OpenAI API keys, GitHub PATs, JWTs, private keys, DB connection strings, Slack/Stripe tokens |
| MCP-3xx | `overprivileged` | Shell+filesystem combos, shell+network combos, code eval, unrestricted path params, sensitive path access |
| MCP-4xx | `auth-missing` | Unauthenticated server response, CORS wildcard, 0.0.0.0 binding, missing security headers |
| MCP-5xx | `session-hijack` | Session ID in URL params, predictable session IDs, long cookie lifetime, missing Secure/HttpOnly flags |
| MCP-6xx | `ssrf` | User-supplied URL parameters, webhook/callback params, HTTP resource URI templates with variables |
| MCP-7xx | `rce-vectors` | `command`/`exec`/`eval` parameter names, execution intent in descriptions, sanitization claims, shell-named tools |
| MCP-8xx | `supply-chain` | CVE version ranges, missing lockfile, typosquatted MCP package names |

### CVE References

| CVE | Package | CVSS | Description |
|---|---|---|---|
| CVE-2025-6514 | `mcp-remote` | 9.6 | Arbitrary OS command execution — first documented full system compromise via MCP |
| CVE-2025-49596 | `@modelcontextprotocol/inspector` | 9.4 | Unauthenticated RCE via inspector-proxy architecture |
| CVE-2025-53967 | `figma-developer-mcp` | 8.2 | Command injection via unsanitized shell string interpolation |
| CVE-2026-25536 | `@modelcontextprotocol/sdk` | 7.5 | StreamableHTTPServerTransport data leakage across clients (v1.10.0–1.25.3) |
| CVE-2025-59536 | `@anthropic-ai/claude-code` | 9.1 | Project file RCE and API token exfiltration |

## Install

**Prerequisites:** Node.js ≥18

```bash
git clone <this-repo>
cd mcpscan
npm install
npm run build
```

Run directly from the dist folder:

```bash
node dist/cli.js scan --help
```

Or link globally:

```bash
npm link
mcpscan scan --help
```

## Usage

### Scan a stdio server (spawn and audit)

```bash
node dist/cli.js scan --command "npx" --args "-y @modelcontextprotocol/server-filesystem /home/user"
```

### Scan from Claude Desktop config

```bash
node dist/cli.js scan --config ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Auto-discover all known config locations

Searches `claude_desktop_config.json`, `.mcp.json`, `.cursor/mcp.json`, and other standard paths:

```bash
node dist/cli.js scan --all-configs
```

### Scan a remote HTTP/SSE server

```bash
node dist/cli.js scan --target http://localhost:3000/mcp
```

### Scan localhost ports for exposed servers

```bash
node dist/cli.js scan --all-configs --network
```

### Run specific checks only

```bash
node dist/cli.js scan --all-configs --checks tool-poisoning,credential-leak,rce-vectors
```

### Filter by severity

```bash
node dist/cli.js scan --all-configs --severity high
```

### JSON output (for pipelines)

```bash
node dist/cli.js scan --all-configs --output json | jq '.summary'
```

### SARIF output (for GitHub Code Scanning, security dashboards)

```bash
node dist/cli.js scan --all-configs --output sarif > findings.sarif
```

### Discover without scanning

```bash
node dist/cli.js discover --all-configs
node dist/cli.js discover --all-configs --network --output json
```

## All Options

```
mcpscan scan [options]

  -c, --config <path>    Path to claude_desktop_config.json or .mcp.json
  -t, --target <url>     Direct HTTP/SSE MCP server URL
  --command <cmd>        Spawn and scan a stdio server with this command
  --args <args>          Space-separated args for --command
  --all-configs          Auto-discover all known MCP config locations
  --network              Also probe localhost ports for HTTP servers
  --checks <list>        Comma-separated checks (default: all)
  -o, --output <format>  terminal | json | sarif  (default: terminal)
  --severity <level>     critical | high | medium | low | info  (default: info)
  --timeout <ms>         Per-server timeout  (default: 30000)
  --verbose              Show check errors and debug output
```

## Config File Locations Searched

When `--all-configs` is used, MCPScan searches:

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Any | `.mcp.json` (cwd) |
| Any | `.cursor/mcp.json` (cwd) |
| Any | `~/.config/mcp/config.json` |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings above the minimum severity |
| `1` | High severity findings detected |
| `2` | Critical severity findings detected |

Useful for gating CI/CD pipelines:

```bash
node dist/cli.js scan --all-configs --severity high
if [ $? -eq 2 ]; then echo "CRITICAL findings — blocking deploy"; exit 1; fi
```

## Output Formats

### Terminal

Rich colored output with severity labels, evidence, CVE references, and a summary box. Default.

### JSON

Structured report with full finding details, suitable for ingestion by SIEMs and custom tooling:

```json
{
  "tool": "mcpscan",
  "version": "0.1.0",
  "timestamp": "2026-03-10T12:00:00.000Z",
  "summary": {
    "serversScanned": 3,
    "serversEnumerated": 3,
    "totalFindings": 7,
    "findingsBySeverity": {
      "critical": 2,
      "high": 3,
      "medium": 1,
      "low": 1,
      "info": 0
    }
  },
  "results": [...]
}
```

### SARIF 2.1.0

Compatible with GitHub Advanced Security, VS Code SARIF Viewer, and any SARIF-aware platform. Each finding maps to a SARIF rule with `security-severity` scores for risk-based triage.

## Architecture

```
src/
├── cli.ts                    Entry point, commander argument parsing
├── scanner.ts                Orchestrator: enumerate → checks → report
├── types.ts                  Shared interfaces (Finding, ScanResult, CheckFn, ...)
├── discovery/
│   ├── config-reader.ts      Parses known MCP config file formats (Zod-validated)
│   └── network-scan.ts       Probes localhost ports for HTTP MCP servers
├── transport/
│   ├── stdio-client.ts       StdioClientTransport with timeout + cleanup
│   └── http-client.ts        StreamableHTTP with SSE fallback; captures headers
├── checks/
│   ├── tool-poisoning.ts     MCP-1xx
│   ├── credential-leak.ts    MCP-2xx
│   ├── overprivileged.ts     MCP-3xx
│   ├── auth-missing.ts       MCP-4xx
│   ├── session-hijack.ts     MCP-5xx
│   ├── ssrf.ts               MCP-6xx
│   ├── rce-vectors.ts        MCP-7xx
│   └── supply-chain.ts       MCP-8xx
└── report/
    ├── terminal.ts           Chalk + Boxen colored terminal output
    └── json.ts               JSON and SARIF 2.1.0 serialization
```

Each check module exports a single `async function check(serverData: ServerData): Promise<Finding[]>`. The scanner runs all enabled checks in parallel via `Promise.allSettled` — a failing check never blocks others.

## Finding Schema

```typescript
interface Finding {
  id: string;          // "MCP-701"
  title: string;       // "RCE Vector: Shell/Execution Parameter Name"
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;    // "rce-vectors"
  description: string; // Full explanation
  evidence: string;    // The specific text/value that triggered the finding
  location: string;    // "tool: bash_exec > inputSchema.properties.command"
  cve?: string;        // "CVE-2025-6514"
  cvss?: number;       // 9.6
  remediation: string; // Actionable fix guidance
}
```

## Development

```bash
# Type-check without building
npm run typecheck

# Run directly with tsx (no build needed)
npm run dev -- scan --all-configs

# Rebuild
npm run build
```

## References

- [MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25)
- [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/2025/)
- [Tool Poisoning Attacks — Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [CVE-2025-6514 — JFrog](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [Palo Alto Unit 42 — MCP Attack Vectors](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)

## License

MIT
