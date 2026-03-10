import fs from 'node:fs/promises';
import path from 'node:path';
import semver from 'semver';
import type { CheckFn, Finding, StdioServerConfig } from '../types.js';

// ─── CVE database ─────────────────────────────────────────────────────────────

interface CveEntry {
  id: string;
  pkg: string;
  cve: string;
  title: string;
  description: string;
  cvss: number;
  affectedRange: string;  // semver range
  remediation: string;
}

const CVE_DB: CveEntry[] = [
  {
    id: 'MCP-801',
    pkg: '@modelcontextprotocol/sdk',
    cve: 'CVE-2026-25536',
    title: 'StreamableHTTPServerTransport Data Leakage Across Clients',
    description: 'MCP TypeScript SDK versions 1.10.0–1.25.3 have a data leakage vulnerability in StreamableHTTPServerTransport where responses can be sent to the wrong client, exposing one user\'s data to another.',
    cvss: 7.5,
    affectedRange: '>=1.10.0 <=1.25.3',
    remediation: 'Upgrade @modelcontextprotocol/sdk to version 1.25.4 or later.',
  },
  {
    id: 'MCP-802',
    pkg: 'mcp-remote',
    cve: 'CVE-2025-6514',
    title: 'mcp-remote Arbitrary OS Command Execution (RCE)',
    description: 'mcp-remote, an OAuth proxy used by ~500,000 developers to connect Claude Desktop to remote MCP servers, allows arbitrary OS command execution via a crafted server response. This is the first documented full system compromise via MCP infrastructure.',
    cvss: 9.6,
    affectedRange: '*',  // All versions — check for its presence
    remediation: 'Remove mcp-remote if not strictly necessary. If required, update to a patched version and monitor for upstream patches at https://github.com/geelen/mcp-remote.',
  },
  {
    id: 'MCP-803',
    pkg: '@modelcontextprotocol/inspector',
    cve: 'CVE-2025-49596',
    title: 'MCP Inspector Unauthenticated RCE via Proxy Architecture',
    description: 'MCP Inspector contains an unauthenticated RCE vulnerability via its inspector-proxy architecture. An attacker with network access to the inspector port can execute arbitrary commands on the host.',
    cvss: 9.4,
    affectedRange: '*',  // All known versions
    remediation: 'Remove @modelcontextprotocol/inspector from production deployments. Use it only in isolated development environments. Bind the inspector only to localhost.',
  },
  {
    id: 'MCP-804',
    pkg: 'figma-developer-mcp',
    cve: 'CVE-2025-53967',
    title: 'Framelink Figma MCP Command Injection via Shell Interpolation',
    description: 'Framelink Figma MCP (figma-developer-mcp) is vulnerable to command injection through unsanitized shell string interpolation in tool execution paths.',
    cvss: 8.2,
    affectedRange: '*',
    remediation: 'Update figma-developer-mcp to the latest patched version. Monitor the Framelink security advisories.',
  },
  {
    id: 'MCP-805',
    pkg: '@anthropic-ai/claude-code',
    cve: 'CVE-2025-59536',
    title: 'Claude Code Project Files RCE and Token Exfiltration',
    description: 'Maliciously crafted project files loaded by Claude Code can trigger RCE and exfiltrate the user\'s Anthropic API token.',
    cvss: 9.1,
    affectedRange: '*',
    remediation: 'Update @anthropic-ai/claude-code to the latest version. Never open project files from untrusted sources.',
  },
];

// ─── Package resolution helpers ───────────────────────────────────────────────

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

async function findPackageRoot(startPath: string, maxLevels = 10): Promise<string | null> {
  let current = path.dirname(startPath);
  for (let i = 0; i < maxLevels; i++) {
    try {
      await fs.access(path.join(current, 'package.json'));
      return current;
    } catch {
      const parent = path.dirname(current);
      if (parent === current) break; // Reached filesystem root
      current = parent;
    }
  }
  return null;
}

async function readPackageJson(dir: string): Promise<PackageJson | null> {
  try {
    const text = await fs.readFile(path.join(dir, 'package.json'), 'utf-8');
    return JSON.parse(text) as PackageJson;
  } catch {
    return null;
  }
}

async function resolveInstalledVersion(packageDir: string, pkgName: string): Promise<string | null> {
  // Scope-aware path building: @scope/name → @scope/name
  const nmPath = path.join(packageDir, 'node_modules', pkgName, 'package.json');
  try {
    const text = await fs.readFile(nmPath, 'utf-8');
    const pkg = JSON.parse(text) as PackageJson;
    return pkg.version ?? null;
  } catch {
    return null;
  }
}

async function hasLockfile(dir: string): Promise<boolean> {
  const lockfiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb'];
  for (const lf of lockfiles) {
    try {
      await fs.access(path.join(dir, lf));
      return true;
    } catch {
      continue;
    }
  }
  return false;
}

async function resolveCommand(command: string): Promise<string | null> {
  // Try to find the absolute path if it's not already absolute
  if (path.isAbsolute(command)) return command;

  // Check common npm global binary locations
  const { execSync } = await import('node:child_process');
  try {
    const result = execSync(`which ${command} 2>/dev/null`, { encoding: 'utf-8' }).trim();
    return result || null;
  } catch {
    return null;
  }
}

// ─── Check ────────────────────────────────────────────────────────────────────

export const check: CheckFn = async (serverData) => {
  if (serverData.serverInfo.transport !== 'stdio') return [];

  const findings: Finding[] = [];
  const config = serverData.serverInfo.config as StdioServerConfig;

  // Resolve the executable to a filesystem path
  const execPath = serverData.executablePath ?? (await resolveCommand(config.command));
  if (!execPath) return findings;

  const packageDir = await findPackageRoot(execPath);
  if (!packageDir) return findings;

  const pkgJson = await readPackageJson(packageDir);
  if (!pkgJson) return findings;

  const allDeps: Record<string, string> = {
    ...(pkgJson.dependencies ?? {}),
    ...(pkgJson.devDependencies ?? {}),
  };

  // ── CVE checks ─────────────────────────────────────────────────────────────

  for (const entry of CVE_DB) {
    // Check if the package is declared in any dependency field
    const declaredVersion = allDeps[entry.pkg];
    const isPresent = declaredVersion !== undefined || pkgJson.name === entry.pkg;

    if (!isPresent) continue;

    if (entry.affectedRange === '*') {
      // All versions affected — presence alone is the finding
      findings.push({
        id: entry.id,
        title: `Supply Chain: ${entry.title}`,
        severity: entry.cvss >= 9.0 ? 'critical' : entry.cvss >= 7.0 ? 'high' : 'medium',
        category: 'supply-chain',
        description: entry.description,
        evidence: `${entry.pkg}@${declaredVersion ?? 'installed'} found in ${path.join(packageDir, 'package.json')}`,
        location: `package: ${packageDir}/package.json`,
        cve: entry.cve,
        cvss: entry.cvss,
        remediation: entry.remediation,
      });
    } else {
      // Check the actually installed version (more accurate than declared range)
      const installedVersion = await resolveInstalledVersion(packageDir, entry.pkg);
      const versionToCheck = installedVersion ?? semver.minVersion(declaredVersion ?? '0.0.0')?.version;

      if (versionToCheck && semver.satisfies(versionToCheck, entry.affectedRange)) {
        findings.push({
          id: entry.id,
          title: `Supply Chain: ${entry.title}`,
          severity: entry.cvss >= 9.0 ? 'critical' : entry.cvss >= 7.0 ? 'high' : 'medium',
          category: 'supply-chain',
          description: entry.description,
          evidence: `${entry.pkg}@${installedVersion ?? declaredVersion} satisfies vulnerable range ${entry.affectedRange}`,
          location: `package: ${packageDir}/package.json`,
          cve: entry.cve,
          cvss: entry.cvss,
          remediation: entry.remediation,
        });
      }
    }
  }

  // ── MCP-806: Missing lockfile ──────────────────────────────────────────────

  if (!(await hasLockfile(packageDir))) {
    findings.push({
      id: 'MCP-806',
      title: 'Supply Chain: No Dependency Lockfile',
      severity: 'medium',
      category: 'supply-chain',
      description: 'The MCP server package has no lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, or bun.lockb). Without a lockfile, dependency versions are not pinned and can be silently updated to compromised versions during npm install.',
      evidence: `No lockfile found in ${packageDir}`,
      location: `package: ${packageDir}`,
      remediation: 'Add a lockfile by running "npm install" (creates package-lock.json) and commit it to source control. Never gitignore lockfiles for production deployments.',
    });
  }

  // ── MCP-807: Suspicious package name typosquat patterns ───────────────────

  const KNOWN_LEGIT_MCP_PKGS = [
    '@modelcontextprotocol/sdk',
    '@modelcontextprotocol/server-filesystem',
    '@modelcontextprotocol/server-github',
    '@modelcontextprotocol/server-brave-search',
    '@modelcontextprotocol/server-fetch',
    '@modelcontextprotocol/inspector',
    'mcp-remote',
  ];

  const TYPOSQUAT_PATTERNS = [
    /^model[-_]context[-_]protocol/i,
    /^mcp[-_]sdk/i,
    /^@modelcontextprotocoo/i,  // typo: modelcontextprotocoo
    /^modelcontextprotocol(?!\/)/i,  // missing scope @
  ];

  for (const dep of Object.keys(allDeps)) {
    if (KNOWN_LEGIT_MCP_PKGS.includes(dep)) continue;
    for (const pattern of TYPOSQUAT_PATTERNS) {
      if (pattern.test(dep)) {
        findings.push({
          id: 'MCP-807',
          title: 'Supply Chain: Possible MCP Package Typosquat',
          severity: 'high',
          category: 'supply-chain',
          description: `Dependency "${dep}" resembles an official MCP package name but is not on the known-legitimate list. This may be a typosquatted package distributing malware.`,
          evidence: `Suspicious dependency: ${dep}@${allDeps[dep]}`,
          location: `package: ${packageDir}/package.json`,
          remediation: `Verify "${dep}" is intentional. Compare against official @modelcontextprotocol packages. Remove if unexpected.`,
        });
        break;
      }
    }
  }

  return findings;
};
