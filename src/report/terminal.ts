import chalk from 'chalk';
import boxen from 'boxen';
import type { Finding, ScanResult, Severity } from '../types.js';

// ─── Severity styling ─────────────────────────────────────────────────────────

function severityLabel(s: Severity): string {
  switch (s) {
    case 'critical': return chalk.bgRed.white.bold(' CRITICAL ');
    case 'high':     return chalk.bgYellow.black.bold('  HIGH    ');
    case 'medium':   return chalk.bgBlue.white.bold(' MEDIUM   ');
    case 'low':      return chalk.bgGray.white.bold('  LOW     ');
    case 'info':     return chalk.bgWhite.black.bold('  INFO    ');
  }
}

function severityColor(s: Severity): (t: string) => string {
  switch (s) {
    case 'critical': return chalk.red.bold;
    case 'high':     return chalk.yellow.bold;
    case 'medium':   return chalk.blue;
    case 'low':      return chalk.gray;
    case 'info':     return chalk.white;
  }
}

// ─── Single finding ───────────────────────────────────────────────────────────

function formatFinding(f: Finding, index: number): string {
  const color = severityColor(f.severity);
  const indent = '          '; // 10 spaces to align with label

  const lines: string[] = [
    '',
    `  ${severityLabel(f.severity)}  ${chalk.bold(f.id)}  ${color(f.title)}`,
    `${indent}${chalk.dim('Location:')}  ${f.location}`,
    `${indent}${chalk.dim('Evidence:')}  ${f.evidence}`,
  ];

  if (f.cve) {
    const cvssStr = f.cvss !== undefined ? ` (CVSS ${f.cvss})` : '';
    lines.push(`${indent}${chalk.dim('CVE:     ')}  ${chalk.cyan(f.cve)}${cvssStr}`);
  }

  lines.push(`${indent}${chalk.dim('Fix:     ')}  ${chalk.green(f.remediation)}`);

  return lines.join('\n');
}

// ─── Server section ───────────────────────────────────────────────────────────

function formatServer(result: ScanResult): string {
  const lines: string[] = [];
  const { server, findings, scanDuration, error, enumerated } = result;

  const transportLabel = server.transport.toUpperCase();
  const configSummary =
    server.config.type === 'stdio'
      ? `${server.config.command}${server.config.args?.length ? ' ' + server.config.args.join(' ') : ''}`
      : server.config.url;

  lines.push('');
  lines.push(chalk.bold.underline(`Server: ${server.name}`) + chalk.dim(` (${transportLabel}: ${configSummary})`));

  if (error) {
    lines.push(chalk.red(`  Connection failed: ${error}`));
    return lines.join('\n');
  }

  if (enumerated) {
    const toolCount = chalk.cyan(String(result.server.version ? `v${result.server.version} · ` : ''));
    lines.push(
      chalk.dim(`  Enumerated in ${(scanDuration / 1000).toFixed(1)}s`) +
      (toolCount ? '  ' + toolCount : ''),
    );
  }

  if (findings.length === 0) {
    lines.push(chalk.green('  No findings above the minimum severity threshold.'));
    return lines.join('\n');
  }

  for (const finding of findings) {
    lines.push(formatFinding(finding, 0));
  }

  return lines.join('\n');
}

// ─── Summary box ──────────────────────────────────────────────────────────────

function buildSummary(results: ScanResult[]): string {
  const total = results.length;
  const enumerated = results.filter(r => r.enumerated).length;
  const failed = total - enumerated;

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const result of results) {
    for (const f of result.findings) {
      counts[f.severity]++;
    }
  }

  const totalFindings = Object.values(counts).reduce((a, b) => a + b, 0);

  const parts: string[] = [
    chalk.bold(`Scanned ${total} server${total !== 1 ? 's' : ''}`),
    enumerated !== total ? chalk.red(`${failed} failed to connect`) : '',
    '',
    totalFindings === 0
      ? chalk.green('No findings.')
      : [
          counts.critical > 0 ? chalk.red.bold(`${counts.critical} critical`) : '',
          counts.high > 0 ? chalk.yellow.bold(`${counts.high} high`) : '',
          counts.medium > 0 ? chalk.blue(`${counts.medium} medium`) : '',
          counts.low > 0 ? chalk.gray(`${counts.low} low`) : '',
          counts.info > 0 ? chalk.white(`${counts.info} info`) : '',
        ].filter(Boolean).join('  ·  '),
  ].filter(s => s !== '');

  return boxen(parts.join('\n'), {
    title: 'MCPScan Results',
    titleAlignment: 'center',
    padding: 1,
    borderStyle: 'round',
    borderColor: counts.critical > 0 ? 'red' : counts.high > 0 ? 'yellow' : 'green',
  });
}

// ─── Main render ──────────────────────────────────────────────────────────────

export function renderTerminal(results: ScanResult[]): void {
  // Header
  console.log(
    chalk.bold.cyan('\n  MCPScan') +
    chalk.dim(' — Offensive MCP Server Auditor') +
    chalk.dim('\n  ' + '─'.repeat(50)),
  );

  for (const result of results) {
    console.log(formatServer(result));
  }

  console.log('\n' + buildSummary(results));
}
