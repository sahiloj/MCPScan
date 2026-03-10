#!/usr/bin/env node
import { program } from 'commander';
import ora from 'ora';
import chalk from 'chalk';
import { readConfigFile, discoverConfigs, getDefaultConfigPaths } from './discovery/config-reader.js';
import { scanLocalPorts } from './discovery/network-scan.js';
import { scanAll } from './scanner.js';
import { renderTerminal } from './report/terminal.js';
import { toJson, toSarif } from './report/json.js';
import type {
  CheckCategory,
  ServerConfig,
  ScanOptions,
  Severity,
} from './types.js';
import { ALL_CATEGORIES } from './types.js';

// ─── Version ──────────────────────────────────────────────────────────────────

const VERSION = '0.1.0';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseCategories(input: string | undefined): CheckCategory[] {
  if (!input) return ALL_CATEGORIES;
  const items = input.split(',').map(s => s.trim()) as CheckCategory[];
  const invalid = items.filter(c => !ALL_CATEGORIES.includes(c));
  if (invalid.length > 0) {
    console.error(`Unknown check(s): ${invalid.join(', ')}`);
    console.error(`Valid checks: ${ALL_CATEGORIES.join(', ')}`);
    process.exit(1);
  }
  return items;
}

function parseSeverity(input: string | undefined): Severity {
  const valid: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  if (!input) return 'info';
  if (!valid.includes(input as Severity)) {
    console.error(`Invalid severity "${input}". Valid: ${valid.join(', ')}`);
    process.exit(1);
  }
  return input as Severity;
}

// ─── Program setup ────────────────────────────────────────────────────────────

program
  .name('mcpscan')
  .description('Offensive MCP server security auditor\nEnumerates servers, checks for tool poisoning, credential leakage, RCE vectors, and supply chain vulnerabilities.')
  .version(VERSION, '-v, --version');

// ─── scan command ─────────────────────────────────────────────────────────────

program
  .command('scan')
  .description('Scan MCP server(s) for security vulnerabilities')
  .option('-c, --config <path>', 'Path to claude_desktop_config.json or .mcp.json')
  .option('-t, --target <url>', 'Direct HTTP/SSE MCP server URL to scan')
  .option('--command <cmd>', 'Spawn and scan a stdio MCP server with this command')
  .option('--args <args>', 'Space-separated args for --command (quote the whole string)')
  .option('--all-configs', 'Auto-discover and scan all known MCP config locations')
  .option('--network', 'Also scan localhost ports for exposed HTTP MCP servers')
  .option('--checks <list>', `Comma-separated checks to run (default: all)\nAvailable: ${ALL_CATEGORIES.join(', ')}`)
  .option('-o, --output <format>', 'Output format: terminal|json|sarif (default: terminal)', 'terminal')
  .option('--severity <level>', 'Minimum severity to report: critical|high|medium|low|info (default: info)', 'info')
  .option('--timeout <ms>', 'Per-server connection timeout in milliseconds (default: 30000)', '30000')
  .option('--verbose', 'Show verbose output including check errors')
  .action(async (opts: {
    config?: string;
    target?: string;
    command?: string;
    args?: string;
    allConfigs?: boolean;
    network?: boolean;
    checks?: string;
    output: string;
    severity: string;
    timeout: string;
    verbose?: boolean;
  }) => {
    const options: ScanOptions = {
      checks: parseCategories(opts.checks),
      outputFormat: opts.output as ScanOptions['outputFormat'],
      minSeverity: parseSeverity(opts.severity),
      timeout: parseInt(opts.timeout, 10) || 30000,
      verbose: opts.verbose ?? false,
    };

    const servers = new Map<string, ServerConfig>();

    // --config
    if (opts.config) {
      const spinner = ora(`Reading config: ${opts.config}`).start();
      try {
        const cfg = await readConfigFile(opts.config);
        cfg.forEach((v, k) => servers.set(k, v));
        spinner.succeed(`Loaded ${cfg.size} server(s) from ${opts.config}`);
      } catch (err) {
        spinner.fail(err instanceof Error ? err.message : String(err));
        process.exit(1);
      }
    }

    // --all-configs
    if (opts.allConfigs) {
      const spinner = ora('Discovering MCP configs...').start();
      const discovered = await discoverConfigs();
      discovered.forEach((v, k) => servers.set(k, v));
      spinner.succeed(`Discovered ${discovered.size} server(s) from known config locations`);
    }

    // --target (HTTP/SSE)
    if (opts.target) {
      servers.set(opts.target, {
        type: 'http',
        url: opts.target,
      });
    }

    // --command (stdio)
    if (opts.command) {
      servers.set(opts.command, {
        type: 'stdio',
        command: opts.command,
        args: opts.args ? opts.args.split(' ') : [],
      });
    }

    // --network (port scan)
    if (opts.network) {
      const spinner = ora('Scanning localhost ports for MCP servers...').start();
      const found = await scanLocalPorts();
      for (const cfg of found) {
        servers.set(cfg.url, cfg);
      }
      spinner.succeed(`Found ${found.length} HTTP server(s) on localhost`);
    }

    if (servers.size === 0) {
      console.error(chalk.red('No servers to scan. Use --config, --target, --command, --all-configs, or --network.'));
      console.error(chalk.dim(`Default config locations:\n${getDefaultConfigPaths().map(p => '  ' + p).join('\n')}`));
      process.exit(1);
    }

    // Run scans
    if (options.outputFormat === 'terminal') {
      console.log(chalk.dim(`\nScanning ${servers.size} server(s) with checks: ${options.checks.join(', ')}`));
    }

    const spinners = new Map<string, ReturnType<typeof ora>>();

    const results = await scanAll(servers, options, (name, result) => {
      if (options.outputFormat === 'terminal') {
        const spinner = spinners.get(name);
        const findingCount = result.findings.length;
        const criticalCount = result.findings.filter(f => f.severity === 'critical').length;
        const statusText = result.error
          ? chalk.red(`failed: ${result.error}`)
          : findingCount === 0
            ? chalk.green('clean')
            : criticalCount > 0
              ? chalk.red(`${findingCount} finding(s), ${criticalCount} critical`)
              : chalk.yellow(`${findingCount} finding(s)`);
        spinner?.succeed(`${name}: ${statusText}`);
      }
    });

    // For terminal output, show spinners during scan
    // Since scanAll is sequential, we start each spinner before calling scan
    // This is already handled by onProgress above

    // Output results
    switch (options.outputFormat) {
      case 'terminal':
        renderTerminal(results);
        break;
      case 'json':
        process.stdout.write(toJson(results) + '\n');
        break;
      case 'sarif':
        process.stdout.write(toSarif(results) + '\n');
        break;
    }

    // Exit with non-zero if any critical/high findings
    const hasCritical = results.some(r => r.findings.some(f => f.severity === 'critical'));
    const hasHigh = results.some(r => r.findings.some(f => f.severity === 'high'));
    if (hasCritical) process.exit(2);
    if (hasHigh) process.exit(1);
  });

// ─── discover command ─────────────────────────────────────────────────────────

program
  .command('discover')
  .description('Discover MCP servers without scanning them')
  .option('--all-configs', 'Search all known config file locations')
  .option('--network', 'Scan localhost ports for exposed HTTP servers')
  .option('-o, --output <format>', 'Output format: terminal|json (default: terminal)', 'terminal')
  .action(async (opts: {
    allConfigs?: boolean;
    network?: boolean;
    output: string;
  }) => {
    const servers = new Map<string, ServerConfig>();

    if (opts.allConfigs || (!opts.network)) {
      const spinner = ora('Discovering MCP configs...').start();
      const discovered = await discoverConfigs();
      discovered.forEach((v, k) => servers.set(k, v));
      spinner.succeed(`Found ${discovered.size} server(s) in config files`);
    }

    if (opts.network) {
      const spinner = ora('Scanning localhost ports...').start();
      const found = await scanLocalPorts();
      for (const cfg of found) {
        servers.set(cfg.url, cfg);
      }
      spinner.succeed(`Found ${found.length} HTTP server(s) on localhost`);
    }

    if (opts.output === 'json') {
      const obj: Record<string, ServerConfig> = {};
      servers.forEach((v, k) => (obj[k] = v));
      console.log(JSON.stringify(obj, null, 2));
    } else {
      if (servers.size === 0) {
        console.log(chalk.yellow('No MCP servers discovered.'));
        console.log(chalk.dim('Try --all-configs to search all known config locations.'));
        return;
      }
      console.log(chalk.bold(`\nDiscovered ${servers.size} MCP server(s):\n`));
      for (const [name, cfg] of servers) {
        const type = chalk.cyan(`[${cfg.type}]`);
        const detail = cfg.type === 'stdio'
          ? `${cfg.command}${cfg.args?.length ? ' ' + cfg.args.join(' ') : ''}`
          : cfg.url;
        console.log(`  ${type} ${chalk.bold(name)}`);
        console.log(chalk.dim(`         ${detail}`));
      }
    }
  });

// ─── Parse ────────────────────────────────────────────────────────────────────

program.parse();
