import type { Finding, ScanResult, Severity } from '../types.js';

// ─── JSON output ──────────────────────────────────────────────────────────────

interface JsonReport {
  tool: string;
  version: string;
  timestamp: string;
  summary: {
    serversScanned: number;
    serversEnumerated: number;
    totalFindings: number;
    findingsBySeverity: Record<Severity, number>;
  };
  results: ScanResult[];
}

export function toJson(results: ScanResult[]): string {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const result of results) {
    for (const f of result.findings) {
      counts[f.severity]++;
    }
  }

  const report: JsonReport = {
    tool: 'mcpscan',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
    summary: {
      serversScanned: results.length,
      serversEnumerated: results.filter(r => r.enumerated).length,
      totalFindings: Object.values(counts).reduce((a, b) => a + b, 0),
      findingsBySeverity: counts,
    },
    results,
  };

  return JSON.stringify(report, null, 2);
}

// ─── SARIF 2.1.0 output ───────────────────────────────────────────────────────

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

function severityToSarifLevel(s: Severity): SarifLevel {
  switch (s) {
    case 'critical':
    case 'high':   return 'error';
    case 'medium': return 'warning';
    case 'low':
    case 'info':   return 'note';
  }
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties?: { tags: string[]; 'security-severity': string };
}

function buildRules(results: ScanResult[]): SarifRule[] {
  const ruleMap = new Map<string, Finding>();
  for (const result of results) {
    for (const f of result.findings) {
      if (!ruleMap.has(f.id)) ruleMap.set(f.id, f);
    }
  }

  return [...ruleMap.values()].map(f => ({
    id: f.id,
    name: f.title.replace(/[^A-Za-z0-9]/g, ''),
    shortDescription: { text: f.title },
    helpUri: f.cve ? `https://nvd.nist.gov/vuln/detail/${f.cve}` : undefined,
    properties: {
      tags: ['security', f.category, ...(f.cve ? [f.cve] : [])],
      'security-severity': f.cvss !== undefined ? String(f.cvss) : severityToSecuritySeverity(f.severity),
    },
  }));
}

function severityToSecuritySeverity(s: Severity): string {
  switch (s) {
    case 'critical': return '9.0';
    case 'high':     return '7.0';
    case 'medium':   return '5.0';
    case 'low':      return '3.0';
    case 'info':     return '1.0';
  }
}

export function toSarif(results: ScanResult[]): string {
  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcpscan',
            version: '0.1.0',
            informationUri: 'https://github.com/mcpscan/mcpscan',
            rules: buildRules(results),
          },
        },
        results: results.flatMap(r =>
          r.findings.map(f => ({
            ruleId: f.id,
            level: severityToSarifLevel(f.severity),
            message: {
              text: `${f.description}\n\nEvidence: ${f.evidence}\n\nRemediation: ${f.remediation}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: r.server.name,
                    uriBaseId: '%SRCROOT%',
                  },
                  region: {
                    message: { text: f.location },
                  },
                },
              },
            ],
            properties: {
              severity: f.severity,
              category: f.category,
              evidence: f.evidence,
              location: f.location,
              cve: f.cve,
              cvss: f.cvss,
            },
          })),
        ),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
