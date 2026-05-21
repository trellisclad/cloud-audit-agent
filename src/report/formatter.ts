import type { AuditReport, Finding, Severity } from "../types/findings.js";

const VALID_SEVERITIES: Set<string> = new Set([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
]);

const VALID_DOMAINS: Set<string> = new Set([
  "IAM",
  "S3",
  "EC2",
  "COST",
  "COMPLIANCE",
]);

/**
 * Extract the structured JSON block from the agent's markdown response.
 *
 * The system prompt instructs the agent to append a fenced ```json block
 * at the end of its output. We extract and validate it here — no fragile
 * markdown heading/bullet parsing needed.
 */
export function markdownToJson(markdownReport: string): AuditReport {
  const parsed = extractJsonBlock(markdownReport);
  if (parsed) return parsed;

  // Fallback: return an empty report if no JSON block found
  console.warn("[formatter] No valid JSON findings block found in agent output");
  return {
    timestamp: new Date().toISOString(),
    region: "unknown",
    scope: [],
    findings: [],
    summary: {
      total: 0,
      bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      byDomain: {},
    },
  };
}

/**
 * Strip the trailing ```json findings block from the markdown so the
 * human-readable report doesn't show raw JSON at the bottom.
 */
export function stripJsonBlock(text: string): string {
  // Remove the last ```json ... ``` block and any "### Structured Findings JSON" heading before it.
  // Can't use non-greedy regex because JSON may contain embedded ``` code blocks.
  const lastJsonStart = text.lastIndexOf("```json");
  let stripped = text;
  if (lastJsonStart !== -1) {
    stripped = text.slice(0, lastJsonStart);
  }
  return stripped
    .replace(/\n*#{1,4}\s*Structured Findings JSON\s*\n*/i, "\n")
    .trimEnd();
}

function extractJsonBlock(text: string): AuditReport | null {
  // The JSON block may contain embedded ``` inside string values (e.g.,
  // bash code blocks in recommendations). Instead of trying to match
  // fence delimiters, find the last ```json marker and extract the JSON
  // object by locating the first { and last } after it.
  const lastJsonStart = text.lastIndexOf("```json");
  if (lastJsonStart === -1) return null;

  const afterMarker = text.slice(lastJsonStart);
  const braceStart = afterMarker.indexOf("{");
  if (braceStart === -1) return null;

  // Find the matching closing brace by scanning from the end
  const lastBrace = afterMarker.lastIndexOf("}");
  if (lastBrace <= braceStart) return null;

  const lastBlock = afterMarker.slice(braceStart, lastBrace + 1);

  let raw: unknown;
  try {
    raw = JSON.parse(lastBlock);
  } catch (err) {
    console.warn("[formatter] JSON block length:", lastBlock.length);
    console.warn("[formatter] JSON block starts with:", lastBlock.slice(0, 100));
    console.warn("[formatter] JSON block ends with:", lastBlock.slice(-100));
    console.warn("[formatter] Parse error:", err instanceof Error ? err.message : String(err));
    return null;
  }

  if (!raw || typeof raw !== "object") return null;

  const obj = raw as Record<string, unknown>;
  const region = typeof obj.region === "string" ? obj.region : "unknown";
  const scope = Array.isArray(obj.scopes)
    ? obj.scopes.filter((s): s is string => typeof s === "string")
    : [];

  const rawFindings = Array.isArray(obj.findings) ? obj.findings : [];
  const findings: Finding[] = [];

  for (let i = 0; i < rawFindings.length; i++) {
    const f = rawFindings[i] as Record<string, unknown>;
    if (!f || typeof f !== "object") continue;

    const severity = String(f.severity ?? "").toUpperCase();
    const domain = String(f.domain ?? "").toUpperCase();

    findings.push({
      id: typeof f.id === "string" ? f.id : `finding-${i + 1}`,
      severity: (VALID_SEVERITIES.has(severity) ? severity : "INFO") as Severity,
      domain: (VALID_DOMAINS.has(domain) ? domain : "COMPLIANCE") as Finding["domain"],
      title: String(f.title ?? "Untitled finding"),
      description: String(f.description ?? ""),
      resource: String(f.resource ?? "N/A"),
      recommendation: String(f.recommendation ?? ""),
    });
  }

  const bySeverity: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  const byDomain: Record<string, number> = {};

  for (const f of findings) {
    bySeverity[f.severity]++;
    byDomain[f.domain] = (byDomain[f.domain] ?? 0) + 1;
  }

  return {
    timestamp: new Date().toISOString(),
    region,
    scope,
    findings,
    summary: {
      total: findings.length,
      bySeverity,
      byDomain,
    },
  };
}
