import { markdownToJson, stripJsonBlock } from "./formatter.js";
import { redactReport } from "./redact.js";
import type { Finding, Severity } from "../types/findings.js";

export type OutputFormat = "markdown" | "human" | "json" | "html";

export interface FormatMetadata {
  costUsd?: number;
  durationMs?: number;
  numTurns?: number;
  inputTokens?: number;
  outputTokens?: number;
}

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function wrapText(text: string, indent: number, width: number): string {
  const prefix = " ".repeat(indent);
  const maxLineWidth = width - indent;
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let currentLine = "";

  for (const word of words) {
    if (currentLine.length + word.length + 1 > maxLineWidth && currentLine.length > 0) {
      lines.push(prefix + currentLine);
      currentLine = word;
    } else {
      currentLine = currentLine ? currentLine + " " + word : word;
    }
  }
  if (currentLine) {
    lines.push(prefix + currentLine);
  }

  return lines.join("\n");
}

function formatFinding(finding: Finding): string {
  const lines: string[] = [];
  const label = `[${finding.severity}]`;
  const id = finding.id.toUpperCase();

  lines.push(`  ${label} ${id} · ${finding.title}`);
  lines.push(`  Resource: ${finding.resource}`);
  lines.push(wrapText(finding.description, 2, 100));
  lines.push(`  → ${finding.recommendation.split(". ")[0]}.`);

  return lines.join("\n");
}

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#2563eb",
  INFO: "#6b7280",
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function htmlFinding(finding: Finding): string {
  const color = SEVERITY_COLORS[finding.severity];
  return `
    <div style="border-left:4px solid ${color}; padding:12px 16px; margin-bottom:12px; background:#fafafa; border-radius:0 6px 6px 0;">
      <div style="margin-bottom:4px;">
        <span style="background:${color}; color:#fff; padding:2px 8px; border-radius:3px; font-size:12px; font-weight:600;">${finding.severity}</span>
        <span style="color:#6b7280; font-size:13px; margin-left:8px;">${escapeHtml(finding.id.toUpperCase())}</span>
      </div>
      <div style="font-weight:600; font-size:15px; margin-bottom:4px;">${escapeHtml(finding.title)}</div>
      <div style="font-size:13px; color:#6b7280; margin-bottom:8px;">Resource: <code>${escapeHtml(finding.resource)}</code></div>
      <div style="font-size:14px; margin-bottom:8px;">${escapeHtml(finding.description)}</div>
      <div style="font-size:14px; background:#f0fdf4; padding:8px 12px; border-radius:4px; border-left:3px solid #16a34a;">
        <strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}
      </div>
    </div>`;
}

function htmlMetadataFooter(meta: FormatMetadata): string {
  const parts: string[] = [];
  if (meta.costUsd !== undefined) parts.push(`Cost: $${meta.costUsd.toFixed(4)}`);
  if (meta.durationMs !== undefined) parts.push(`Duration: ${(meta.durationMs / 1000).toFixed(1)}s`);
  if (meta.numTurns !== undefined) parts.push(`Turns: ${meta.numTurns}`);
  if (meta.inputTokens !== undefined && meta.outputTokens !== undefined) {
    parts.push(`Tokens: ${meta.inputTokens.toLocaleString()} in / ${meta.outputTokens.toLocaleString()} out`);
  }
  if (parts.length === 0) return "";
  return `
  <div style="margin-top:32px; padding:12px 16px; background:#f8fafc; border-top:1px solid #e2e8f0; font-size:13px; color:#64748b;">
    ${parts.join(" &middot; ")}
  </div>`;
}

function convertMarkdownTable(tableLines: string[]): string {
  // tableLines: [header, separator, ...rows]
  const parseRow = (line: string) =>
    line.split("|").slice(1, -1).map(cell => cell.trim());

  const headers = parseRow(tableLines[0]);
  const rows = tableLines.slice(2).map(parseRow);

  let html = "<table><thead><tr>";
  for (const h of headers) {
    html += `<th>${h.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")}</th>`;
  }
  html += "</tr></thead><tbody>";
  for (const row of rows) {
    html += "<tr>";
    for (const cell of row) {
      html += `<td>${cell.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")}</td>`;
    }
    html += "</tr>";
  }
  html += "</tbody></table>";
  return html;
}

function markdownToHtmlBasic(md: string): string {
  const lines = md.split("\n");
  const output: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Detect markdown table: current line has pipes, next line is separator (|---|)
    if (
      line.includes("|") &&
      i + 1 < lines.length &&
      /^\|[\s-:|]+\|$/.test(lines[i + 1].trim())
    ) {
      const tableLines: string[] = [];
      while (i < lines.length && lines[i].includes("|")) {
        tableLines.push(lines[i]);
        i++;
      }
      output.push(convertMarkdownTable(tableLines));
      continue;
    }

    // Headings
    if (line.startsWith("# ")) {
      output.push(`<h1>${line.slice(2)}</h1>`);
    } else if (line.startsWith("## ")) {
      output.push(`<h2 style="margin-top:24px;border-bottom:1px solid #e2e8f0;padding-bottom:8px;">${line.slice(3)}</h2>`);
    } else if (line.startsWith("### ")) {
      output.push(`<h3>${line.slice(4)}</h3>`);
    } else if (line.startsWith("- ")) {
      output.push(`<li>${line.slice(2).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")}</li>`);
    } else if (line.trim() === "") {
      output.push("<br>");
    } else {
      output.push(`<p style="margin:4px 0;">${line.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")}</p>`);
    }
    i++;
  }

  return output.join("\n");
}

export function formatHtmlReport(markdown: string, metadata?: FormatMetadata): string {
  const cleanMarkdown = stripJsonBlock(markdown);
  const report = markdownToJson(markdown);
  const findings = report.findings;

  // Summary badges
  const severityCounts = SEVERITY_ORDER
    .filter(s => report.summary.bySeverity[s] > 0)
    .map(s => `<span style="background:${SEVERITY_COLORS[s]}; color:#fff; padding:4px 12px; border-radius:4px; font-size:13px; font-weight:600; margin-right:6px;">${s}: ${report.summary.bySeverity[s]}</span>`)
    .join(" ");

  // Group findings by severity
  const grouped = new Map<Severity, Finding[]>();
  for (const severity of SEVERITY_ORDER) {
    const matches = findings.filter(f => f.severity === severity);
    if (matches.length > 0) {
      grouped.set(severity, matches);
    }
  }

  let findingsHtml = "";
  for (const [severity, group] of grouped) {
    const color = SEVERITY_COLORS[severity];
    findingsHtml += `
    <div style="margin-top:24px;">
      <h3 style="color:${color}; border-bottom:2px solid ${color}; padding-bottom:6px;">${severity} (${group.length})</h3>
      ${group.map(f => htmlFinding(f)).join("")}
    </div>`;
  }

  const metaFooter = metadata ? htmlMetadataFooter(metadata) : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AWS Audit Report — ${report.region}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 24px; color: #1e293b; line-height: 1.6; }
    h1 { font-size: 24px; margin-bottom: 4px; }
    h2 { font-size: 18px; color: #334155; }
    h3 { font-size: 16px; }
    code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0; }
    th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; font-size: 14px; }
    th { background: #f8fafc; font-weight: 600; }
  </style>
</head>
<body>
  <div style="margin-bottom:24px;">
    ${markdownToHtmlBasic(cleanMarkdown)}
  </div>

  ${findings.length > 0 ? `
  <div style="margin:20px 0;">
    ${severityCounts}
  </div>

  <h2 style="margin-top:32px; border-bottom:1px solid #e2e8f0; padding-bottom:8px;">Findings (${findings.length} total)</h2>
  ${findingsHtml}` : ""}

  ${metaFooter}

  <div style="margin-top:24px; text-align:center; font-size:12px; color:#94a3b8;">
    Generated by <a href="https://github.com/trellisclad/cloud-audit-agent" style="color:#64748b;">cloud-audit-agent</a>
  </div>
</body>
</html>`;
}

function formatMetadataFooter(meta: FormatMetadata): string {
  const parts: string[] = [];
  if (meta.costUsd !== undefined) parts.push(`$${meta.costUsd.toFixed(4)}`);
  if (meta.durationMs !== undefined) parts.push(`${(meta.durationMs / 1000).toFixed(1)}s`);
  if (meta.numTurns !== undefined) parts.push(`${meta.numTurns} turns`);
  if (meta.inputTokens !== undefined && meta.outputTokens !== undefined) {
    parts.push(`${meta.inputTokens.toLocaleString()} in / ${meta.outputTokens.toLocaleString()} out tokens`);
  }
  if (parts.length === 0) return "";

  const line = "─".repeat(60);
  return `\n${line}\nAudit: ${parts.join(" | ")}\n`;
}

export function formatHumanReport(markdown: string, metadata?: FormatMetadata): string {
  const cleanMarkdown = stripJsonBlock(markdown);
  const report = markdownToJson(markdown);
  const findings = report.findings;

  if (findings.length === 0) {
    const footer = metadata ? formatMetadataFooter(metadata) : "";
    return cleanMarkdown + footer;
  }

  // Group findings by severity
  const grouped = new Map<Severity, Finding[]>();
  for (const severity of SEVERITY_ORDER) {
    const matches = findings.filter(f => f.severity === severity);
    if (matches.length > 0) {
      grouped.set(severity, matches);
    }
  }

  const sections: string[] = [];
  sections.push(cleanMarkdown);
  sections.push("");
  sections.push("─".repeat(60));
  sections.push(`Findings (${findings.length} total)`);
  sections.push("─".repeat(60));

  for (const [severity, group] of grouped) {
    const count = group.length;
    const label = `── ${severity} (${count}) `;
    sections.push("");
    sections.push(label + "─".repeat(Math.max(0, 60 - label.length)));
    sections.push("");

    for (let i = 0; i < group.length; i++) {
      sections.push(formatFinding(group[i]));
      if (i < group.length - 1) sections.push("");
    }
  }

  const footer = metadata ? formatMetadataFooter(metadata) : "";
  return sections.join("\n") + footer;
}

export interface FormatOutputOptions {
  format: OutputFormat;
  markdown: string;
  metadata?: FormatMetadata;
  redact?: boolean;
}

export function formatOutput(
  format: OutputFormat,
  markdown: string,
  metadata?: FormatMetadata,
  redact?: boolean,
): string {
  const md = redact ? redactReport(markdown) : markdown;
  switch (format) {
    case "markdown":
      return md;

    case "human":
      return formatHumanReport(md, metadata);

    case "html":
      return formatHtmlReport(md, metadata);

    case "json": {
      const report = markdownToJson(md);
      const output = metadata
        ? { ...report, metadata }
        : report;
      return JSON.stringify(output, null, 2);
    }
  }
}
