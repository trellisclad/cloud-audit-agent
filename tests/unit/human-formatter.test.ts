import { describe, it, expect } from "vitest";
import { formatOutput, formatHumanReport, formatHtmlReport } from "../../src/report/human-formatter.js";
import { markdownToJson, stripJsonBlock } from "../../src/report/formatter.js";

const SAMPLE_MARKDOWN = `# AWS Security & Cost Audit Report

**Account:** 123456789012
**Date:** 2026-05-22
**Region:** us-east-1

## Executive Summary
Found 3 issues across IAM and S3.

## Findings Count
CRITICAL: 1 | HIGH: 1 | INFO: 1

\`\`\`json
{
  "region": "us-east-1",
  "scopes": ["iam", "s3"],
  "findings": [
    {
      "id": "finding-1",
      "domain": "S3",
      "severity": "CRITICAL",
      "title": "Public bucket detected",
      "description": "The bucket my-bucket has public read access enabled.",
      "resource": "arn:aws:s3:::my-bucket",
      "recommendation": "Remove the public access policy. Enable Public Access Block."
    },
    {
      "id": "finding-2",
      "domain": "IAM",
      "severity": "HIGH",
      "title": "Root account lacks MFA",
      "description": "The root account does not have multi-factor authentication enabled.",
      "resource": "arn:aws:iam::123456789012:root",
      "recommendation": "Enable MFA on the root account using a hardware token."
    },
    {
      "id": "finding-3",
      "domain": "COST",
      "severity": "INFO",
      "title": "S3 spend is stable",
      "description": "No cost anomalies detected for S3.",
      "resource": "us-east-1 / S3",
      "recommendation": "No action needed."
    }
  ]
}
\`\`\``;

const SAMPLE_METADATA = {
  costUsd: 0.0342,
  durationMs: 45200,
  numTurns: 12,
  inputTokens: 48231,
  outputTokens: 12044,
};

describe("formatHumanReport", () => {
  it("strips JSON block and renders findings grouped by severity", () => {
    const result = formatHumanReport(SAMPLE_MARKDOWN, SAMPLE_METADATA);

    // Should not contain raw JSON
    expect(result).not.toContain("```json");

    // Should contain the executive summary from markdown
    expect(result).toContain("Executive Summary");
    expect(result).toContain("Found 3 issues across IAM and S3.");

    // Should have severity group headers
    expect(result).toContain("CRITICAL (1)");
    expect(result).toContain("HIGH (1)");
    expect(result).toContain("INFO (1)");

    // Should contain finding details
    expect(result).toContain("[CRITICAL] FINDING-1");
    expect(result).toContain("Public bucket detected");
    expect(result).toContain("Resource: arn:aws:s3:::my-bucket");

    expect(result).toContain("[HIGH] FINDING-2");
    expect(result).toContain("Root account lacks MFA");

    // Should contain metadata footer
    expect(result).toContain("$0.0342");
    expect(result).toContain("45.2s");
    expect(result).toContain("12 turns");
    expect(result).toContain("48,231 in / 12,044 out tokens");
  });

  it("renders CRITICAL before HIGH before INFO", () => {
    const result = formatHumanReport(SAMPLE_MARKDOWN);
    const critIdx = result.indexOf("CRITICAL (1)");
    const highIdx = result.indexOf("HIGH (1)");
    const infoIdx = result.indexOf("INFO (1)");
    expect(critIdx).toBeLessThan(highIdx);
    expect(highIdx).toBeLessThan(infoIdx);
  });

  it("handles empty findings gracefully", () => {
    const emptyMarkdown = `# Report

No issues found.

\`\`\`json
{
  "region": "us-east-1",
  "scopes": ["iam"],
  "findings": []
}
\`\`\``;

    const result = formatHumanReport(emptyMarkdown);
    expect(result).toContain("No issues found.");
    expect(result).not.toContain("```json");
    expect(result).not.toContain("Findings (");
  });

  it("works without metadata", () => {
    const result = formatHumanReport(SAMPLE_MARKDOWN);
    expect(result).toContain("[CRITICAL] FINDING-1");
    expect(result).not.toContain("Audit:");
  });
});

describe("formatOutput", () => {
  it("returns raw markdown for 'markdown' format", () => {
    const result = formatOutput("markdown", SAMPLE_MARKDOWN);
    expect(result).toBe(SAMPLE_MARKDOWN);
  });

  it("returns human-friendly report for 'human' format", () => {
    const result = formatOutput("human", SAMPLE_MARKDOWN, SAMPLE_METADATA);
    expect(result).toContain("CRITICAL (1)");
    expect(result).not.toContain("```json");
    expect(result).toContain("$0.0342");
  });

  it("returns valid JSON for 'json' format", () => {
    const result = formatOutput("json", SAMPLE_MARKDOWN, SAMPLE_METADATA);
    const parsed = JSON.parse(result);
    expect(parsed.findings).toHaveLength(3);
    expect(parsed.findings[0].severity).toBe("CRITICAL");
    expect(parsed.metadata.costUsd).toBe(0.0342);
    expect(parsed.summary.total).toBe(3);
  });

  it("returns JSON without metadata when not provided", () => {
    const result = formatOutput("json", SAMPLE_MARKDOWN);
    const parsed = JSON.parse(result);
    expect(parsed.findings).toHaveLength(3);
    expect(parsed.metadata).toBeUndefined();
  });
});

describe("formatHtmlReport", () => {
  it("returns valid HTML with findings", () => {
    const result = formatHtmlReport(SAMPLE_MARKDOWN, SAMPLE_METADATA);
    expect(result).toContain("<!DOCTYPE html>");
    expect(result).toContain("</html>");
    expect(result).toContain("Public bucket detected");
    expect(result).toContain("Root account lacks MFA");
    expect(result).not.toContain("```json");
  });

  it("renders severity badges with colors", () => {
    const result = formatHtmlReport(SAMPLE_MARKDOWN);
    expect(result).toContain("CRITICAL: 1");
    expect(result).toContain("HIGH: 1");
    expect(result).toContain("INFO: 1");
  });

  it("escapes HTML in finding content", () => {
    const mdWithHtml = `# Report

\`\`\`json
{
  "region": "us-east-1",
  "scopes": ["s3"],
  "findings": [
    {
      "id": "finding-1",
      "domain": "S3",
      "severity": "HIGH",
      "title": "Bucket <script>alert('xss')</script>",
      "description": "Desc with <b>tags</b>",
      "resource": "arn:aws:s3:::test",
      "recommendation": "Fix it"
    }
  ]
}
\`\`\``;
    const result = formatHtmlReport(mdWithHtml);
    expect(result).not.toContain("<script>");
    expect(result).toContain("&lt;script&gt;");
  });

  it("includes metadata footer", () => {
    const result = formatHtmlReport(SAMPLE_MARKDOWN, SAMPLE_METADATA);
    expect(result).toContain("$0.0342");
    expect(result).toContain("45.2s");
    expect(result).toContain("12");
  });

  it("renders markdown tables as HTML tables", () => {
    const mdWithTable = `# Report

## Monthly Spend Summary
| Bucket | Region | Estimated Monthly Cost |
|---|---|---|
| my-bucket | us-east-1 | $12.34 |
| **Total** | | **$12.34** |

\`\`\`json
{
  "region": "us-east-1",
  "scopes": ["s3"],
  "findings": []
}
\`\`\``;
    const result = formatHtmlReport(mdWithTable);
    expect(result).toContain("<table>");
    expect(result).toContain("<th>Bucket</th>");
    expect(result).toContain("<td>my-bucket</td>");
    expect(result).toContain("<td>$12.34</td>");
    expect(result).toContain("<strong>Total</strong>");
    expect(result).not.toContain("|---|");
  });

  it("includes link to cloud-audit-agent repo", () => {
    const result = formatHtmlReport(SAMPLE_MARKDOWN);
    expect(result).toContain("github.com/trellisclad/cloud-audit-agent");
  });
});

describe("formatOutput html", () => {
  it("returns HTML for 'html' format", () => {
    const result = formatOutput("html", SAMPLE_MARKDOWN, SAMPLE_METADATA);
    expect(result).toContain("<!DOCTYPE html>");
    expect(result).toContain("Public bucket detected");
  });
});

describe("existing exports still work (regression)", () => {
  it("markdownToJson extracts findings", () => {
    const report = markdownToJson(SAMPLE_MARKDOWN);
    expect(report.findings).toHaveLength(3);
    expect(report.findings[0].severity).toBe("CRITICAL");
    expect(report.summary.bySeverity.CRITICAL).toBe(1);
  });

  it("stripJsonBlock removes the JSON block", () => {
    const stripped = stripJsonBlock(SAMPLE_MARKDOWN);
    expect(stripped).not.toContain("```json");
    expect(stripped).toContain("Executive Summary");
  });
});
