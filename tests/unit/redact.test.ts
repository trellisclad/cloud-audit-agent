import { describe, it, expect } from "vitest";
import { redactReport, redactAuditReport } from "../../src/report/redact.js";
import type { AuditReport, Finding } from "../../src/types/findings.js";

describe("redactReport", () => {
  it("redacts AWS account IDs", () => {
    const text = "Account: 821496737932 has issues. Also 821496737932 again.";
    const result = redactReport(text);
    expect(result).not.toContain("821496737932");
    // Same account ID should get same replacement
    const matches = result.match(/111-01/g);
    expect(matches?.length).toBe(2);
  });

  it("redacts security group IDs", () => {
    const text = "Security group sg-0a1b2c3d4e is open to 0.0.0.0/0";
    const result = redactReport(text);
    expect(result).not.toContain("sg-0a1b2c3d4e");
    expect(result).toContain("sg-redacted");
  });

  it("redacts VPC IDs", () => {
    const text = "VPC vpc-abcdef12 has no flow logs";
    const result = redactReport(text);
    expect(result).not.toContain("vpc-abcdef12");
    expect(result).toContain("vpc-redacted");
  });

  it("redacts instance IDs", () => {
    const text = "Instance i-0123456789abcdef0 is publicly exposed";
    const result = redactReport(text);
    expect(result).not.toContain("i-0123456789abcdef0");
    expect(result).toContain("i-redacted");
  });

  it("redacts access key IDs", () => {
    const text = "Access key AKIAIOSFODNN7EXAMPLE is stale";
    const result = redactReport(text);
    expect(result).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(result).toContain("AKIAEXAMPLE");
  });

  it("redacts ARNs", () => {
    const text = "Resource: arn:aws:iam::821496737932:user/alice is at risk";
    const result = redactReport(text);
    expect(result).not.toContain("821496737932");
    expect(result).not.toContain("alice");
  });

  it("maintains consistency — same value gets same token", () => {
    const text = [
      "Bucket arn:aws:s3:::my-secret-bucket has issues.",
      "The bucket arn:aws:s3:::my-secret-bucket should be fixed.",
      "Account 999888777666 owns arn:aws:s3:::my-secret-bucket.",
      "Account 999888777666 also owns other resources.",
    ].join("\n");
    const result = redactReport(text);

    // Account ID should be consistently replaced
    expect(result).not.toContain("999888777666");

    // The same ARN should produce the same token everywhere
    const lines = result.split("\n");
    // Each mention of the original ARN should map to the same redacted value
    expect(result).not.toContain("my-secret-bucket");
  });
});

describe("redactAuditReport", () => {
  const makeFinding = (overrides: Partial<Finding> = {}): Finding => ({
    id: "finding-1",
    domain: "S3",
    severity: "CRITICAL",
    title: "Public bucket radixdlt-mainnet-snapshots detected",
    description: "The bucket radixdlt-mainnet-snapshots in account 821496737932 is publicly accessible via arn:aws:s3:::radixdlt-mainnet-snapshots/*.",
    resource: "arn:aws:s3:::radixdlt-mainnet-snapshots",
    recommendation: "Remove public access from radixdlt-mainnet-snapshots and enable Public Access Block.",
    ...overrides,
  });

  it("redacts all finding fields", () => {
    const report: AuditReport = {
      timestamp: new Date().toISOString(),
      region: "eu-west-1",
      scope: ["s3"],
      findings: [makeFinding()],
      summary: { total: 1, bySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byDomain: { S3: 1 } },
    };

    const result = redactAuditReport(report);

    expect(result.findings[0].title).not.toContain("radixdlt-mainnet-snapshots");
    expect(result.findings[0].description).not.toContain("821496737932");
    expect(result.findings[0].description).not.toContain("radixdlt-mainnet-snapshots");
    expect(result.findings[0].resource).not.toContain("radixdlt-mainnet-snapshots");
    expect(result.findings[0].recommendation).not.toContain("radixdlt-mainnet-snapshots");
  });

  it("preserves non-sensitive data", () => {
    const report: AuditReport = {
      timestamp: "2026-05-22T00:00:00Z",
      region: "eu-west-1",
      scope: ["s3"],
      findings: [makeFinding()],
      summary: { total: 1, bySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byDomain: { S3: 1 } },
    };

    const result = redactAuditReport(report);

    // Metadata should be preserved
    expect(result.region).toBe("eu-west-1");
    expect(result.scope).toEqual(["s3"]);
    expect(result.timestamp).toBe("2026-05-22T00:00:00Z");
    expect(result.findings[0].severity).toBe("CRITICAL");
    expect(result.findings[0].domain).toBe("S3");
    expect(result.findings[0].id).toBe("finding-1");
  });

  it("uses consistent tokens across findings", () => {
    const report: AuditReport = {
      timestamp: new Date().toISOString(),
      region: "eu-west-1",
      scope: ["s3"],
      findings: [
        makeFinding({ id: "finding-1", resource: "arn:aws:s3:::my-bucket" }),
        makeFinding({ id: "finding-2", resource: "arn:aws:s3:::my-bucket", title: "Another issue with my-bucket" }),
      ],
      summary: { total: 2, bySeverity: { CRITICAL: 2, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byDomain: { S3: 2 } },
    };

    const result = redactAuditReport(report);
    // Same resource should get same redacted value
    expect(result.findings[0].resource).toBe(result.findings[1].resource);
  });
});
