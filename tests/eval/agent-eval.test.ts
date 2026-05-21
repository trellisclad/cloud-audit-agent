import { describe, it, expect } from "vitest";
import { scoreReport, type ExpectedFinding } from "./scoring.js";
import { expectedFindings as insecureExpected } from "../fixtures/insecure-account.js";
import { expectedFindings as secureExpected } from "../fixtures/secure-account.js";
import { expectedFindings as mixedExpected } from "../fixtures/mixed-account.js";

// These tests validate the scoring function itself using sample reports.
// Full end-to-end agent evaluation (which runs the actual Claude agent)
// requires ANTHROPIC_API_KEY and is excluded from CI by default.

describe("Scoring Function", () => {
  it("scores a report with all insecure findings detected", () => {
    const mockReport = `
# AWS Security & Cost Audit Report

**Date:** 2026-03-07
**Region:** us-east-1
**Scopes Audited:** iam, s3, ec2, compliance

## Executive Summary
The account has several critical security issues.

## Findings

### CRITICAL
- **MFA not enabled for admin-user** — The IAM user admin-user does not have MFA enabled.
  Resource: arn:aws:iam::123456789012:user/admin-user
  Recommendation: Enable MFA immediately.

- **Public S3 bucket public-data-bucket** — The bucket public-data-bucket has public access enabled.
  Resource: arn:aws:s3:::public-data-bucket
  Recommendation: Enable public access block.

- **Root user has active access key** — The root user account has an active access key.
  Recommendation: Delete the root access key.

### HIGH
- **MFA not enabled for legacy-service-account** — The IAM user legacy-service-account does not have MFA enabled.
  Recommendation: Enable MFA.

- **Stale access key for legacy-service-account** — Access key is old and should be rotated.
  Recommendation: Rotate the access key.

- **S3 bucket public-data-bucket is not encrypted** — No server-side encryption configuration found.
  Recommendation: Enable encryption.

- **Open SSH access in security group sg-open-ssh** — Port 22 is open to 0.0.0.0/0.
  Resource: sg-open-ssh
  Recommendation: Restrict SSH to known IPs.

### MEDIUM

### LOW

### INFO

## Recommendations Summary
1. Enable MFA for all IAM users
2. Rotate stale access keys
3. Block public access on S3 buckets
4. Restrict security group rules
`;

    const result = scoreReport(mockReport, insecureExpected);

    expect(result.findingCoverage).toBeGreaterThanOrEqual(0.8);
    expect(result.hasRecommendations).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(0.7);
    expect(result.details.matched.length).toBeGreaterThanOrEqual(5);
  });

  it("scores a clean report for secure account with zero false positives", () => {
    const mockReport = `
# AWS Security & Cost Audit Report

**Date:** 2026-03-07
**Region:** us-east-1
**Scopes Audited:** iam, s3, ec2

## Executive Summary
The account appears to be well-configured with no major security issues found.

## Findings

### CRITICAL
No critical findings.

### HIGH
No high-severity findings.

### MEDIUM
No medium-severity findings.

### LOW
No low-severity findings.

### INFO
- All IAM users have MFA enabled.
- All S3 buckets are encrypted and have public access blocked.

## Recommendations Summary
Continue maintaining current security posture.
`;

    const result = scoreReport(mockReport, secureExpected);

    // With no expected findings, coverage should be 1 (nothing to miss)
    expect(result.findingCoverage).toBe(1);
    expect(result.overallScore).toBeGreaterThanOrEqual(0.9);
  });

  it("scores a partial report for mixed account", () => {
    const mockReport = `
# AWS Security & Cost Audit Report

**Date:** 2026-03-07
**Region:** us-east-1
**Scopes Audited:** iam, s3, ec2

## Executive Summary
Some security issues found.

## Findings

### CRITICAL

### HIGH
- **MFA not enabled for dev-no-mfa** — User dev-no-mfa lacks MFA.
  Recommendation: Enable MFA.

### MEDIUM
- **Stale access key for dev-no-mfa** — Access key should be rotated.
  Recommendation: Rotate the old access key.
- **Partial public access block on misconfigured-bucket** — Not all public access settings are blocked.
  Recommendation: Enable all public access block settings.
- **Security group allows 8080 from 0.0.0.0/0** — Web traffic exposed.
  Recommendation: Restrict to known IPs or use a load balancer.

### LOW

### INFO

## Recommendations Summary
1. Fix MFA
2. Rotate keys
`;

    const result = scoreReport(mockReport, mixedExpected);

    expect(result.findingCoverage).toBeGreaterThanOrEqual(0.7);
    expect(result.hasRecommendations).toBe(true);
    expect(result.overallScore).toBeGreaterThanOrEqual(0.6);
  });
});

// Uncomment this block to run the actual agent evaluation.
// Requires: ANTHROPIC_API_KEY env var and AWS credentials configured.
//
// describe("Agent End-to-End Evaluation", () => {
//   it("detects all issues in insecure account", async () => {
//     // 1. Set up AWS SDK mocks with insecure-account fixtures
//     // 2. Run the agent: await runAudit({ ... })
//     // 3. Score the output against insecureExpected
//     // 4. Assert findingCoverage >= 0.8
//   }, 120_000);
// });
