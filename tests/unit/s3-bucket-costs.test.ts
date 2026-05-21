import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
} from "@aws-sdk/client-s3";
import {
  CloudWatchClient,
  GetMetricStatisticsCommand,
} from "@aws-sdk/client-cloudwatch";
import { createS3ToolsServer } from "../../src/tools/s3-tools.js";

const s3Mock = mockClient(S3Client);
const cwMock = mockClient(CloudWatchClient);

/** Helper to call a tool on the MCP server by name. */
async function callTool(toolName: string) {
  const server = createS3ToolsServer({ region: "us-east-1" });
  // Access the registered tool handler directly
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registeredTool = (server as any).instance._registeredTools[toolName];
  if (!registeredTool) throw new Error(`Tool "${toolName}" not found`);
  const result = await registeredTool.handler({}, {});
  const textContent = result.content.find(
    (c: { type: string }) => c.type === "text",
  ) as { type: string; text: string } | undefined;
  return textContent ? JSON.parse(textContent.text) : null;
}

describe("estimate_all_bucket_costs", () => {
  beforeEach(() => {
    s3Mock.reset();
    cwMock.reset();
  });

  it("returns per-bucket cost estimates sorted by cost descending", async () => {
    // Two buckets: one expensive, one cheap
    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [
        { Name: "small-bucket", CreationDate: new Date("2024-01-01") },
        { Name: "big-bucket", CreationDate: new Date("2024-06-01") },
      ],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: undefined }); // us-east-1

    // Route CloudWatch responses based on Dimensions
    cwMock.on(GetMetricStatisticsCommand).callsFake((input: Record<string, unknown>) => {
      const dims = (input.Dimensions ?? []) as { Name: string; Value: string }[];
      const bucketDim = dims.find((d) => d.Name === "BucketName");
      const storageDim = dims.find((d) => d.Name === "StorageType");
      if (storageDim?.Value === "StandardStorage") {
        if (bucketDim?.Value === "small-bucket") {
          return Promise.resolve({ Datapoints: [{ Average: 10 * 1024 * 1024 * 1024, Timestamp: new Date() }] }); // 10 GB
        }
        if (bucketDim?.Value === "big-bucket") {
          return Promise.resolve({ Datapoints: [{ Average: 1024 * 1024 * 1024 * 1024, Timestamp: new Date() }] }); // 1 TB
        }
      }
      return Promise.resolve({ Datapoints: [] });
    });

    const result = await callTool("estimate_all_bucket_costs");

    expect(result.totalBuckets).toBe(2);
    expect(result.buckets).toHaveLength(2);
    // Sorted by cost descending — big-bucket first
    expect(result.buckets[0].name).toBe("big-bucket");
    expect(result.buckets[1].name).toBe("small-bucket");
    expect(parseFloat(result.buckets[0].estimatedMonthlyCost)).toBeGreaterThan(
      parseFloat(result.buckets[1].estimatedMonthlyCost),
    );
    expect(result.note).toContain("Estimated");
  });

  it("handles CloudWatch permission error gracefully — skips bucket", async () => {
    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [
        { Name: "accessible-bucket", CreationDate: new Date("2024-01-01") },
        { Name: "denied-bucket", CreationDate: new Date("2024-06-01") },
      ],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: undefined });

    cwMock.on(GetMetricStatisticsCommand).callsFake((input: Record<string, unknown>) => {
      const dims = (input.Dimensions ?? []) as { Name: string; Value: string }[];
      const bucketDim = dims.find((d) => d.Name === "BucketName");
      if (bucketDim?.Value === "denied-bucket") {
        return Promise.reject(new Error("AccessDenied: User is not authorized to perform cloudwatch:GetMetricStatistics"));
      }
      const storageDim = dims.find((d) => d.Name === "StorageType");
      if (storageDim?.Value === "StandardStorage") {
        return Promise.resolve({ Datapoints: [{ Average: 100 * 1024 * 1024 * 1024, Timestamp: new Date() }] });
      }
      return Promise.resolve({ Datapoints: [] });
    });

    const result = await callTool("estimate_all_bucket_costs");

    // Should still return both buckets — denied one with $0 cost
    expect(result.totalBuckets).toBe(2);
    const accessible = result.buckets.find((b: { name: string }) => b.name === "accessible-bucket");
    const denied = result.buckets.find((b: { name: string }) => b.name === "denied-bucket");
    expect(parseFloat(accessible.estimatedMonthlyCost)).toBeGreaterThan(0);
    expect(parseFloat(denied.estimatedMonthlyCost)).toBe(0);
  });

  it("aggregates cost across multiple storage classes per bucket", async () => {
    s3Mock.on(ListBucketsCommand).resolves({
      Buckets: [{ Name: "multi-class-bucket", CreationDate: new Date("2024-01-01") }],
    });
    s3Mock.on(GetBucketLocationCommand).resolves({ LocationConstraint: undefined });

    // 100 GB Standard ($2.30) + 500 GB Glacier ($1.80) = $4.10
    cwMock.on(GetMetricStatisticsCommand).callsFake((input: Record<string, unknown>) => {
      const dims = (input.Dimensions ?? []) as { Name: string; Value: string }[];
      const storageDim = dims.find((d) => d.Name === "StorageType");
      if (storageDim?.Value === "StandardStorage") {
        return Promise.resolve({ Datapoints: [{ Average: 100 * 1024 * 1024 * 1024, Timestamp: new Date() }] });
      }
      if (storageDim?.Value === "GlacierStorage") {
        return Promise.resolve({ Datapoints: [{ Average: 500 * 1024 * 1024 * 1024, Timestamp: new Date() }] });
      }
      return Promise.resolve({ Datapoints: [] });
    });

    const result = await callTool("estimate_all_bucket_costs");

    expect(result.totalBuckets).toBe(1);
    const bucket = result.buckets[0];
    expect(bucket.storageBreakdown).toHaveLength(2);
    // Total should be Standard + Glacier
    const totalCost = parseFloat(bucket.estimatedMonthlyCost);
    expect(totalCost).toBeGreaterThan(3.5);
    expect(totalCost).toBeLessThan(5);
  });

  it("returns empty result for account with no buckets", async () => {
    s3Mock.on(ListBucketsCommand).resolves({ Buckets: [] });

    const result = await callTool("estimate_all_bucket_costs");

    expect(result.totalBuckets).toBe(0);
    expect(result.buckets).toHaveLength(0);
    expect(result.totalEstimatedMonthlyCost).toBe("0.00");
  });
});
