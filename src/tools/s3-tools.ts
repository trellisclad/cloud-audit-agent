import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod/v4";
import { Effect } from "effect";
import {
  S3Client,
  ListBucketsCommand,
  GetBucketPolicyCommand,
  GetPublicAccessBlockCommand,
  GetBucketEncryptionCommand,
  GetBucketLocationCommand,
} from "@aws-sdk/client-s3";
import {
  CloudWatchClient,
  GetMetricStatisticsCommand,
} from "@aws-sdk/client-cloudwatch";
import { getClientConfig, type AwsConfig } from "../aws/client.js";
import { awsCall, toolResponse, toolError, formatAwsError, createTracedSdkMcpServer } from "../aws/effect.js";
import { getS3StorageRate } from "./s3-pricing.js";

const STORAGE_TYPES = [
  "StandardStorage",
  "IntelligentTieringFAStorage",
  "IntelligentTieringIAStorage",
  "StandardIAStorage",
  "OneZoneIAStorage",
  "GlacierInstantRetrievalStorage",
  "GlacierStorage",
  "DeepArchiveStorage",
];

const BYTES_PER_GB = 1024 * 1024 * 1024;
const MAX_BUCKETS_IN_OUTPUT = 20;

export function createS3ToolsServer(awsConfig: AwsConfig) {
  const s3 = new S3Client(getClientConfig(awsConfig));
  const cloudwatch = new CloudWatchClient(getClientConfig(awsConfig));

  return createTracedSdkMcpServer({
    name: "aws-s3",
    version: "1.0.0",
    tools: [
      tool(
        "list_s3_buckets",
        "List all S3 buckets in the account with their creation date. Use this as a starting point to then check individual bucket security settings.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("S3", "ListBuckets", () =>
              s3.send(new ListBucketsCommand({})),
            ).pipe(
              Effect.flatMap((response) => {
                const buckets = response.Buckets ?? [];
                return Effect.forEach(
                  buckets,
                  (b) =>
                    awsCall("S3", "GetBucketLocation", () =>
                      s3.send(
                        new GetBucketLocationCommand({ Bucket: b.Name }),
                      ),
                    ).pipe(
                      Effect.map(
                        (loc) => loc.LocationConstraint ?? "us-east-1",
                      ),
                      // Permission denied for location is expected — degrade gracefully
                      Effect.catchAll(() => Effect.succeed("unknown")),
                    ).pipe(
                      Effect.map((region) => ({
                        name: b.Name,
                        creationDate: b.CreationDate?.toISOString(),
                        region,
                      })),
                    ),
                  { concurrency: "unbounded" },
                ).pipe(
                  Effect.map((bucketDetails) =>
                    toolResponse({
                      bucketCount: buckets.length,
                      buckets: bucketDetails,
                    }),
                  ),
                );
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError("Error listing S3 buckets", error),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "check_bucket_public_access",
        "Check public access block settings for a specific S3 bucket. Buckets without all four public access blocks enabled are potentially exposed.",
        {
          bucketName: z.string().describe("The S3 bucket name to check"),
        },
        async (args) =>
          Effect.runPromise(
            awsCall("S3", "GetPublicAccessBlock", () =>
              s3.send(
                new GetPublicAccessBlockCommand({ Bucket: args.bucketName }),
              ),
            ).pipe(
              Effect.map((response) => {
                const config = response.PublicAccessBlockConfiguration;
                return toolResponse({
                  bucketName: args.bucketName,
                  blockPublicAcls: config?.BlockPublicAcls ?? false,
                  ignorePublicAcls: config?.IgnorePublicAcls ?? false,
                  blockPublicPolicy: config?.BlockPublicPolicy ?? false,
                  restrictPublicBuckets:
                    config?.RestrictPublicBuckets ?? false,
                  allBlocked:
                    (config?.BlockPublicAcls ?? false) &&
                    (config?.IgnorePublicAcls ?? false) &&
                    (config?.BlockPublicPolicy ?? false) &&
                    (config?.RestrictPublicBuckets ?? false),
                });
              }),
              // Expected: no public access block config exists
              Effect.catchTag("AwsNotFoundError", () =>
                Effect.succeed(
                  toolResponse({
                    bucketName: args.bucketName,
                    blockPublicAcls: false,
                    ignorePublicAcls: false,
                    blockPublicPolicy: false,
                    restrictPublicBuckets: false,
                    allBlocked: false,
                    note: "No public access block configuration found — bucket may be publicly accessible.",
                  }),
                ),
              ),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      `Error checking public access for ${args.bucketName}`,
                      error,
                    ),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "check_bucket_encryption",
        "Check server-side encryption configuration for a specific S3 bucket. Unencrypted buckets are a compliance risk.",
        {
          bucketName: z.string().describe("The S3 bucket name to check"),
        },
        async (args) =>
          Effect.runPromise(
            awsCall("S3", "GetBucketEncryption", () =>
              s3.send(
                new GetBucketEncryptionCommand({ Bucket: args.bucketName }),
              ),
            ).pipe(
              Effect.map((response) => {
                const rules =
                  response.ServerSideEncryptionConfiguration?.Rules ?? [];
                return toolResponse({
                  bucketName: args.bucketName,
                  encrypted: rules.length > 0,
                  rules: rules.map((r) => ({
                    sseAlgorithm:
                      r.ApplyServerSideEncryptionByDefault?.SSEAlgorithm,
                    kmsMasterKeyID:
                      r.ApplyServerSideEncryptionByDefault?.KMSMasterKeyID ??
                      "N/A",
                    bucketKeyEnabled: r.BucketKeyEnabled ?? false,
                  })),
                });
              }),
              // Expected: no encryption config exists
              Effect.catchTag("AwsNotFoundError", () =>
                Effect.succeed(
                  toolResponse({
                    bucketName: args.bucketName,
                    encrypted: false,
                    note: "No server-side encryption configuration found.",
                  }),
                ),
              ),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      `Error checking encryption for ${args.bucketName}`,
                      error,
                    ),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "check_bucket_policy",
        "Retrieve and return the bucket policy for a specific S3 bucket. The policy JSON is returned for analysis of overly permissive access.",
        {
          bucketName: z.string().describe("The S3 bucket name to check"),
        },
        async (args) =>
          Effect.runPromise(
            awsCall("S3", "GetBucketPolicy", () =>
              s3.send(
                new GetBucketPolicyCommand({ Bucket: args.bucketName }),
              ),
            ).pipe(
              Effect.map((response) => {
                const policy = response.Policy
                  ? JSON.parse(response.Policy)
                  : null;
                const hasWildcardPrincipal =
                  response.Policy?.includes('"Principal":"*"') ||
                  response.Policy?.includes('"Principal": "*"');

                return toolResponse({
                  bucketName: args.bucketName,
                  hasPolicy: true,
                  hasWildcardPrincipal,
                  policy,
                });
              }),
              // Expected: no bucket policy exists
              Effect.catchTag("AwsNotFoundError", () =>
                Effect.succeed(
                  toolResponse({
                    bucketName: args.bucketName,
                    hasPolicy: false,
                    note: "No bucket policy attached.",
                  }),
                ),
              ),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      `Error checking bucket policy for ${args.bucketName}`,
                      error,
                    ),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "audit_all_buckets",
        "Audit ALL S3 buckets in one call — checks public access, encryption, and bucket policy for every bucket. Use this instead of calling individual check tools per bucket. Returns a summary with findings per bucket.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("S3", "ListBuckets", () =>
              s3.send(new ListBucketsCommand({})),
            ).pipe(
              Effect.flatMap((response) => {
                const buckets = response.Buckets ?? [];
                return Effect.forEach(
                  buckets,
                  (bucket) =>
                    Effect.all(
                      {
                        publicAccess: awsCall("S3", "GetPublicAccessBlock", () =>
                          s3.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name })),
                        ).pipe(
                          Effect.map((r) => {
                            const c = r.PublicAccessBlockConfiguration;
                            const allBlocked =
                              (c?.BlockPublicAcls ?? false) &&
                              (c?.IgnorePublicAcls ?? false) &&
                              (c?.BlockPublicPolicy ?? false) &&
                              (c?.RestrictPublicBuckets ?? false);
                            return { allBlocked, config: c };
                          }),
                          Effect.catchAll(() =>
                            Effect.succeed({
                              allBlocked: false,
                              config: null,
                              note: "No public access block — may be publicly accessible",
                            }),
                          ),
                        ),
                        encryption: awsCall("S3", "GetBucketEncryption", () =>
                          s3.send(new GetBucketEncryptionCommand({ Bucket: bucket.Name })),
                        ).pipe(
                          Effect.map((r) => {
                            const rules = r.ServerSideEncryptionConfiguration?.Rules ?? [];
                            return {
                              encrypted: rules.length > 0,
                              algorithm: rules[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm ?? null,
                            };
                          }),
                          Effect.catchAll(() =>
                            Effect.succeed({ encrypted: false, algorithm: null }),
                          ),
                        ),
                        policy: awsCall("S3", "GetBucketPolicy", () =>
                          s3.send(new GetBucketPolicyCommand({ Bucket: bucket.Name })),
                        ).pipe(
                          Effect.map((r) => ({
                            hasPolicy: true,
                            hasWildcardPrincipal:
                              r.Policy?.includes('"Principal":"*"') ||
                              r.Policy?.includes('"Principal": "*"') ||
                              false,
                          })),
                          Effect.catchAll(() =>
                            Effect.succeed({ hasPolicy: false, hasWildcardPrincipal: false }),
                          ),
                        ),
                        location: awsCall("S3", "GetBucketLocation", () =>
                          s3.send(new GetBucketLocationCommand({ Bucket: bucket.Name })),
                        ).pipe(
                          Effect.map((r) => r.LocationConstraint ?? "us-east-1"),
                          Effect.catchAll(() => Effect.succeed("unknown")),
                        ),
                      },
                      { concurrency: 4 },
                    ).pipe(
                      Effect.map((checks) => ({
                        name: bucket.Name,
                        region: checks.location,
                        creationDate: bucket.CreationDate?.toISOString(),
                        publicAccessBlocked: checks.publicAccess.allBlocked,
                        encrypted: checks.encryption.encrypted,
                        encryptionAlgorithm: checks.encryption.algorithm,
                        hasPolicy: checks.policy.hasPolicy,
                        hasWildcardPrincipal: checks.policy.hasWildcardPrincipal,
                        risks: [
                          ...(!checks.publicAccess.allBlocked ? ["Public access not fully blocked"] : []),
                          ...(!checks.encryption.encrypted ? ["No server-side encryption"] : []),
                          ...(checks.policy.hasWildcardPrincipal ? ["Bucket policy has wildcard principal (*)"] : []),
                        ],
                      })),
                    ),
                  { concurrency: 5 },
                );
              }),
              Effect.map((results) => {
                const atRisk = results.filter((b) => b.risks.length > 0);
                return toolResponse({
                  totalBuckets: results.length,
                  bucketsAtRisk: atRisk.length,
                  buckets: results,
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(formatAwsError("Error auditing S3 buckets", error)),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "estimate_all_bucket_costs",
        "Estimate monthly storage costs for ALL S3 buckets using CloudWatch BucketSizeBytes metrics. Returns per-bucket cost breakdown by storage class, sorted by cost descending (top 20). Storage cost only — excludes requests and data transfer.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("S3", "ListBuckets", () =>
              s3.send(new ListBucketsCommand({})),
            ).pipe(
              Effect.flatMap((response) => {
                const buckets = response.Buckets ?? [];
                return Effect.forEach(
                  buckets,
                  (bucket) =>
                    // Get bucket region
                    awsCall("S3", "GetBucketLocation", () =>
                      s3.send(new GetBucketLocationCommand({ Bucket: bucket.Name })),
                    ).pipe(
                      Effect.map((r) => r.LocationConstraint ?? "us-east-1"),
                      Effect.catchAll(() => Effect.succeed("us-east-1")),
                      Effect.flatMap((region) => {
                        const now = new Date();
                        const twoDaysAgo = new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000);
                        // Query CloudWatch for each storage type
                        return Effect.forEach(
                          STORAGE_TYPES,
                          (storageType) =>
                            awsCall("CloudWatch", "GetMetricStatistics", () =>
                              cloudwatch.send(
                                new GetMetricStatisticsCommand({
                                  Namespace: "AWS/S3",
                                  MetricName: "BucketSizeBytes",
                                  Dimensions: [
                                    { Name: "BucketName", Value: bucket.Name },
                                    { Name: "StorageType", Value: storageType },
                                  ],
                                  StartTime: twoDaysAgo,
                                  EndTime: now,
                                  Period: 86400,
                                  Statistics: ["Average"],
                                }),
                              ),
                            ).pipe(
                              Effect.map((r) => {
                                const latestPoint = r.Datapoints
                                  ?.sort((a, b) => (b.Timestamp?.getTime() ?? 0) - (a.Timestamp?.getTime() ?? 0))
                                  ?.[0];
                                const bytes = latestPoint?.Average ?? 0;
                                if (bytes === 0) return null;
                                const gb = bytes / BYTES_PER_GB;
                                const rate = getS3StorageRate(region, storageType);
                                return {
                                  storageClass: storageType,
                                  sizeGb: parseFloat(gb.toFixed(2)),
                                  monthlyCost: parseFloat((gb * rate).toFixed(2)),
                                };
                              }),
                              Effect.catchAll(() => Effect.succeed(null)),
                            ),
                          { concurrency: 4 },
                        ).pipe(
                          Effect.map((storageResults) => {
                            const breakdown = storageResults.filter((r) => r !== null);
                            const totalCost = breakdown.reduce((sum, r) => sum + r.monthlyCost, 0);
                            return {
                              name: bucket.Name!,
                              region,
                              storageBreakdown: breakdown,
                              estimatedMonthlyCost: totalCost.toFixed(2),
                            };
                          }),
                        );
                      }),
                    ),
                  { concurrency: 5 },
                );
              }),
              Effect.map((results) => {
                const sorted = [...results].sort(
                  (a, b) => parseFloat(b.estimatedMonthlyCost) - parseFloat(a.estimatedMonthlyCost),
                );
                const topBuckets = sorted.slice(0, MAX_BUCKETS_IN_OUTPUT);
                const totalCost = sorted.reduce((sum, b) => sum + parseFloat(b.estimatedMonthlyCost), 0);
                return toolResponse({
                  totalBuckets: sorted.length,
                  totalEstimatedMonthlyCost: totalCost.toFixed(2),
                  buckets: topBuckets,
                  note: "Estimated storage cost based on published rates. Excludes requests and data transfer.",
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(formatAwsError("Error estimating S3 bucket costs", error)),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),
    ],
  });
}
