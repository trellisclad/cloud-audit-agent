import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  S3Client,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketEncryptionCommand,
  GetBucketPolicyCommand,
} from "@aws-sdk/client-s3";
import { createS3ToolsServer } from "../../src/tools/s3-tools.js";
import {
  insecureBuckets,
  insecurePublicAccessBlock,
} from "../fixtures/insecure-account.js";

const s3Mock = mockClient(S3Client);

describe("S3 Tools - AWS API Mocking", () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it("ListBucketsCommand returns insecure account buckets", async () => {
    s3Mock.on(ListBucketsCommand).resolves(insecureBuckets);

    const client = new S3Client({ region: "us-east-1" });
    const response = await client.send(new ListBucketsCommand({}));

    expect(response.Buckets).toHaveLength(2);
    expect(response.Buckets![0].Name).toBe("public-data-bucket");
  });

  it("GetPublicAccessBlockCommand shows public bucket", async () => {
    s3Mock
      .on(GetPublicAccessBlockCommand, { Bucket: "public-data-bucket" })
      .resolves(insecurePublicAccessBlock["public-data-bucket"]);

    const client = new S3Client({ region: "us-east-1" });
    const response = await client.send(
      new GetPublicAccessBlockCommand({ Bucket: "public-data-bucket" }),
    );

    const config = response.PublicAccessBlockConfiguration;
    expect(config?.BlockPublicAcls).toBe(false);
    expect(config?.BlockPublicPolicy).toBe(false);
  });

  it("GetPublicAccessBlockCommand shows secure bucket", async () => {
    s3Mock
      .on(GetPublicAccessBlockCommand, { Bucket: "logs-bucket" })
      .resolves(insecurePublicAccessBlock["logs-bucket"]);

    const client = new S3Client({ region: "us-east-1" });
    const response = await client.send(
      new GetPublicAccessBlockCommand({ Bucket: "logs-bucket" }),
    );

    const config = response.PublicAccessBlockConfiguration;
    expect(config?.BlockPublicAcls).toBe(true);
    expect(config?.BlockPublicPolicy).toBe(true);
    expect(config?.RestrictPublicBuckets).toBe(true);
  });

  it("handles NoSuchPublicAccessBlockConfiguration", async () => {
    s3Mock
      .on(GetPublicAccessBlockCommand, { Bucket: "no-config-bucket" })
      .rejects(
        new Error("NoSuchPublicAccessBlockConfiguration: The public access block configuration was not found"),
      );

    const client = new S3Client({ region: "us-east-1" });
    await expect(
      client.send(
        new GetPublicAccessBlockCommand({ Bucket: "no-config-bucket" }),
      ),
    ).rejects.toThrow("NoSuchPublicAccessBlockConfiguration");
  });

  it("handles bucket with no encryption", async () => {
    s3Mock
      .on(GetBucketEncryptionCommand, { Bucket: "unencrypted-bucket" })
      .rejects(
        new Error("ServerSideEncryptionConfigurationNotFoundError"),
      );

    const client = new S3Client({ region: "us-east-1" });
    await expect(
      client.send(
        new GetBucketEncryptionCommand({ Bucket: "unencrypted-bucket" }),
      ),
    ).rejects.toThrow("ServerSideEncryptionConfigurationNotFoundError");
  });

  it("handles bucket with no policy", async () => {
    s3Mock
      .on(GetBucketPolicyCommand, { Bucket: "no-policy-bucket" })
      .rejects(new Error("NoSuchBucketPolicy"));

    const client = new S3Client({ region: "us-east-1" });
    await expect(
      client.send(
        new GetBucketPolicyCommand({ Bucket: "no-policy-bucket" }),
      ),
    ).rejects.toThrow("NoSuchBucketPolicy");
  });

  it("createS3ToolsServer returns a valid MCP server config", () => {
    const server = createS3ToolsServer({ region: "us-east-1" });
    expect(server).toBeDefined();
  });
});
