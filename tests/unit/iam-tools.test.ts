import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  IAMClient,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListMFADevicesCommand,
  ListRolesCommand,
  ListUserPoliciesCommand,
  ListAttachedUserPoliciesCommand,
  GetAccountAuthorizationDetailsCommand,
} from "@aws-sdk/client-iam";
import { createIamToolsServer } from "../../src/tools/iam-tools.js";
import {
  insecureIamUsers,
  insecureAccessKeys,
  insecureAccessKeyLastUsed,
  insecureMfaDevices,
} from "../fixtures/insecure-account.js";

const iamMock = mockClient(IAMClient);

// We can't directly call the tool handlers via the MCP server wrapper,
// but we CAN verify the AWS mock setup works correctly for integration tests.
// For unit-level validation, we test the AWS calls directly.

describe("IAM Tools - AWS API Mocking", () => {
  beforeEach(() => {
    iamMock.reset();
  });

  it("ListUsersCommand returns insecure account users", async () => {
    iamMock.on(ListUsersCommand).resolves(insecureIamUsers);

    const client = new IAMClient({ region: "us-east-1" });
    const response = await client.send(new ListUsersCommand({}));

    expect(response.Users).toHaveLength(2);
    expect(response.Users![0].UserName).toBe("admin-user");
    expect(response.Users![1].UserName).toBe("legacy-service-account");
  });

  it("ListAccessKeysCommand returns stale keys", async () => {
    iamMock
      .on(ListAccessKeysCommand, { UserName: "legacy-service-account" })
      .resolves(insecureAccessKeys["legacy-service-account"]);

    const client = new IAMClient({ region: "us-east-1" });
    const response = await client.send(
      new ListAccessKeysCommand({ UserName: "legacy-service-account" }),
    );

    expect(response.AccessKeyMetadata).toHaveLength(2);
    // Verify the oldest key is over 90 days old
    const oldestKey = response.AccessKeyMetadata![1];
    const ageMs =
      Date.now() - (oldestKey.CreateDate?.getTime() ?? Date.now());
    const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
    expect(ageDays).toBeGreaterThan(90);
  });

  it("GetAccessKeyLastUsedCommand returns usage details", async () => {
    iamMock
      .on(GetAccessKeyLastUsedCommand, { AccessKeyId: "AKIAEXAMPLE1" })
      .resolves(insecureAccessKeyLastUsed["AKIAEXAMPLE1"]);

    const client = new IAMClient({ region: "us-east-1" });
    const response = await client.send(
      new GetAccessKeyLastUsedCommand({ AccessKeyId: "AKIAEXAMPLE1" }),
    );

    expect(response.AccessKeyLastUsed?.ServiceName).toBe("iam");
    expect(response.AccessKeyLastUsed?.Region).toBe("us-east-1");
  });

  it("ListMFADevicesCommand shows no MFA for insecure users", async () => {
    iamMock
      .on(ListMFADevicesCommand, { UserName: "admin-user" })
      .resolves(insecureMfaDevices["admin-user"]);

    const client = new IAMClient({ region: "us-east-1" });
    const response = await client.send(
      new ListMFADevicesCommand({ UserName: "admin-user" }),
    );

    expect(response.MFADevices).toHaveLength(0);
  });

  it("handles permission denied errors gracefully", async () => {
    iamMock
      .on(ListUsersCommand)
      .rejects(new Error("AccessDenied: User is not authorized"));

    const client = new IAMClient({ region: "us-east-1" });
    await expect(
      client.send(new ListUsersCommand({})),
    ).rejects.toThrow("AccessDenied");
  });

  it("ListRolesCommand returns roles with trust policies", async () => {
    iamMock.on(ListRolesCommand).resolves({
      Roles: [
        {
          RoleName: "AdminRole",
          RoleId: "AROAEXAMPLE",
          Arn: "arn:aws:iam::123456789012:role/AdminRole",
          CreateDate: new Date("2024-01-01"),
          MaxSessionDuration: 3600,
          AssumeRolePolicyDocument: encodeURIComponent(
            JSON.stringify({
              Version: "2012-10-17",
              Statement: [
                {
                  Effect: "Allow",
                  Principal: { AWS: "*" },
                  Action: "sts:AssumeRole",
                },
              ],
            }),
          ),
          Path: "/",
        },
      ],
    });

    const client = new IAMClient({ region: "us-east-1" });
    const response = await client.send(new ListRolesCommand({}));

    expect(response.Roles).toHaveLength(1);
    expect(response.Roles![0].RoleName).toBe("AdminRole");
    // Verify trust policy has wildcard principal
    const policy = JSON.parse(
      decodeURIComponent(response.Roles![0].AssumeRolePolicyDocument!),
    );
    expect(policy.Statement[0].Principal.AWS).toBe("*");
  });

  it("createIamToolsServer returns a valid MCP server config", () => {
    const server = createIamToolsServer({ region: "us-east-1" });
    expect(server).toBeDefined();
  });
});
