import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod/v4";
import { Effect } from "effect";
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
import { getClientConfig, type AwsConfig } from "../aws/client.js";
import { awsCall, toolResponse, toolError, formatAwsError, createTracedSdkMcpServer } from "../aws/effect.js";

export function createIamToolsServer(awsConfig: AwsConfig) {
  const iam = new IAMClient(getClientConfig(awsConfig));

  return createTracedSdkMcpServer({
    name: "aws-iam",
    version: "1.0.0",
    tools: [
      tool(
        "list_iam_users",
        "List all IAM users with creation date, password last used, and ARN. Use this to get an overview of all IAM identities.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("IAM", "ListUsers", () =>
              iam.send(new ListUsersCommand({})),
            ).pipe(
              Effect.map((response) => {
                const users = response.Users ?? [];
                return toolResponse({
                  userCount: users.length,
                  users: users.map((u) => ({
                    userName: u.UserName,
                    userId: u.UserId,
                    arn: u.Arn,
                    createDate: u.CreateDate?.toISOString(),
                    passwordLastUsed:
                      u.PasswordLastUsed?.toISOString() ?? "Never",
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(formatAwsError("Error listing IAM users", error)),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "check_access_keys",
        "Check access key age, status, and last used date for a specific IAM user. Identifies keys older than 90 days that should be rotated.",
        {
          userName: z.string().describe("The IAM user name to check access keys for"),
        },
        async (args) =>
          Effect.runPromise(
            Effect.gen(function* () {
              const keysResponse = yield* awsCall("IAM", "ListAccessKeys", () =>
                iam.send(new ListAccessKeysCommand({ UserName: args.userName })),
              );
              const keys = keysResponse.AccessKeyMetadata ?? [];

              const keyDetails = yield* Effect.forEach(
                keys,
                (key) =>
                  awsCall("IAM", "GetAccessKeyLastUsed", () =>
                    iam.send(
                      new GetAccessKeyLastUsedCommand({
                        AccessKeyId: key.AccessKeyId,
                      }),
                    ),
                  ).pipe(
                    Effect.map((lastUsed) => {
                      const ageMs =
                        Date.now() - (key.CreateDate?.getTime() ?? Date.now());
                      const ageDays = Math.floor(
                        ageMs / (1000 * 60 * 60 * 24),
                      );
                      return {
                        accessKeyId: key.AccessKeyId,
                        status: key.Status,
                        createDate: key.CreateDate?.toISOString(),
                        ageDays,
                        isStale: ageDays > 90,
                        lastUsedDate:
                          lastUsed.AccessKeyLastUsed?.LastUsedDate?.toISOString() ??
                          "Never",
                        lastUsedService:
                          lastUsed.AccessKeyLastUsed?.ServiceName ?? "N/A",
                        lastUsedRegion:
                          lastUsed.AccessKeyLastUsed?.Region ?? "N/A",
                      };
                    }),
                  ),
                { concurrency: "unbounded" },
              );

              return toolResponse({
                userName: args.userName,
                accessKeys: keyDetails,
              });
            }).pipe(
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      `Error checking access keys for ${args.userName}`,
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
        "check_mfa_status",
        "Check whether MFA is enabled for a specific IAM user. Users without MFA are a significant security risk.",
        {
          userName: z.string().describe("The IAM user name to check MFA status for"),
        },
        async (args) =>
          Effect.runPromise(
            awsCall("IAM", "ListMFADevices", () =>
              iam.send(new ListMFADevicesCommand({ UserName: args.userName })),
            ).pipe(
              Effect.map((response) => {
                const devices = response.MFADevices ?? [];
                return toolResponse({
                  userName: args.userName,
                  mfaEnabled: devices.length > 0,
                  mfaDeviceCount: devices.length,
                  devices: devices.map((d) => ({
                    serialNumber: d.SerialNumber,
                    enableDate: d.EnableDate?.toISOString(),
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      `Error checking MFA for ${args.userName}`,
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
        "list_iam_roles",
        "List all IAM roles with their trust policy (AssumeRolePolicyDocument). Useful for identifying overly permissive role trust relationships.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("IAM", "ListRoles", () =>
              iam.send(new ListRolesCommand({})),
            ).pipe(
              Effect.map((response) => {
                const roles = response.Roles ?? [];
                return toolResponse({
                  roleCount: roles.length,
                  roles: roles.map((r) => ({
                    roleName: r.RoleName,
                    roleId: r.RoleId,
                    arn: r.Arn,
                    createDate: r.CreateDate?.toISOString(),
                    maxSessionDuration: r.MaxSessionDuration,
                    trustPolicy: r.AssumeRolePolicyDocument
                      ? JSON.parse(
                          decodeURIComponent(r.AssumeRolePolicyDocument),
                        )
                      : null,
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(formatAwsError("Error listing IAM roles", error)),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "check_user_policies",
        "List all inline and attached policies for a specific IAM user. Helps identify overly permissive access.",
        {
          userName: z.string().describe("The IAM user name to check policies for"),
        },
        async (args) =>
          Effect.runPromise(
            Effect.all([
              awsCall("IAM", "ListUserPolicies", () =>
                iam.send(
                  new ListUserPoliciesCommand({ UserName: args.userName }),
                ),
              ),
              awsCall("IAM", "ListAttachedUserPolicies", () =>
                iam.send(
                  new ListAttachedUserPoliciesCommand({
                    UserName: args.userName,
                  }),
                ),
              ),
            ], { concurrency: 2 }).pipe(
              Effect.map(([inlineResponse, attachedResponse]) =>
                toolResponse({
                  userName: args.userName,
                  inlinePolicies: inlineResponse.PolicyNames ?? [],
                  attachedPolicies: (
                    attachedResponse.AttachedPolicies ?? []
                  ).map((p) => ({
                    policyName: p.PolicyName,
                    policyArn: p.PolicyArn,
                  })),
                }),
              ),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      `Error checking policies for ${args.userName}`,
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
        "get_account_summary",
        "Get a full IAM authorization details snapshot including users, roles, groups, and policies. Provides a comprehensive view of the account's IAM configuration.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("IAM", "GetAccountAuthorizationDetails", () =>
              iam.send(new GetAccountAuthorizationDetailsCommand({})),
            ).pipe(
              Effect.map((response) =>
                toolResponse({
                  userDetailCount: response.UserDetailList?.length ?? 0,
                  roleDetailCount: response.RoleDetailList?.length ?? 0,
                  groupDetailCount: response.GroupDetailList?.length ?? 0,
                  policyCount: response.Policies?.length ?? 0,
                  users: (response.UserDetailList ?? []).map((u) => ({
                    userName: u.UserName,
                    arn: u.Arn,
                    inlinePolicyCount: u.UserPolicyList?.length ?? 0,
                    attachedPolicyCount:
                      u.AttachedManagedPolicies?.length ?? 0,
                    groupCount: u.GroupList?.length ?? 0,
                  })),
                  roles: (response.RoleDetailList ?? []).map((r) => ({
                    roleName: r.RoleName,
                    arn: r.Arn,
                    inlinePolicyCount: r.RolePolicyList?.length ?? 0,
                    attachedPolicyCount:
                      r.AttachedManagedPolicies?.length ?? 0,
                  })),
                }),
              ),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      "Error getting account authorization details",
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
        "audit_all_users",
        "Audit ALL IAM users in one call — checks access keys, MFA status, and attached policies for every user. Use this instead of calling individual check tools per user. Returns a summary with findings per user.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("IAM", "ListUsers", () =>
              iam.send(new ListUsersCommand({})),
            ).pipe(
              Effect.flatMap((response) => {
                const users = response.Users ?? [];
                return Effect.forEach(
                  users,
                  (user) =>
                    Effect.all(
                      {
                        accessKeys: awsCall("IAM", "ListAccessKeys", () =>
                          iam.send(new ListAccessKeysCommand({ UserName: user.UserName })),
                        ).pipe(
                          Effect.flatMap((keysResp) =>
                            Effect.forEach(
                              keysResp.AccessKeyMetadata ?? [],
                              (key) =>
                                awsCall("IAM", "GetAccessKeyLastUsed", () =>
                                  iam.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId })),
                                ).pipe(
                                  Effect.map((lastUsed) => {
                                    const ageMs = Date.now() - (key.CreateDate?.getTime() ?? Date.now());
                                    const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
                                    return {
                                      accessKeyId: key.AccessKeyId,
                                      status: key.Status,
                                      ageDays,
                                      isStale: ageDays > 90,
                                      lastUsedDate: lastUsed.AccessKeyLastUsed?.LastUsedDate?.toISOString() ?? "Never",
                                      lastUsedService: lastUsed.AccessKeyLastUsed?.ServiceName ?? "N/A",
                                    };
                                  }),
                                ),
                              { concurrency: "unbounded" },
                            ),
                          ),
                          Effect.catchAll(() => Effect.succeed([])),
                        ),
                        mfa: awsCall("IAM", "ListMFADevices", () =>
                          iam.send(new ListMFADevicesCommand({ UserName: user.UserName })),
                        ).pipe(
                          Effect.map((r) => ({
                            enabled: (r.MFADevices ?? []).length > 0,
                            deviceCount: (r.MFADevices ?? []).length,
                          })),
                          Effect.catchAll(() =>
                            Effect.succeed({ enabled: false, deviceCount: 0 }),
                          ),
                        ),
                        policies: Effect.all([
                          awsCall("IAM", "ListUserPolicies", () =>
                            iam.send(new ListUserPoliciesCommand({ UserName: user.UserName })),
                          ),
                          awsCall("IAM", "ListAttachedUserPolicies", () =>
                            iam.send(new ListAttachedUserPoliciesCommand({ UserName: user.UserName })),
                          ),
                        ], { concurrency: 2 }).pipe(
                          Effect.map(([inlineResp, attachedResp]) => ({
                            inlinePolicies: inlineResp.PolicyNames ?? [],
                            attachedPolicies: (attachedResp.AttachedPolicies ?? []).map((p) => ({
                              name: p.PolicyName,
                              arn: p.PolicyArn,
                            })),
                          })),
                          Effect.catchAll(() =>
                            Effect.succeed({ inlinePolicies: [] as string[], attachedPolicies: [] as Array<{ name: string | undefined; arn: string | undefined }> }),
                          ),
                        ),
                      },
                      { concurrency: 3 },
                    ).pipe(
                      Effect.map((checks) => {
                        const staleKeys = checks.accessKeys.filter((k) => k.isStale);
                        return {
                          userName: user.UserName,
                          arn: user.Arn,
                          createDate: user.CreateDate?.toISOString(),
                          passwordLastUsed: user.PasswordLastUsed?.toISOString() ?? "Never",
                          mfaEnabled: checks.mfa.enabled,
                          accessKeyCount: checks.accessKeys.length,
                          accessKeys: checks.accessKeys,
                          policies: checks.policies,
                          risks: [
                            ...(!checks.mfa.enabled ? ["MFA not enabled"] : []),
                            ...(staleKeys.length > 0 ? [`${staleKeys.length} access key(s) older than 90 days`] : []),
                          ],
                        };
                      }),
                    ),
                  { concurrency: 5 },
                );
              }),
              Effect.map((results) => {
                const atRisk = results.filter((u) => u.risks.length > 0);
                return toolResponse({
                  totalUsers: results.length,
                  usersAtRisk: atRisk.length,
                  users: results,
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(formatAwsError("Error auditing IAM users", error)),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),
    ],
  });
}
