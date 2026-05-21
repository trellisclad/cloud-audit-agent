import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod/v4";
import { Effect } from "effect";
import {
  SecurityHubClient,
  GetFindingsCommand,
  type AwsSecurityFindingFilters,
} from "@aws-sdk/client-securityhub";
import {
  ConfigServiceClient,
  DescribeComplianceByConfigRuleCommand,
} from "@aws-sdk/client-config-service";
import { getClientConfig, type AwsConfig } from "../aws/client.js";
import { awsCall, toolResponse, toolError, formatAwsError, createTracedSdkMcpServer } from "../aws/effect.js";

export function createComplianceToolsServer(awsConfig: AwsConfig) {
  const securityHub = new SecurityHubClient(getClientConfig(awsConfig));
  const configService = new ConfigServiceClient(getClientConfig(awsConfig));

  return createTracedSdkMcpServer({
    name: "aws-compliance",
    version: "1.0.0",
    tools: [
      tool(
        "get_security_hub_findings",
        "Get active AWS Security Hub findings. Optionally filter by severity. Returns findings with title, description, severity, and remediation guidance.",
        {
          severityLabel: z
            .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
            .optional()
            .describe("Filter findings by severity label"),
          maxResults: z
            .number()
            .min(1)
            .max(100)
            .default(25)
            .describe("Maximum number of findings to return"),
        },
        async (args) =>
          Effect.runPromise(
            Effect.sync(() => {
              const filters: AwsSecurityFindingFilters = {
                RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }],
              };
              if (args.severityLabel) {
                filters.SeverityLabel = [
                  { Value: args.severityLabel, Comparison: "EQUALS" },
                ];
              }
              return filters;
            }).pipe(
              Effect.flatMap((filters) =>
                awsCall("SecurityHub", "GetFindings", () =>
                  securityHub.send(
                    new GetFindingsCommand({
                      Filters: filters,
                      MaxResults: args.maxResults,
                      SortCriteria: [
                        { Field: "SeverityLabel", SortOrder: "desc" },
                      ],
                    }),
                  ),
                ),
              ),
              Effect.map((response) => {
                const findings = response.Findings ?? [];
                return toolResponse({
                  findingCount: findings.length,
                  findings: findings.map((f) => ({
                    id: f.Id,
                    title: f.Title,
                    description: f.Description,
                    severity: f.Severity?.Label,
                    severityScore: f.Severity?.Normalized,
                    status: f.Workflow?.Status,
                    resourceType: f.Resources?.[0]?.Type,
                    resourceId: f.Resources?.[0]?.Id,
                    generatorId: f.GeneratorId,
                    createdAt: f.CreatedAt,
                    updatedAt: f.UpdatedAt,
                    remediation: f.Remediation?.Recommendation?.Text,
                    remediationUrl: f.Remediation?.Recommendation?.Url,
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      "Error getting Security Hub findings",
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
        "get_config_compliance",
        "Get AWS Config rule compliance status. Shows which Config rules are compliant or non-compliant.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("ConfigService", "DescribeComplianceByConfigRule", () =>
              configService.send(
                new DescribeComplianceByConfigRuleCommand({}),
              ),
            ).pipe(
              Effect.map((response) => {
                const rules = response.ComplianceByConfigRules ?? [];
                return toolResponse({
                  ruleCount: rules.length,
                  compliantCount: rules.filter(
                    (r) =>
                      r.Compliance?.ComplianceType === "COMPLIANT",
                  ).length,
                  nonCompliantCount: rules.filter(
                    (r) =>
                      r.Compliance?.ComplianceType === "NON_COMPLIANT",
                  ).length,
                  rules: rules.map((r) => ({
                    configRuleName: r.ConfigRuleName,
                    complianceType: r.Compliance?.ComplianceType,
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      "Error getting Config compliance",
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
        "get_cis_benchmark_status",
        "Get CIS AWS Foundations Benchmark findings from Security Hub. CIS benchmarks are industry-standard security configuration guidelines.",
        {
          maxResults: z
            .number()
            .min(1)
            .max(100)
            .default(50)
            .describe("Maximum number of CIS findings to return"),
        },
        async (args) =>
          Effect.runPromise(
            awsCall("SecurityHub", "GetFindings", () =>
              securityHub.send(
                new GetFindingsCommand({
                  Filters: {
                    RecordState: [
                      { Value: "ACTIVE", Comparison: "EQUALS" },
                    ],
                    GeneratorId: [
                      {
                        Value:
                          "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark",
                        Comparison: "PREFIX",
                      },
                    ],
                  },
                  MaxResults: args.maxResults,
                  SortCriteria: [
                    { Field: "SeverityLabel", SortOrder: "desc" },
                  ],
                }),
              ),
            ).pipe(
              Effect.map((response) => {
                const findings = response.Findings ?? [];
                return toolResponse({
                  cisFindings: findings.length,
                  findings: findings.map((f) => ({
                    id: f.Id,
                    title: f.Title,
                    severity: f.Severity?.Label,
                    status: f.Compliance?.Status,
                    resourceType: f.Resources?.[0]?.Type,
                    resourceId: f.Resources?.[0]?.Id,
                    remediation: f.Remediation?.Recommendation?.Text,
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      "Error getting CIS benchmark findings",
                      error,
                    ),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),
    ],
  });
}
