import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  SecurityHubClient,
  GetFindingsCommand,
} from "@aws-sdk/client-securityhub";
import {
  ConfigServiceClient,
  DescribeComplianceByConfigRuleCommand,
} from "@aws-sdk/client-config-service";
import { createComplianceToolsServer } from "../../src/tools/compliance-tools.js";
import { insecureSecurityHubFindings } from "../fixtures/insecure-account.js";

const shMock = mockClient(SecurityHubClient);
const configMock = mockClient(ConfigServiceClient);

describe("Compliance Tools - AWS API Mocking", () => {
  beforeEach(() => {
    shMock.reset();
    configMock.reset();
  });

  it("GetFindingsCommand returns Security Hub findings", async () => {
    shMock.on(GetFindingsCommand).resolves(insecureSecurityHubFindings);

    const client = new SecurityHubClient({ region: "us-east-1" });
    const response = await client.send(new GetFindingsCommand({}));

    expect(response.Findings).toHaveLength(3);
    expect(response.Findings![0].Severity?.Label).toBe("CRITICAL");
    expect(response.Findings![0].Title).toContain("root user");
  });

  it("handles Security Hub not enabled", async () => {
    shMock
      .on(GetFindingsCommand)
      .rejects(
        new Error(
          "InvalidAccessException: Security Hub is not enabled",
        ),
      );

    const client = new SecurityHubClient({ region: "us-east-1" });
    await expect(
      client.send(new GetFindingsCommand({})),
    ).rejects.toThrow("Security Hub is not enabled");
  });

  it("DescribeComplianceByConfigRuleCommand returns rule status", async () => {
    configMock.on(DescribeComplianceByConfigRuleCommand).resolves({
      ComplianceByConfigRules: [
        {
          ConfigRuleName: "iam-root-access-key-check",
          Compliance: { ComplianceType: "NON_COMPLIANT" },
        },
        {
          ConfigRuleName: "s3-bucket-ssl-requests-only",
          Compliance: { ComplianceType: "COMPLIANT" },
        },
        {
          ConfigRuleName: "vpc-flow-logs-enabled",
          Compliance: { ComplianceType: "NON_COMPLIANT" },
        },
      ],
    });

    const client = new ConfigServiceClient({ region: "us-east-1" });
    const response = await client.send(
      new DescribeComplianceByConfigRuleCommand({}),
    );

    const rules = response.ComplianceByConfigRules!;
    expect(rules).toHaveLength(3);

    const compliant = rules.filter(
      (r) => r.Compliance?.ComplianceType === "COMPLIANT",
    );
    const nonCompliant = rules.filter(
      (r) => r.Compliance?.ComplianceType === "NON_COMPLIANT",
    );
    expect(compliant).toHaveLength(1);
    expect(nonCompliant).toHaveLength(2);
  });

  it("handles AWS Config not enabled", async () => {
    configMock
      .on(DescribeComplianceByConfigRuleCommand)
      .rejects(
        new Error(
          "NoSuchConfigRuleException: AWS Config is not enabled",
        ),
      );

    const client = new ConfigServiceClient({ region: "us-east-1" });
    await expect(
      client.send(new DescribeComplianceByConfigRuleCommand({})),
    ).rejects.toThrow("AWS Config is not enabled");
  });

  it("createComplianceToolsServer returns a valid MCP server config", () => {
    const server = createComplianceToolsServer({ region: "us-east-1" });
    expect(server).toBeDefined();
  });
});
