import { createIamToolsServer } from "./iam-tools.js";
import { createS3ToolsServer } from "./s3-tools.js";
import { createEc2ToolsServer } from "./ec2-tools.js";
import { createCostToolsServer } from "./cost-tools.js";
import { createComplianceToolsServer } from "./compliance-tools.js";
import type { AwsConfig } from "../aws/client.js";
import type { AuditScope } from "../types/findings.js";

type McpServerMap = Record<
  string,
  ReturnType<typeof createIamToolsServer>
>;

export function createMcpServers(
  awsConfig: AwsConfig,
  scopes: AuditScope[],
): McpServerMap {
  const includeAll = scopes.includes("all");
  const servers: McpServerMap = {};

  if (includeAll || scopes.includes("iam")) {
    servers["aws-iam"] = createIamToolsServer(awsConfig);
  }
  if (includeAll || scopes.includes("s3")) {
    servers["aws-s3"] = createS3ToolsServer(awsConfig);
  }
  if (includeAll || scopes.includes("ec2")) {
    servers["aws-ec2"] = createEc2ToolsServer(awsConfig);
  }
  if (includeAll || scopes.includes("cost")) {
    servers["aws-cost"] = createCostToolsServer(awsConfig);
  }
  if (includeAll || scopes.includes("compliance")) {
    servers["aws-compliance"] = createComplianceToolsServer(awsConfig);
  }

  return servers;
}
