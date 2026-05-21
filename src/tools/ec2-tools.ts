import { tool } from "@anthropic-ai/claude-agent-sdk";
import { Effect } from "effect";
import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  DescribeNetworkAclsCommand,
  DescribeFlowLogsCommand,
} from "@aws-sdk/client-ec2";
import { getClientConfig, type AwsConfig } from "../aws/client.js";
import { awsCall, toolResponse, toolError, formatAwsError, createTracedSdkMcpServer } from "../aws/effect.js";

const SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 8080, 8443];

export function createEc2ToolsServer(awsConfig: AwsConfig) {
  const ec2 = new EC2Client(getClientConfig(awsConfig));

  return createTracedSdkMcpServer({
    name: "aws-ec2",
    version: "1.0.0",
    tools: [
      tool(
        "list_security_groups",
        "List all EC2 security groups with their inbound and outbound rules. Returns full rule details for security analysis.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("EC2", "DescribeSecurityGroups", () =>
              ec2.send(new DescribeSecurityGroupsCommand({})),
            ).pipe(
              Effect.map((response) => {
                const groups = response.SecurityGroups ?? [];
                return toolResponse({
                  securityGroupCount: groups.length,
                  securityGroups: groups.map((sg) => ({
                    groupId: sg.GroupId,
                    groupName: sg.GroupName,
                    description: sg.Description,
                    vpcId: sg.VpcId,
                    inboundRules: (sg.IpPermissions ?? []).map((r) => ({
                      protocol: r.IpProtocol,
                      fromPort: r.FromPort,
                      toPort: r.ToPort,
                      ipRanges: (r.IpRanges ?? []).map((ip) => ({
                        cidr: ip.CidrIp,
                        description: ip.Description,
                      })),
                      ipv6Ranges: (r.Ipv6Ranges ?? []).map((ip) => ({
                        cidr: ip.CidrIpv6,
                        description: ip.Description,
                      })),
                    })),
                    outboundRules: (sg.IpPermissionsEgress ?? []).map(
                      (r) => ({
                        protocol: r.IpProtocol,
                        fromPort: r.FromPort,
                        toPort: r.ToPort,
                        ipRanges: (r.IpRanges ?? []).map((ip) => ({
                          cidr: ip.CidrIp,
                        })),
                      }),
                    ),
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError("Error listing security groups", error),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "check_open_security_groups",
        "Find security groups with inbound rules allowing 0.0.0.0/0 or ::/0 access, especially on sensitive ports (SSH, RDP, databases). These are high-risk misconfigurations.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("EC2", "DescribeSecurityGroups", () =>
              ec2.send(new DescribeSecurityGroupsCommand({})),
            ).pipe(
              Effect.map((response) => {
                const groups = response.SecurityGroups ?? [];
                const openGroups: Array<{
                  groupId: string;
                  groupName: string;
                  vpcId: string;
                  openRules: Array<{
                    protocol: string;
                    fromPort: number;
                    toPort: number;
                    cidr: string;
                    isSensitivePort: boolean;
                  }>;
                }> = [];

                for (const sg of groups) {
                  const openRules: typeof openGroups[number]["openRules"] = [];

                  for (const rule of sg.IpPermissions ?? []) {
                    for (const ipRange of rule.IpRanges ?? []) {
                      if (ipRange.CidrIp === "0.0.0.0/0") {
                        const fromPort = rule.FromPort ?? 0;
                        const toPort = rule.ToPort ?? 65535;
                        const isSensitive = SENSITIVE_PORTS.some(
                          (p) => p >= fromPort && p <= toPort,
                        );
                        openRules.push({
                          protocol: rule.IpProtocol ?? "all",
                          fromPort,
                          toPort,
                          cidr: "0.0.0.0/0",
                          isSensitivePort: isSensitive,
                        });
                      }
                    }
                    for (const ipv6Range of rule.Ipv6Ranges ?? []) {
                      if (ipv6Range.CidrIpv6 === "::/0") {
                        const fromPort = rule.FromPort ?? 0;
                        const toPort = rule.ToPort ?? 65535;
                        const isSensitive = SENSITIVE_PORTS.some(
                          (p) => p >= fromPort && p <= toPort,
                        );
                        openRules.push({
                          protocol: rule.IpProtocol ?? "all",
                          fromPort,
                          toPort,
                          cidr: "::/0",
                          isSensitivePort: isSensitive,
                        });
                      }
                    }
                  }

                  if (openRules.length > 0) {
                    openGroups.push({
                      groupId: sg.GroupId ?? "",
                      groupName: sg.GroupName ?? "",
                      vpcId: sg.VpcId ?? "",
                      openRules,
                    });
                  }
                }

                return toolResponse({
                  totalSecurityGroups: groups.length,
                  openSecurityGroupCount: openGroups.length,
                  openSecurityGroups: openGroups,
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      "Error checking open security groups",
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
        "list_vpcs",
        "List all VPCs with their CIDR blocks and check whether VPC flow logs are enabled. Flow logs are important for network monitoring.",
        {},
        async () =>
          Effect.runPromise(
            Effect.all([
              awsCall("EC2", "DescribeVpcs", () =>
                ec2.send(new DescribeVpcsCommand({})),
              ),
              awsCall("EC2", "DescribeFlowLogs", () =>
                ec2.send(new DescribeFlowLogsCommand({})),
              ),
            ], { concurrency: 2 }).pipe(
              Effect.map(([vpcsResponse, flowLogsResponse]) => {
                const vpcs = vpcsResponse.Vpcs ?? [];
                const flowLogs = flowLogsResponse.FlowLogs ?? [];

                const flowLogVpcIds = new Set(
                  flowLogs
                    .filter((fl) => fl.ResourceId?.startsWith("vpc-"))
                    .map((fl) => fl.ResourceId),
                );

                return toolResponse({
                  vpcCount: vpcs.length,
                  vpcs: vpcs.map((v) => ({
                    vpcId: v.VpcId,
                    cidrBlock: v.CidrBlock,
                    isDefault: v.IsDefault,
                    state: v.State,
                    hasFlowLogs: flowLogVpcIds.has(v.VpcId),
                    tags: (v.Tags ?? []).reduce(
                      (acc, t) => {
                        if (t.Key && t.Value) acc[t.Key] = t.Value;
                        return acc;
                      },
                      {} as Record<string, string>,
                    ),
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(formatAwsError("Error listing VPCs", error)),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "list_network_acls",
        "List all network ACLs with their inbound and outbound rules. Network ACLs provide subnet-level network security.",
        {},
        async () =>
          Effect.runPromise(
            awsCall("EC2", "DescribeNetworkAcls", () =>
              ec2.send(new DescribeNetworkAclsCommand({})),
            ).pipe(
              Effect.map((response) => {
                const acls = response.NetworkAcls ?? [];
                return toolResponse({
                  networkAclCount: acls.length,
                  networkAcls: acls.map((acl) => ({
                    networkAclId: acl.NetworkAclId,
                    vpcId: acl.VpcId,
                    isDefault: acl.IsDefault,
                    inboundRules: (acl.Entries ?? [])
                      .filter((e) => !e.Egress)
                      .map((e) => ({
                        ruleNumber: e.RuleNumber,
                        protocol: e.Protocol,
                        ruleAction: e.RuleAction,
                        cidrBlock: e.CidrBlock,
                        portRange: e.PortRange
                          ? `${e.PortRange.From}-${e.PortRange.To}`
                          : "all",
                      })),
                    outboundRules: (acl.Entries ?? [])
                      .filter((e) => e.Egress)
                      .map((e) => ({
                        ruleNumber: e.RuleNumber,
                        protocol: e.Protocol,
                        ruleAction: e.RuleAction,
                        cidrBlock: e.CidrBlock,
                        portRange: e.PortRange
                          ? `${e.PortRange.From}-${e.PortRange.To}`
                          : "all",
                      })),
                  })),
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError("Error listing network ACLs", error),
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
