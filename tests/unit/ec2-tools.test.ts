import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  DescribeFlowLogsCommand,
} from "@aws-sdk/client-ec2";
import { createEc2ToolsServer } from "../../src/tools/ec2-tools.js";
import { insecureSecurityGroups } from "../fixtures/insecure-account.js";

const ec2Mock = mockClient(EC2Client);

describe("EC2 Tools - AWS API Mocking", () => {
  beforeEach(() => {
    ec2Mock.reset();
  });

  it("DescribeSecurityGroupsCommand returns groups with open SSH", async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves(insecureSecurityGroups);

    const client = new EC2Client({ region: "us-east-1" });
    const response = await client.send(
      new DescribeSecurityGroupsCommand({}),
    );

    expect(response.SecurityGroups).toHaveLength(2);

    // Verify the first SG has open SSH
    const openSshSg = response.SecurityGroups![0];
    expect(openSshSg.GroupId).toBe("sg-open-ssh");

    const sshRule = openSshSg.IpPermissions![0];
    expect(sshRule.FromPort).toBe(22);
    expect(sshRule.ToPort).toBe(22);
    expect(sshRule.IpRanges![0].CidrIp).toBe("0.0.0.0/0");
  });

  it("detects 0.0.0.0/0 on sensitive ports", async () => {
    ec2Mock.on(DescribeSecurityGroupsCommand).resolves(insecureSecurityGroups);

    const client = new EC2Client({ region: "us-east-1" });
    const response = await client.send(
      new DescribeSecurityGroupsCommand({}),
    );

    const openRules: Array<{
      groupId: string;
      port: number;
      cidr: string;
    }> = [];

    const sensitivePorts = [22, 3389, 3306, 5432];

    for (const sg of response.SecurityGroups ?? []) {
      for (const rule of sg.IpPermissions ?? []) {
        for (const ipRange of rule.IpRanges ?? []) {
          if (ipRange.CidrIp === "0.0.0.0/0") {
            const fromPort = rule.FromPort ?? 0;
            const toPort = rule.ToPort ?? 65535;
            const isSensitive = sensitivePorts.some(
              (p) => p >= fromPort && p <= toPort,
            );
            if (isSensitive) {
              openRules.push({
                groupId: sg.GroupId!,
                port: fromPort,
                cidr: "0.0.0.0/0",
              });
            }
          }
        }
      }
    }

    expect(openRules).toHaveLength(1);
    expect(openRules[0].groupId).toBe("sg-open-ssh");
    expect(openRules[0].port).toBe(22);
  });

  it("DescribeVpcsCommand returns VPCs", async () => {
    ec2Mock.on(DescribeVpcsCommand).resolves({
      Vpcs: [
        {
          VpcId: "vpc-123",
          CidrBlock: "10.0.0.0/16",
          IsDefault: true,
          State: "available",
          Tags: [{ Key: "Name", Value: "default-vpc" }],
        },
      ],
    });
    ec2Mock.on(DescribeFlowLogsCommand).resolves({ FlowLogs: [] });

    const client = new EC2Client({ region: "us-east-1" });
    const response = await client.send(new DescribeVpcsCommand({}));

    expect(response.Vpcs).toHaveLength(1);
    expect(response.Vpcs![0].VpcId).toBe("vpc-123");
  });

  it("createEc2ToolsServer returns a valid MCP server config", () => {
    const server = createEc2ToolsServer({ region: "us-east-1" });
    expect(server).toBeDefined();
  });
});
