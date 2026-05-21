#!/usr/bin/env node
import { Command } from "commander";
import { runAudit } from "./agent.js";
import { verifyAwsCredentials } from "./aws/client.js";
import type { AuditScope } from "./types/findings.js";

const program = new Command();

program
  .name("aws-audit")
  .description("AWS Cost & Security Audit Agent powered by Claude")
  .version("1.0.0")
  .option("-r, --region <region>", "AWS region to audit", "us-east-1")
  .option("-p, --profile <profile>", "AWS CLI profile to use")
  .option(
    "-s, --scope <scopes...>",
    "Audit scopes: iam, s3, ec2, cost, compliance, all",
    ["all"],
  )
  .option("-m, --model <model>", "Claude model to use")
  .option("--max-turns <number>", "Maximum agent turns", "30")
  .option("--trace", "Enable Phoenix tracing", false)
  .action(async (opts) => {
    const scopes = opts.scope as AuditScope[];

    if (opts.trace) {
      const { initTracing } = await import("./tracing.js");
      initTracing("aws-security-agent");
    }

    console.error(`\n  AWS Security & Cost Audit Agent`);
    console.error(`  Region: ${opts.region}`);
    console.error(`  Scopes: ${scopes.join(", ")}`);

    // Verify AWS credentials before starting the agent
    console.error(`  Verifying AWS credentials...`);
    let accountId: string | undefined;
    try {
      const identity = await verifyAwsCredentials({
        region: opts.region,
        profile: opts.profile,
      });
      accountId = identity.account;
      console.error(`  Account: ${identity.account}`);
      console.error(`  Identity: ${identity.arn}`);
    } catch (error) {
      console.error(`\n  ${(error as Error).message}`);
      process.exit(1);
    }

    if (opts.trace) {
      console.error(`  Tracing: enabled (Phoenix)`);
    }
    console.error(`  Starting audit...\n`);

    try {
      const result = await runAudit({
        awsConfig: {
          region: opts.region,
          profile: opts.profile,
        },
        scopes,
        maxTurns: parseInt(opts.maxTurns, 10),
        model: opts.model,
        accountId,
      });

      console.log(result.markdown);
    } catch (error) {
      console.error(`\n  Error: ${(error as Error).message}`);
      process.exit(1);
    } finally {
      if (opts.trace) {
        const { shutdownTracing } = await import("./tracing.js");
        await shutdownTracing();
      }
    }
  });

program.parse();
