# cloud-audit-agent

AI-powered CLI agent that audits AWS accounts for security misconfigurations and cost anomalies using Claude.

The agent uses read-only AWS API calls to scan your account, then applies Claude's reasoning to produce prioritized findings with actionable remediation steps. It never modifies your AWS resources.

## Features

- **20 audit tools** across 5 domains: IAM, S3, EC2, Cost, and Compliance
- **AI-powered analysis** — Claude reasons over raw AWS data to detect issues human-written rules would miss
- **Read-only** — every tool is explicitly annotated as non-destructive
- **Scoped audits** — run a full audit or target specific domains
- **Cost anomaly detection** — identifies daily spending spikes and usage-type drill-downs
- **Bedrock support** — optionally route LLM calls through AWS Bedrock so data stays in your VPC
- **OpenTelemetry tracing** — optional Phoenix instrumentation for inspecting agent behavior

## Quick Start

### Prerequisites

- Node.js 18+
- AWS credentials configured (via `~/.aws/credentials`, environment variables, or IAM role)
- Claude authentication (Claude Max plan, Anthropic API key, or AWS Bedrock)

### Run with npx

```bash
# Full audit
npx @trellisclad/cloud-audit-agent --scope all

# Security-only audit
npx @trellisclad/cloud-audit-agent --scope iam s3 ec2 compliance

# Cost-only audit
npx @trellisclad/cloud-audit-agent --scope cost

# Specific region and AWS profile
npx @trellisclad/cloud-audit-agent --region eu-west-1 --profile production --scope all
```

### Install globally

```bash
npm install -g @trellisclad/cloud-audit-agent
cloud-audit-agent --scope all
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-s, --scope <scopes...>` | Audit scopes: `iam`, `s3`, `ec2`, `cost`, `compliance`, `all` | `all` |
| `-r, --region <region>` | AWS region to audit | `us-east-1` |
| `-p, --profile <profile>` | AWS CLI profile to use | default |
| `-f, --format <format>` | Output format: `markdown`, `human`, `html`, `json` | `markdown` |
| `-m, --model <model>` | Claude model to use | auto |
| `--max-turns <number>` | Maximum agent turns | auto-computed |
| `--redact` | Redact sensitive data (account IDs, resource names, ARNs) | `false` |
| `--trace` | Enable Phoenix tracing | `false` |

## Output Formats

The `--format` flag controls how the audit report is rendered.

### Markdown (default)

Raw markdown output from the agent, including the structured JSON findings block at the end. Best for piping into other tools or saving as `.md` files.

```bash
cloud-audit-agent --scope all > report.md
```

### Human

Clean, terminal-friendly report with findings grouped by severity. Strips the raw JSON block and adds scannable labels, resource identifiers, and a metadata footer.

```bash
cloud-audit-agent --scope all --format human
```

### HTML

Self-contained styled HTML report with color-coded severity badges, properly rendered tables, and a metadata footer. Open directly in a browser.

```bash
cloud-audit-agent --scope s3 --format html > report.html
open report.html
```

### JSON

Structured `AuditReport` object with parsed findings, severity/domain summaries, and audit metadata. Useful for programmatic consumption.

```bash
# Pipe to jq
cloud-audit-agent --scope iam --format json | jq '.findings[] | select(.severity == "CRITICAL")'

# Save for processing
cloud-audit-agent --scope all --format json > audit.json
```

## Audit Scopes

### IAM (6 tools)
List users, check access key age/rotation, MFA status, role trust policies, inline/attached policies, account summary.

### S3 (4 tools + cost estimation)
List buckets, check public access blocks, encryption settings, bucket policies. Per-bucket storage cost estimation via CloudWatch.

### EC2 (4 tools)
Security groups (open ports, 0.0.0.0/0 rules), VPCs, network ACLs, VPC flow log status.

### Cost (3 tools + anomaly detection)
Cost breakdown by service, cost forecasting, cost anomalies. Daily spike detection with usage-type drill-down.

### Compliance (3 tools)
Security Hub findings, AWS Config rule compliance, CIS benchmark status.

## Programmatic Usage

```typescript
import { runAudit } from "@trellisclad/cloud-audit-agent";

const result = await runAudit({
  awsConfig: { region: "us-east-1", profile: "default" },
  scopes: ["iam", "s3"],
});

console.log(result.markdown);
console.log(`Cost: $${result.costUsd.toFixed(4)}`);
```

## Architecture

The agent is built on the [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk) and uses [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) tool servers to interact with AWS.

```
CLI (commander) → runAudit() → Claude Agent SDK
                                    ↓
                              MCP Tool Servers
                         ┌──────────┼──────────┐
                     aws-iam    aws-s3    aws-ec2
                     aws-cost   aws-compliance
                         └──────────┼──────────┘
                                    ↓
                          AWS SDK (read-only)
```

The agent follows a 3-phase workflow:
1. **Detect** — systematically call all tools in scope to gather raw data
2. **Analyze** — reason over the data to identify security risks and cost issues
3. **Recommend** — produce prioritized findings with severity, impact, and remediation steps

## AWS Permissions

The agent requires **read-only** access. The following AWS managed policies cover all tools:

- `ReadOnlyAccess` (covers all services), or individually:
- `IAMReadOnlyAccess`
- `AmazonS3ReadOnlyAccess`
- `AmazonEC2ReadOnlyAccess`
- `AWSBillingReadOnlyAccess`
- `AWSSecurityHubReadOnlyAccess`
- `AWSConfigUserAccess`

## Development

```bash
git clone https://github.com/trellisclad/cloud-audit-agent.git
cd cloud-audit-agent
npm install
npm test        # run unit tests
npm run dev     # run CLI in dev mode
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on setting up the project and submitting pull requests.

## License

[Apache 2.0](LICENSE)
