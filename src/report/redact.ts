import type { AuditReport, Finding } from "../types/findings.js";

/**
 * Token registry that maps real values to consistent placeholder tokens.
 * If "babylon-mainnet-ledger-backups" appears 5 times, it's always "app-data-backups-01".
 */
class TokenRegistry {
  private counters = new Map<string, number>();
  private mappings = new Map<string, string>();

  register(category: string, realValue: string, prefix: string): string {
    const key = `${category}:${realValue}`;
    if (this.mappings.has(key)) return this.mappings.get(key)!;

    const count = (this.counters.get(category) ?? 0) + 1;
    this.counters.set(category, count);
    const token = `${prefix}-${String(count).padStart(2, "0")}`;
    this.mappings.set(key, token);
    return token;
  }

  /** Get all mappings for applying to free-form text (longest-first to avoid partial matches). */
  allMappings(): Array<[string, string]> {
    const entries = [...this.mappings.entries()].map(
      ([key, token]) => [key.split(":").slice(1).join(":"), token] as [string, string],
    );
    // Sort longest-first so "babylon-mainnet-ledger-backups" is replaced before "mainnet"
    entries.sort((a, b) => b[0].length - a[0].length);
    return entries;
  }
}

// AWS resource ID patterns
const ACCOUNT_ID_RE = /\b\d{12}\b/g;
const SG_ID_RE = /\bsg-[a-f0-9]{8,17}\b/g;
const VPC_ID_RE = /\bvpc-[a-f0-9]{8,17}\b/g;
const SUBNET_ID_RE = /\bsubnet-[a-f0-9]{8,17}\b/g;
const INSTANCE_ID_RE = /\bi-[a-f0-9]{8,17}\b/g;
const ACCESS_KEY_RE = /\bAKIA[A-Z0-9]{16}\b/g;
const ARN_RE = /arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s,)"]+/g;
const BUCKET_IN_ARN_RE = /arn:aws:s3:::([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])/g;

function redactString(text: string, registry: TokenRegistry): string {
  let result = text;

  // 1. Redact full ARNs first (they contain account IDs and resource names)
  result = result.replace(ARN_RE, (arn) => {
    return registry.register("arn", arn, "arn:aws:service:region:ACCT:resource");
  });

  // 2. S3 bucket ARNs — extract bucket name
  result = result.replace(BUCKET_IN_ARN_RE, (_match, bucket: string) => {
    const token = registry.register("bucket", bucket, "bucket");
    return `arn:aws:s3:::${token}`;
  });

  // 3. Account IDs
  result = result.replace(ACCOUNT_ID_RE, (id) => {
    return registry.register("account", id, "111111111111".slice(0, 3));
  });

  // 4. Resource IDs
  result = result.replace(SG_ID_RE, (id) => registry.register("sg", id, "sg-redacted"));
  result = result.replace(VPC_ID_RE, (id) => registry.register("vpc", id, "vpc-redacted"));
  result = result.replace(SUBNET_ID_RE, (id) => registry.register("subnet", id, "subnet-redacted"));
  result = result.replace(INSTANCE_ID_RE, (id) => registry.register("instance", id, "i-redacted"));
  result = result.replace(ACCESS_KEY_RE, (id) => registry.register("accesskey", id, "AKIAEXAMPLE"));

  return result;
}

const DEMO_BUCKET_NAMES = [
  "web-assets",
  "app-data-backups",
  "log-archive",
  "config-snapshots",
  "deployment-artifacts",
  "analytics-data",
  "media-uploads",
  "terraform-state",
  "session-logs",
  "compliance-reports",
  "cdn-origin",
  "data-lake",
  "ml-training-data",
  "api-cache",
  "temp-files",
];

const DEMO_USER_NAMES = [
  "deploy-bot",
  "ci-runner",
  "admin-user",
  "data-analyst",
  "monitoring-svc",
  "backup-agent",
];

const DEMO_ROLE_NAMES = [
  "LambdaExecutionRole",
  "EC2InstanceRole",
  "ECSTaskRole",
  "CrossAccountAudit",
  "DataPipelineRole",
];

function buildBucketNameReplacer(registry: TokenRegistry): (text: string) => string {
  // Match S3 bucket name patterns in free text — these look like:
  // lowercase alphanumeric with hyphens/dots, 3-63 chars, often compound names
  // We target names that appear after "bucket " or "s3:::" or in resource fields
  return (text: string) => {
    // Find bucket names from s3::: patterns
    const bucketPattern = /(?:s3:::|\bbucket\s+)([a-z0-9][a-z0-9.\-]{2,62})/gi;
    let match;
    while ((match = bucketPattern.exec(text)) !== null) {
      const name = match[1];
      if (!name.startsWith("bucket-") && !name.startsWith("ACCT")) {
        const idx = registry.allMappings().filter(([, t]) => t.startsWith("bucket-")).length;
        const demo = DEMO_BUCKET_NAMES[idx % DEMO_BUCKET_NAMES.length];
        registry.register("bucket", name, demo);
      }
    }
    return text;
  };
}

function applyRegistryReplacements(text: string, registry: TokenRegistry): string {
  let result = text;
  for (const [real, token] of registry.allMappings()) {
    // Use global replacement for each real value
    const escaped = real.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    result = result.replace(new RegExp(escaped, "g"), token);
  }
  return result;
}

/**
 * Redact sensitive data from the full markdown output and structured report.
 * Returns redacted markdown string.
 */
export function redactReport(markdown: string): string {
  const registry = new TokenRegistry();

  // Pre-scan: find bucket names, usernames etc. in the text
  const bucketScanner = buildBucketNameReplacer(registry);
  bucketScanner(markdown);

  // Apply pattern-based redaction
  let result = redactString(markdown, registry);

  // Apply all accumulated token replacements
  result = applyRegistryReplacements(result, registry);

  return result;
}

/**
 * Redact sensitive data from a structured AuditReport.
 */
export function redactAuditReport(report: AuditReport): AuditReport {
  const registry = new TokenRegistry();

  // Pre-scan all finding text to build registry
  for (const f of report.findings) {
    const combined = `${f.resource} ${f.title} ${f.description} ${f.recommendation}`;
    const bucketScanner = buildBucketNameReplacer(registry);
    bucketScanner(combined);
    redactString(combined, registry);
  }

  // Now apply redaction to each finding
  const findings: Finding[] = report.findings.map((f) => ({
    ...f,
    resource: applyRegistryReplacements(redactString(f.resource, registry), registry),
    title: applyRegistryReplacements(redactString(f.title, registry), registry),
    description: applyRegistryReplacements(redactString(f.description, registry), registry),
    recommendation: applyRegistryReplacements(redactString(f.recommendation, registry), registry),
  }));

  return { ...report, findings };
}
