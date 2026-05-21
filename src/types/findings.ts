export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  id: string;
  domain: "IAM" | "S3" | "EC2" | "COST" | "COMPLIANCE";
  severity: Severity;
  title: string;
  description: string;
  resource: string;
  recommendation: string;
}

export interface AuditReport {
  timestamp: string;
  region: string;
  scope: string[];
  findings: Finding[];
  summary: {
    total: number;
    bySeverity: Record<Severity, number>;
    byDomain: Record<string, number>;
  };
}

export type AuditScope = "iam" | "s3" | "ec2" | "cost" | "compliance" | "all";
