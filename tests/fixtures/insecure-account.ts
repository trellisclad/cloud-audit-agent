/**
 * Mock AWS responses representing an insecure account.
 * This fixture simulates an account with known security issues
 * that the agent should detect.
 */

export const insecureIamUsers = {
  Users: [
    {
      UserName: "admin-user",
      UserId: "AIDAEXAMPLE1",
      Arn: "arn:aws:iam::123456789012:user/admin-user",
      CreateDate: new Date("2024-01-15"),
      PasswordLastUsed: new Date("2026-03-01"),
    },
    {
      UserName: "legacy-service-account",
      UserId: "AIDAEXAMPLE2",
      Arn: "arn:aws:iam::123456789012:user/legacy-service-account",
      CreateDate: new Date("2023-06-01"),
      PasswordLastUsed: undefined,
    },
  ],
};

export const insecureAccessKeys = {
  "admin-user": {
    AccessKeyMetadata: [
      {
        UserName: "admin-user",
        AccessKeyId: "AKIAEXAMPLE1",
        Status: "Active",
        CreateDate: new Date("2024-01-15"),
      },
    ],
  },
  "legacy-service-account": {
    AccessKeyMetadata: [
      {
        UserName: "legacy-service-account",
        AccessKeyId: "AKIAEXAMPLE2",
        Status: "Active",
        CreateDate: new Date("2025-06-01"), // ~9 months old = stale
      },
      {
        UserName: "legacy-service-account",
        AccessKeyId: "AKIAEXAMPLE3",
        Status: "Active",
        CreateDate: new Date("2024-03-01"), // ~2 years old = very stale
      },
    ],
  },
};

export const insecureAccessKeyLastUsed = {
  AKIAEXAMPLE1: {
    AccessKeyLastUsed: {
      LastUsedDate: new Date("2026-03-06"),
      ServiceName: "iam",
      Region: "us-east-1",
    },
  },
  AKIAEXAMPLE2: {
    AccessKeyLastUsed: {
      LastUsedDate: new Date("2025-12-01"),
      ServiceName: "s3",
      Region: "us-east-1",
    },
  },
  AKIAEXAMPLE3: {
    AccessKeyLastUsed: {
      LastUsedDate: undefined,
      ServiceName: "N/A",
      Region: "N/A",
    },
  },
};

export const insecureMfaDevices = {
  "admin-user": { MFADevices: [] }, // No MFA!
  "legacy-service-account": { MFADevices: [] }, // No MFA!
};

export const insecureBuckets = {
  Buckets: [
    { Name: "public-data-bucket", CreationDate: new Date("2024-06-01") },
    { Name: "logs-bucket", CreationDate: new Date("2024-01-01") },
  ],
};

export const insecurePublicAccessBlock = {
  "public-data-bucket": {
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: false,
      IgnorePublicAcls: false,
      BlockPublicPolicy: false,
      RestrictPublicBuckets: false,
    },
  },
  "logs-bucket": {
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: true,
      IgnorePublicAcls: true,
      BlockPublicPolicy: true,
      RestrictPublicBuckets: true,
    },
  },
};

export const insecureEncryption = {
  "public-data-bucket": null, // No encryption!
  "logs-bucket": {
    ServerSideEncryptionConfiguration: {
      Rules: [
        {
          ApplyServerSideEncryptionByDefault: {
            SSEAlgorithm: "AES256",
          },
          BucketKeyEnabled: true,
        },
      ],
    },
  },
};

export const insecureSecurityGroups = {
  SecurityGroups: [
    {
      GroupId: "sg-open-ssh",
      GroupName: "allow-ssh-from-anywhere",
      Description: "Open SSH",
      VpcId: "vpc-123",
      IpPermissions: [
        {
          IpProtocol: "tcp",
          FromPort: 22,
          ToPort: 22,
          IpRanges: [{ CidrIp: "0.0.0.0/0", Description: "Open SSH" }],
          Ipv6Ranges: [{ CidrIpv6: "::/0" }],
        },
      ],
      IpPermissionsEgress: [
        {
          IpProtocol: "-1",
          IpRanges: [{ CidrIp: "0.0.0.0/0" }],
        },
      ],
    },
    {
      GroupId: "sg-web",
      GroupName: "web-server",
      Description: "Web server SG",
      VpcId: "vpc-123",
      IpPermissions: [
        {
          IpProtocol: "tcp",
          FromPort: 443,
          ToPort: 443,
          IpRanges: [{ CidrIp: "0.0.0.0/0" }],
          Ipv6Ranges: [],
        },
      ],
      IpPermissionsEgress: [],
    },
  ],
};

export const insecureSecurityHubFindings = {
  Findings: [
    {
      Id: "finding-1",
      Title: "IAM root user access key should not exist",
      Description:
        "The root user has an access key, which provides unrestricted access to all AWS resources.",
      Severity: { Label: "CRITICAL", Normalized: 90 },
      Workflow: { Status: "NEW" },
      Resources: [
        {
          Type: "AwsAccount",
          Id: "AWS::::Account:123456789012",
        },
      ],
      GeneratorId: "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.12",
      CreatedAt: "2026-02-01T00:00:00Z",
      UpdatedAt: "2026-03-01T00:00:00Z",
      Compliance: { Status: "FAILED" },
      Remediation: {
        Recommendation: {
          Text: "Delete the root user access keys.",
          Url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
        },
      },
    },
    {
      Id: "finding-2",
      Title: "S3 bucket public read access should be restricted",
      Description:
        "public-data-bucket allows public read access, which could expose sensitive data.",
      Severity: { Label: "CRITICAL", Normalized: 90 },
      Workflow: { Status: "NEW" },
      Resources: [
        {
          Type: "AwsS3Bucket",
          Id: "arn:aws:s3:::public-data-bucket",
        },
      ],
      GeneratorId: "aws-foundational-security-best-practices",
      CreatedAt: "2026-01-15T00:00:00Z",
      UpdatedAt: "2026-03-01T00:00:00Z",
      Compliance: { Status: "FAILED" },
      Remediation: {
        Recommendation: {
          Text: "Enable public access block for the S3 bucket.",
        },
      },
    },
    {
      Id: "finding-3",
      Title: "Security groups should not allow unrestricted SSH access",
      Description:
        "Security group sg-open-ssh allows SSH access from 0.0.0.0/0.",
      Severity: { Label: "HIGH", Normalized: 70 },
      Workflow: { Status: "NEW" },
      Resources: [
        {
          Type: "AwsEc2SecurityGroup",
          Id: "arn:aws:ec2:us-east-1:123456789012:security-group/sg-open-ssh",
        },
      ],
      GeneratorId: "aws-foundational-security-best-practices",
      CreatedAt: "2026-02-10T00:00:00Z",
      UpdatedAt: "2026-03-01T00:00:00Z",
      Compliance: { Status: "FAILED" },
      Remediation: {
        Recommendation: {
          Text: "Restrict SSH access to specific IP ranges.",
        },
      },
    },
  ],
};

/**
 * Expected findings that the agent should detect for this scenario.
 * Used by the scoring function to evaluate agent accuracy.
 */
export const expectedFindings = [
  {
    id: "no-mfa-admin",
    domain: "IAM",
    severity: "CRITICAL",
    keywords: ["mfa", "admin-user"],
  },
  {
    id: "no-mfa-legacy",
    domain: "IAM",
    severity: "HIGH",
    keywords: ["mfa", "legacy-service-account"],
  },
  {
    id: "stale-key-legacy",
    domain: "IAM",
    severity: "HIGH",
    keywords: ["access key", "legacy-service-account", "old", "stale", "rotate"],
  },
  {
    id: "public-s3-bucket",
    domain: "S3",
    severity: "CRITICAL",
    keywords: ["public", "public-data-bucket", "access"],
  },
  {
    id: "unencrypted-s3-bucket",
    domain: "S3",
    severity: "HIGH",
    keywords: ["encrypt", "public-data-bucket"],
  },
  {
    id: "open-ssh-sg",
    domain: "EC2",
    severity: "HIGH",
    keywords: ["ssh", "22", "0.0.0.0", "security group", "sg-open-ssh"],
  },
  {
    id: "root-access-key",
    domain: "COMPLIANCE",
    severity: "CRITICAL",
    keywords: ["root", "access key"],
  },
];
