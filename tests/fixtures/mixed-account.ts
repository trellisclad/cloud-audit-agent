/**
 * Mock AWS responses representing an account with some security issues.
 * The agent should find partial issues but also note compliant resources.
 */

export const mixedIamUsers = {
  Users: [
    {
      UserName: "admin-with-mfa",
      UserId: "AIDAMIXED1",
      Arn: "arn:aws:iam::123456789012:user/admin-with-mfa",
      CreateDate: new Date("2025-01-01"),
      PasswordLastUsed: new Date("2026-03-06"),
    },
    {
      UserName: "dev-no-mfa",
      UserId: "AIDAMIXED2",
      Arn: "arn:aws:iam::123456789012:user/dev-no-mfa",
      CreateDate: new Date("2025-06-01"),
      PasswordLastUsed: new Date("2026-03-05"),
    },
  ],
};

export const mixedAccessKeys = {
  "admin-with-mfa": {
    AccessKeyMetadata: [
      {
        UserName: "admin-with-mfa",
        AccessKeyId: "AKIAMIXED1",
        Status: "Active",
        CreateDate: new Date("2026-02-01"), // Fresh key
      },
    ],
  },
  "dev-no-mfa": {
    AccessKeyMetadata: [
      {
        UserName: "dev-no-mfa",
        AccessKeyId: "AKIAMIXED2",
        Status: "Active",
        CreateDate: new Date("2025-06-01"), // ~9 months old
      },
    ],
  },
};

export const mixedAccessKeyLastUsed = {
  AKIAMIXED1: {
    AccessKeyLastUsed: {
      LastUsedDate: new Date("2026-03-06"),
      ServiceName: "sts",
      Region: "us-east-1",
    },
  },
  AKIAMIXED2: {
    AccessKeyLastUsed: {
      LastUsedDate: new Date("2026-03-01"),
      ServiceName: "s3",
      Region: "us-east-1",
    },
  },
};

export const mixedMfaDevices = {
  "admin-with-mfa": {
    MFADevices: [
      {
        SerialNumber: "arn:aws:iam::123456789012:mfa/admin-with-mfa",
        EnableDate: new Date("2025-01-01"),
      },
    ],
  },
  "dev-no-mfa": { MFADevices: [] }, // Missing MFA
};

export const mixedBuckets = {
  Buckets: [
    { Name: "secure-bucket", CreationDate: new Date("2025-01-01") },
    { Name: "misconfigured-bucket", CreationDate: new Date("2025-06-01") },
  ],
};

export const mixedPublicAccessBlock = {
  "secure-bucket": {
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: true,
      IgnorePublicAcls: true,
      BlockPublicPolicy: true,
      RestrictPublicBuckets: true,
    },
  },
  "misconfigured-bucket": {
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: true,
      IgnorePublicAcls: false,
      BlockPublicPolicy: false,
      RestrictPublicBuckets: false,
    },
  },
};

export const mixedSecurityGroups = {
  SecurityGroups: [
    {
      GroupId: "sg-web-open",
      GroupName: "web-public",
      Description: "Web server open on 8080",
      VpcId: "vpc-789",
      IpPermissions: [
        {
          IpProtocol: "tcp",
          FromPort: 8080,
          ToPort: 8080,
          IpRanges: [{ CidrIp: "0.0.0.0/0" }],
          Ipv6Ranges: [],
        },
      ],
      IpPermissionsEgress: [],
    },
    {
      GroupId: "sg-internal",
      GroupName: "internal-only",
      Description: "Internal services",
      VpcId: "vpc-789",
      IpPermissions: [
        {
          IpProtocol: "tcp",
          FromPort: 5432,
          ToPort: 5432,
          IpRanges: [{ CidrIp: "10.0.0.0/8" }],
          Ipv6Ranges: [],
        },
      ],
      IpPermissionsEgress: [],
    },
  ],
};

export const expectedFindings = [
  {
    id: "no-mfa-dev",
    domain: "IAM",
    severity: "HIGH",
    keywords: ["mfa", "dev-no-mfa"],
  },
  {
    id: "stale-key-dev",
    domain: "IAM",
    severity: "MEDIUM",
    keywords: ["access key", "dev-no-mfa", "old", "rotate"],
  },
  {
    id: "partial-public-access-block",
    domain: "S3",
    severity: "MEDIUM",
    keywords: ["public access", "misconfigured-bucket"],
  },
  {
    id: "open-8080-sg",
    domain: "EC2",
    severity: "MEDIUM",
    keywords: ["8080", "0.0.0.0", "security group"],
  },
];
