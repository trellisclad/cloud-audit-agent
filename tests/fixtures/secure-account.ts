/**
 * Mock AWS responses representing a secure, well-configured account.
 * The agent should produce a clean report with no major findings.
 */

export const secureIamUsers = {
  Users: [
    {
      UserName: "dev-user",
      UserId: "AIDASECURE1",
      Arn: "arn:aws:iam::123456789012:user/dev-user",
      CreateDate: new Date("2025-06-01"),
      PasswordLastUsed: new Date("2026-03-06"),
    },
  ],
};

export const secureAccessKeys = {
  "dev-user": {
    AccessKeyMetadata: [
      {
        UserName: "dev-user",
        AccessKeyId: "AKIASECURE1",
        Status: "Active",
        CreateDate: new Date("2026-01-15"), // ~2 months old
      },
    ],
  },
};

export const secureAccessKeyLastUsed = {
  AKIASECURE1: {
    AccessKeyLastUsed: {
      LastUsedDate: new Date("2026-03-06"),
      ServiceName: "s3",
      Region: "us-east-1",
    },
  },
};

export const secureMfaDevices = {
  "dev-user": {
    MFADevices: [
      {
        SerialNumber:
          "arn:aws:iam::123456789012:mfa/dev-user",
        EnableDate: new Date("2025-06-01"),
      },
    ],
  },
};

export const secureBuckets = {
  Buckets: [
    { Name: "app-data-encrypted", CreationDate: new Date("2025-01-01") },
  ],
};

export const securePublicAccessBlock = {
  "app-data-encrypted": {
    PublicAccessBlockConfiguration: {
      BlockPublicAcls: true,
      IgnorePublicAcls: true,
      BlockPublicPolicy: true,
      RestrictPublicBuckets: true,
    },
  },
};

export const secureEncryption = {
  "app-data-encrypted": {
    ServerSideEncryptionConfiguration: {
      Rules: [
        {
          ApplyServerSideEncryptionByDefault: {
            SSEAlgorithm: "aws:kms",
            KMSMasterKeyID: "arn:aws:kms:us-east-1:123456789012:key/example",
          },
          BucketKeyEnabled: true,
        },
      ],
    },
  },
};

export const secureSecurityGroups = {
  SecurityGroups: [
    {
      GroupId: "sg-restricted",
      GroupName: "web-server-restricted",
      Description: "Restricted web server SG",
      VpcId: "vpc-456",
      IpPermissions: [
        {
          IpProtocol: "tcp",
          FromPort: 443,
          ToPort: 443,
          IpRanges: [{ CidrIp: "10.0.0.0/8", Description: "Internal only" }],
          Ipv6Ranges: [],
        },
      ],
      IpPermissionsEgress: [
        {
          IpProtocol: "tcp",
          FromPort: 443,
          ToPort: 443,
          IpRanges: [{ CidrIp: "0.0.0.0/0" }],
        },
      ],
    },
  ],
};

export const secureSecurityHubFindings = {
  Findings: [],
};

export const expectedFindings: Array<{
  id: string;
  domain: string;
  severity: string;
  keywords: string[];
}> = [];
