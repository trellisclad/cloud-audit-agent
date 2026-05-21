/**
 * S3 storage pricing lookup by region and storage class.
 * Rates are per GB/month based on published AWS pricing (as of 2025).
 * CloudWatch reports storage class as the StorageType dimension value.
 */

/** Per-GB/month rates by storage class for each region. */
const PRICING: Record<string, Record<string, number>> = {
  "us-east-1": {
    StandardStorage: 0.023,
    IntelligentTieringFAStorage: 0.023,
    IntelligentTieringIAStorage: 0.0125,
    StandardIAStorage: 0.0125,
    OneZoneIAStorage: 0.01,
    GlacierInstantRetrievalStorage: 0.004,
    GlacierStorage: 0.0036,
    DeepArchiveStorage: 0.00099,
  },
  "us-west-2": {
    StandardStorage: 0.023,
    IntelligentTieringFAStorage: 0.023,
    IntelligentTieringIAStorage: 0.0125,
    StandardIAStorage: 0.0125,
    OneZoneIAStorage: 0.01,
    GlacierInstantRetrievalStorage: 0.004,
    GlacierStorage: 0.0036,
    DeepArchiveStorage: 0.00099,
  },
  "eu-west-1": {
    StandardStorage: 0.024,
    IntelligentTieringFAStorage: 0.024,
    IntelligentTieringIAStorage: 0.0131,
    StandardIAStorage: 0.0131,
    OneZoneIAStorage: 0.0104,
    GlacierInstantRetrievalStorage: 0.004,
    GlacierStorage: 0.0036,
    DeepArchiveStorage: 0.00099,
  },
  "eu-central-1": {
    StandardStorage: 0.0245,
    IntelligentTieringFAStorage: 0.0245,
    IntelligentTieringIAStorage: 0.0135,
    StandardIAStorage: 0.0135,
    OneZoneIAStorage: 0.0108,
    GlacierInstantRetrievalStorage: 0.004,
    GlacierStorage: 0.0036,
    DeepArchiveStorage: 0.00099,
  },
  "ap-southeast-1": {
    StandardStorage: 0.025,
    IntelligentTieringFAStorage: 0.025,
    IntelligentTieringIAStorage: 0.0138,
    StandardIAStorage: 0.0138,
    OneZoneIAStorage: 0.011,
    GlacierInstantRetrievalStorage: 0.005,
    GlacierStorage: 0.005,
    DeepArchiveStorage: 0.002,
  },
  "ap-northeast-1": {
    StandardStorage: 0.025,
    IntelligentTieringFAStorage: 0.025,
    IntelligentTieringIAStorage: 0.0138,
    StandardIAStorage: 0.0138,
    OneZoneIAStorage: 0.011,
    GlacierInstantRetrievalStorage: 0.005,
    GlacierStorage: 0.005,
    DeepArchiveStorage: 0.002,
  },
};

const DEFAULT_REGION = "us-east-1";
const DEFAULT_STORAGE_CLASS = "StandardStorage";

/**
 * Get the per-GB/month storage rate for a given region and storage class.
 * Falls back to us-east-1 for unknown regions, and StandardStorage for unknown classes.
 */
export function getS3StorageRate(region: string, storageClass: string): number {
  const regionPricing = PRICING[region] ?? PRICING[DEFAULT_REGION]!;
  return regionPricing[storageClass] ?? regionPricing[DEFAULT_STORAGE_CLASS]!;
}
