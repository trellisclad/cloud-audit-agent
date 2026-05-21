import { fromIni, fromNodeProviderChain } from "@aws-sdk/credential-providers";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import {
  BedrockClient,
  ListInferenceProfilesCommand,
} from "@aws-sdk/client-bedrock";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";

export interface AwsConfig {
  region: string;
  profile?: string;
}

export interface CallerIdentity {
  account: string;
  arn: string;
  userId: string;
}

export function getCredentials(
  profile?: string,
): AwsCredentialIdentityProvider {
  if (profile) {
    return fromIni({ profile });
  }
  return fromNodeProviderChain();
}

export function getClientConfig(config: AwsConfig) {
  return {
    region: config.region,
    credentials: getCredentials(config.profile),
  };
}

/**
 * Query Bedrock for available Anthropic inference profiles and return
 * env vars that pin Claude Code to valid model IDs.
 * Results are cached for the lifetime of the process.
 *
 * ListInferenceProfiles returns ALL system-defined profiles, even ones
 * not enabled in the account. We prefer versioned IDs (contain a date
 * like "20250514") since those correspond to explicitly enabled models.
 * Unversioned short aliases (e.g. "us.anthropic.claude-opus-4-6-v1")
 * may point to models not yet enabled.
 */
let cachedModelEnv: Record<string, string> | null = null;

export async function resolveBedrockModelEnv(
  config: AwsConfig,
): Promise<Record<string, string>> {
  if (cachedModelEnv) return cachedModelEnv;

  const client = new BedrockClient(getClientConfig(config));
  const resp = await client.send(new ListInferenceProfilesCommand({}));

  const profiles = (resp.inferenceProfileSummaries ?? [])
    .filter((p) => p.inferenceProfileId?.includes("anthropic"))
    .map((p) => p.inferenceProfileId!);

  console.log(
    `[bedrock] Found ${profiles.length} Anthropic inference profiles:`,
    profiles,
  );

  const envVars: Record<string, string> = {};

  // Pick the best profile for a model family.
  // Prefer: us. prefix > other prefixes, versioned (has date) > unversioned
  const findBest = (keyword: string): string | undefined => {
    const matches = profiles.filter((id) => id.includes(keyword));
    if (matches.length === 0) return undefined;

    const hasDate = (id: string) => /\d{8}/.test(id);

    // Sort: us. + versioned first, then us. unversioned, then others
    matches.sort((a, b) => {
      const aUs = a.startsWith("us.") ? 1 : 0;
      const bUs = b.startsWith("us.") ? 1 : 0;
      const aVer = hasDate(a) ? 1 : 0;
      const bVer = hasDate(b) ? 1 : 0;
      // Higher score = better: us prefix (2 points) + versioned (1 point)
      return bUs * 2 + bVer - (aUs * 2 + aVer);
    });

    return matches[0];
  };

  const sonnet = findBest("sonnet");
  const opus = findBest("opus");
  const haiku = findBest("haiku");

  if (sonnet) envVars.ANTHROPIC_DEFAULT_SONNET_MODEL = sonnet;
  if (opus) envVars.ANTHROPIC_DEFAULT_OPUS_MODEL = opus;
  if (haiku) envVars.ANTHROPIC_DEFAULT_HAIKU_MODEL = haiku;

  console.log("[bedrock] Resolved model env vars:", envVars);

  cachedModelEnv = envVars;
  return envVars;
}

/**
 * Validate AWS credentials by calling STS GetCallerIdentity.
 * Throws a descriptive error if credentials are missing, invalid, or expired.
 */
export async function verifyAwsCredentials(
  config: AwsConfig,
): Promise<CallerIdentity> {
  const sts = new STSClient(getClientConfig(config));
  try {
    const identity = await sts.send(new GetCallerIdentityCommand({}));
    return {
      account: identity.Account ?? "unknown",
      arn: identity.Arn ?? "unknown",
      userId: identity.UserId ?? "unknown",
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    throw new Error(
      `AWS credential check failed: ${msg}\n  Ensure valid credentials are configured via AWS_PROFILE, environment variables, or IAM role.`,
    );
  }
}
