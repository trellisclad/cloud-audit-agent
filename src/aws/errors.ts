import { Data } from "effect";

/**
 * Tagged error for AWS permission/auth failures (403, AccessDenied, etc.)
 * The compiler tracks this in the Effect error channel so callers
 * can distinguish "no permission" from "service broken".
 */
export class AwsPermissionError extends Data.TaggedError("AwsPermissionError")<{
  service: string;
  operation: string;
  message: string;
}> {}

/**
 * Tagged error for AWS API throttling (429, Throttling, etc.)
 * Callers can retry selectively with Effect.retry + Schedule.
 */
export class AwsThrottleError extends Data.TaggedError("AwsThrottleError")<{
  service: string;
  operation: string;
  message: string;
}> {}

/**
 * Tagged error for "resource not found" responses (404, NoSuch*, *NotFound*).
 * Many AWS APIs use this for expected "not configured" states (e.g.,
 * NoSuchBucketPolicy). Tools can catchTag this and return data instead of error.
 */
export class AwsNotFoundError extends Data.TaggedError("AwsNotFoundError")<{
  service: string;
  operation: string;
  message: string;
}> {}

/**
 * Generic AWS service error — anything that doesn't match the above categories.
 */
export class AwsServiceError extends Data.TaggedError("AwsServiceError")<{
  service: string;
  operation: string;
  message: string;
  code?: string;
}> {}

export type AwsError =
  | AwsPermissionError
  | AwsThrottleError
  | AwsNotFoundError
  | AwsServiceError;
