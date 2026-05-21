import { Effect } from "effect";
import { trace, SpanStatusCode } from "@opentelemetry/api";
import {
  AwsPermissionError,
  AwsThrottleError,
  AwsNotFoundError,
  AwsServiceError,
  type AwsError,
} from "./errors.js";

// ---------------------------------------------------------------------------
// Tool response helpers
// ---------------------------------------------------------------------------

export type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
};

/** Wrap structured data as a successful MCP tool response. */
export const toolResponse = (data: unknown): ToolResult => ({
  content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
});

/** Wrap a plain string as an MCP tool error response. */
export const toolError = (message: string): ToolResult => ({
  content: [{ type: "text" as const, text: message }],
});

// ---------------------------------------------------------------------------
// Traced MCP server wrapper
// ---------------------------------------------------------------------------

import { createSdkMcpServer } from "@anthropic-ai/claude-agent-sdk";

/**
 * Drop-in replacement for createSdkMcpServer that wraps every tool handler
 * with OpenTelemetry tracing. Captures tool input (args) and output as
 * OpenInference TOOL spans visible in Phoenix.
 *
 * Safe to use without tracing enabled — OTel returns a no-op tracer by default.
 */
export function createTracedSdkMcpServer(
  options: Parameters<typeof createSdkMcpServer>[0],
): ReturnType<typeof createSdkMcpServer> {
  const tracedTools = options.tools?.map((toolDef) => ({
    ...toolDef,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    handler: async (args: any, extra: unknown) => {
      const tracer = trace.getTracer("aws-security-agent");
      return tracer.startActiveSpan(`tool:${toolDef.name}`, async (span) => {
        span.setAttribute("openinference.span.kind", "TOOL");
        span.setAttribute("tool.name", toolDef.name);
        span.setAttribute("input.value", JSON.stringify(args ?? {}));
        span.setAttribute("input.mime_type", "application/json");
        try {
          const result = await toolDef.handler(args, extra);
          const output = (result.content ?? [])
            .map((c: { type: string; text?: string }) =>
              c.type === "text" ? c.text ?? "" : "",
            )
            .join("\n");
          if (output) {
            span.setAttribute("output.value", output);
            span.setAttribute("output.mime_type", "application/json");
          }
          return result;
        } catch (error) {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: error instanceof Error ? error.message : String(error),
          });
          if (error instanceof Error) span.recordException(error);
          throw error;
        } finally {
          span.end();
        }
      });
    },
  }));

  return createSdkMcpServer({ ...options, tools: tracedTools });
}

// ---------------------------------------------------------------------------
// AWS SDK → Effect wrapper
// ---------------------------------------------------------------------------

/**
 * Wraps an AWS SDK call in an Effect, classifying the error by tag.
 *
 * Usage:
 *   awsCall("IAM", "ListUsers", () => iam.send(new ListUsersCommand({})))
 *
 * The returned Effect fails with one of:
 *   AwsPermissionError | AwsThrottleError | AwsNotFoundError | AwsServiceError
 */
export function awsCall<A>(
  service: string,
  operation: string,
  fn: () => Promise<A>,
): Effect.Effect<A, AwsError> {
  return Effect.tryPromise({
    try: fn,
    catch: (error) => classifyAwsError(service, operation, error),
  });
}

// ---------------------------------------------------------------------------
// Error formatting
// ---------------------------------------------------------------------------

/** Format an AwsError into a human-readable tool error message. */
export function formatAwsError(prefix: string, error: AwsError): string {
  switch (error._tag) {
    case "AwsPermissionError":
      return `${prefix}: ${error.message}. May indicate insufficient permissions.`;
    case "AwsThrottleError":
      return `${prefix}: API rate limited for ${error.service}:${error.operation}. Please retry.`;
    case "AwsNotFoundError":
      return `${prefix}: ${error.message}`;
    case "AwsServiceError":
      return `${prefix}: ${error.message}`;
  }
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

const PERMISSION_CODES = new Set([
  "AccessDeniedException",
  "AccessDenied",
  "UnauthorizedAccess",
  "InvalidClientTokenId",
  "ExpiredTokenException",
  "AuthFailure",
  "SignatureDoesNotMatch",
]);

const THROTTLE_CODES = new Set([
  "Throttling",
  "ThrottlingException",
  "TooManyRequestsException",
  "RequestLimitExceeded",
  "BandwidthLimitExceeded",
  "ProvisionedThroughputExceededException",
]);

function classifyAwsError(
  service: string,
  operation: string,
  error: unknown,
): AwsError {
  const name: string =
    (error as { name?: string })?.name ?? "";
  const statusCode: number | undefined =
    (error as { $metadata?: { httpStatusCode?: number } })?.$metadata
      ?.httpStatusCode;
  const message =
    error instanceof Error ? error.message : String(error);

  // Permission / auth errors
  if (
    statusCode === 403 ||
    statusCode === 401 ||
    PERMISSION_CODES.has(name)
  ) {
    return new AwsPermissionError({ service, operation, message });
  }

  // Throttle errors
  if (statusCode === 429 || THROTTLE_CODES.has(name)) {
    return new AwsThrottleError({ service, operation, message });
  }

  // Not-found errors (includes AWS "NoSuch*" / "*NotFound*" / "*NotExist*")
  if (
    statusCode === 404 ||
    name.includes("NotFound") ||
    name.includes("NoSuch") ||
    name.includes("NotExist")
  ) {
    return new AwsNotFoundError({ service, operation, message });
  }

  // Anything else
  return new AwsServiceError({
    service,
    operation,
    message,
    code: name || undefined,
  });
}
