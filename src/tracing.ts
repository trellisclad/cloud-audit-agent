import { register } from "@arizeai/phoenix-otel";
import { trace, type Span, SpanStatusCode } from "@opentelemetry/api";
import type { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";

let provider: NodeTracerProvider | undefined;

export function initTracing(projectName: string) {
  provider = register({
    projectName,
    url:
      process.env.PHOENIX_COLLECTOR_ENDPOINT ?? "http://localhost:6006",
    batch: false,
  });
  return trace.getTracer("aws-security-agent");
}

export function getTracer() {
  return trace.getTracer("aws-security-agent");
}

export async function shutdownTracing() {
  if (provider) {
    await provider.forceFlush();
    await provider.shutdown();
  }
}

export function recordError(span: Span, error: unknown) {
  span.setStatus({ code: SpanStatusCode.ERROR, message: String(error) });
  if (error instanceof Error) {
    span.recordException(error);
  }
}

export { SpanStatusCode };
