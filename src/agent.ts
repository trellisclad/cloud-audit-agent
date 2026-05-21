import { query } from "@anthropic-ai/claude-agent-sdk";
import { createMcpServers } from "./tools/index.js";
import { buildSystemPrompt } from "./prompts/system-prompt.js";
import { getTracer, recordError, SpanStatusCode } from "./tracing.js";
import { resolveBedrockModelEnv, type AwsConfig } from "./aws/client.js";
import type { AuditScope } from "./types/findings.js";

// OpenInference semantic conventions for Phoenix
const OI = {
  SPAN_KIND: "openinference.span.kind",
  INPUT_VALUE: "input.value",
  INPUT_MIME_TYPE: "input.mime_type",
  OUTPUT_VALUE: "output.value",
  OUTPUT_MIME_TYPE: "output.mime_type",
  LLM_MODEL_NAME: "llm.model_name",
  LLM_TOKEN_COUNT_PROMPT: "llm.token_count.prompt",
  LLM_TOKEN_COUNT_COMPLETION: "llm.token_count.completion",
  LLM_TOKEN_COUNT_TOTAL: "llm.token_count.total",
  TOOL_NAME: "tool.name",
  TOOL_PARAMETERS: "tool.parameters",
} as const;

export interface AuditResult {
  markdown: string;
  costUsd: number;
  durationMs: number;
  numTurns: number;
  inputTokens: number;
  outputTokens: number;
}

export interface AnomalyThresholdOptions {
  minAbsoluteChange?: number;
  percentChangeThreshold?: number;
  dailySpikeStdDevs?: number;
}

export interface AgentOptions {
  awsConfig: AwsConfig;
  scopes: AuditScope[];
  maxTurns?: number;
  model?: string;
  onProgress?: (msg: string) => void;
  abortSignal?: AbortSignal;
  anomalyThresholds?: AnomalyThresholdOptions;
  includeCliCommands?: boolean;
  analysisPeriodDays?: number;
  drillDownMinSpend?: number;
  accountId?: string;
}

/** Compute maxTurns based on number of active scopes.
 *  Extra turns are added when cost or S3 scopes are active to allow for
 *  usage-type drill-down and per-bucket cost estimation. */
function computeMaxTurns(scopes: AuditScope[]): number {
  const hasCost = scopes.includes("all") || scopes.includes("cost");
  const hasS3 = scopes.includes("all") || scopes.includes("s3");
  const drillDownBuffer = (hasCost ? 5 : 0) + (hasS3 ? 2 : 0);
  const count = scopes.includes("all") ? 5 : scopes.length;
  if (count <= 1) return 10 + drillDownBuffer;
  if (count <= 3) return 15 + drillDownBuffer;
  return 25 + drillDownBuffer;
}

function defaultLog(msg: string) {
  const ts = new Date().toISOString().slice(11, 19);
  process.stderr.write(`  [${ts}] ${msg}\n`);
}

function serializeContent(
  content: Array<{ type: string; text?: string; name?: string; input?: unknown }>,
): string {
  return content
    .map((b) => {
      if (b.type === "text" && b.text) return b.text;
      if (b.type === "tool_use") return `[tool_call: ${b.name}(${JSON.stringify(b.input)})]`;
      return "";
    })
    .filter(Boolean)
    .join("\n");
}

export async function runAudit(options: AgentOptions): Promise<AuditResult> {
  const { awsConfig, scopes, maxTurns: userMaxTurns, model, onProgress, abortSignal, anomalyThresholds, includeCliCommands, analysisPeriodDays, drillDownMinSpend, accountId } = options;
  const maxTurns = userMaxTurns ?? computeMaxTurns(scopes);
  const log = onProgress ?? defaultLog;
  const tracer = getTracer();

  // Create an AbortController that the SDK can use, linked to our signal
  const abortController = new AbortController();
  if (abortSignal) {
    if (abortSignal.aborted) {
      abortController.abort();
    } else {
      abortSignal.addEventListener("abort", () => abortController.abort(), { once: true });
    }
  }

  return tracer.startActiveSpan("audit", async (auditSpan) => {
    auditSpan.setAttribute(OI.SPAN_KIND, "AGENT");

    try {
      const mcpServers = createMcpServers(awsConfig, scopes);
      const systemPrompt = buildSystemPrompt(scopes, anomalyThresholds, includeCliCommands, analysisPeriodDays, drillDownMinSpend, accountId);
      log(`maxTurns: ${maxTurns} (${userMaxTurns ? "user-specified" : "computed from " + scopes.length + " scope(s)"})`);

      const userPrompt = `Perform a comprehensive AWS security and cost audit for the ${awsConfig.region} region. Audit the following areas: ${scopes.join(", ")}. Use ALL available tools systematically. Start with the DETECT phase.`;

      auditSpan.setAttribute(
        OI.INPUT_VALUE,
        JSON.stringify({
          systemPrompt,
          userPrompt,
          region: awsConfig.region,
          scopes,
          maxTurns,
          ...(model ? { model } : {}),
        }),
      );
      auditSpan.setAttribute(OI.INPUT_MIME_TYPE, "application/json");

      let finalResult: AuditResult = {
        markdown: "",
        costUsd: 0,
        durationMs: 0,
        numTurns: 0,
        inputTokens: 0,
        outputTokens: 0,
      };
      let turnCount = 0;

      // Auto-resolve available Bedrock model IDs so Claude Code doesn't
      // try to use models that aren't enabled in this region
      const bedrockModelEnv =
        process.env.CLAUDE_CODE_USE_BEDROCK === "1"
          ? await resolveBedrockModelEnv(awsConfig)
          : {};

      const env: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) {
        if (v !== undefined) env[k] = v;
      }
      // Overlay auto-resolved models (explicit env vars take precedence)
      for (const [k, v] of Object.entries(bedrockModelEnv)) {
        if (!env[k]) env[k] = v;
      }

      const agentQuery = query({
        prompt: userPrompt,
        options: {
          systemPrompt,
          mcpServers,
          maxTurns,
          abortController,
          env,
          ...(model ? { model } : {}),
          tools: [],
          permissionMode: "bypassPermissions",
          allowDangerouslySkipPermissions: true,
        },
      });

      for await (const message of agentQuery) {
        if (message.type === "system" && message.subtype === "init") {
          log(`Model: ${message.model}`);
          log(`Tools: ${message.tools.join(", ")}`);
          log(
            `MCP servers: ${message.mcp_servers.map((s) => `${s.name} (${s.status})`).join(", ")}`,
          );
          auditSpan.setAttribute(OI.LLM_MODEL_NAME, message.model);
        }

        if (message.type === "assistant") {
          turnCount++;
          log(`Turn ${turnCount}/${maxTurns}`);

          const content = message.message.content as Array<{
            type: string;
            text?: string;
            name?: string;
            input?: unknown;
          }>;

          for (const block of content) {
            if (block.type === "tool_use") {
              log(`  Tool call: ${block.name}`);
            }
          }

          tracer.startActiveSpan(`turn_${turnCount}`, (turnSpan) => {
            turnSpan.setAttribute(OI.SPAN_KIND, "CHAIN");
            turnSpan.setAttribute("turn.number", turnCount);

            const output = serializeContent(content);
            if (output) {
              turnSpan.setAttribute(OI.OUTPUT_VALUE, output);
              turnSpan.setAttribute(OI.OUTPUT_MIME_TYPE, "text/plain");
            }

            if (message.error) {
              log(`  Error: ${message.error}`);
              turnSpan.setStatus({
                code: SpanStatusCode.ERROR,
                message: message.error,
              });
            }

            turnSpan.end();
          });

          if (turnCount >= maxTurns) {
            log(`Max turns (${maxTurns}) reached — stopping agent`);
            await agentQuery.interrupt();
            break;
          }
        }

        if (message.type === "result" && message.subtype === "success") {
          log(
            `Audit complete — ${message.num_turns} turns, $${message.total_cost_usd.toFixed(4)} cost, ${(message.duration_ms / 1000).toFixed(1)}s`,
          );
          auditSpan.setAttribute(OI.OUTPUT_VALUE, message.result);
          auditSpan.setAttribute(OI.OUTPUT_MIME_TYPE, "text/plain");
          auditSpan.setAttribute(
            OI.LLM_TOKEN_COUNT_PROMPT,
            message.usage.input_tokens,
          );
          auditSpan.setAttribute(
            OI.LLM_TOKEN_COUNT_COMPLETION,
            message.usage.output_tokens,
          );
          auditSpan.setAttribute(
            OI.LLM_TOKEN_COUNT_TOTAL,
            message.usage.input_tokens + message.usage.output_tokens,
          );
          auditSpan.setAttribute("audit.cost_usd", message.total_cost_usd);
          auditSpan.setAttribute("audit.duration_ms", message.duration_ms);
          auditSpan.setAttribute("audit.num_turns", message.num_turns);
          finalResult = {
            markdown: message.result,
            costUsd: message.total_cost_usd,
            durationMs: message.duration_ms,
            numTurns: message.num_turns,
            inputTokens: message.usage.input_tokens,
            outputTokens: message.usage.output_tokens,
          };
          break;
        }

        if (message.type === "result") {
          const errorMsg =
            "errors" in message
              ? (message as { errors: string[] }).errors.join(", ")
              : "Unknown error";
          log(`Audit failed (${message.subtype}): ${errorMsg}`);
          throw new Error(`Audit failed: ${errorMsg}`);
        }
      }

      auditSpan.setStatus({ code: SpanStatusCode.OK });
      return finalResult;
    } catch (error) {
      recordError(auditSpan, error);
      throw error;
    } finally {
      auditSpan.end();
    }
  });
}
