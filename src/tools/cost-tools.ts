import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod/v4";
import { Effect } from "effect";
import {
  CostExplorerClient,
  GetCostAndUsageCommand,
  GetCostForecastCommand,
} from "@aws-sdk/client-cost-explorer";
import { getClientConfig, type AwsConfig } from "../aws/client.js";
import { awsCall, toolResponse, toolError, formatAwsError, createTracedSdkMcpServer } from "../aws/effect.js";
import {
  DEFAULT_THRESHOLDS,
  detectTrendAnomalies,
  detectDailySpikes,
  type DailyCostEntry,
  type AnomalyThresholds,
} from "./anomaly-detection.js";

function formatDate(date: Date): string {
  return date.toISOString().split("T")[0]!;
}

function daysAgo(days: number): Date {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d;
}

/** Number of days of daily data used for spike baseline (not user-configurable). */
const DAILY_BASELINE_DAYS = 60;

/** Aggregate Cost Explorer ResultsByTime into a service → total cost map. */
function aggregateCosts(
  resultsByTime: { Groups?: { Keys?: string[]; Metrics?: Record<string, { Amount?: string }> }[] }[],
): Map<string, number> {
  const costs = new Map<string, number>();
  for (const result of resultsByTime) {
    for (const group of result.Groups ?? []) {
      const service = group.Keys?.[0] ?? "Unknown";
      const cost = parseFloat(group.Metrics?.UnblendedCost?.Amount ?? "0");
      costs.set(service, (costs.get(service) ?? 0) + cost);
    }
  }
  return costs;
}

export function createCostToolsServer(awsConfig: AwsConfig) {
  const costExplorer = new CostExplorerClient(getClientConfig(awsConfig));

  return createTracedSdkMcpServer({
    name: "aws-cost",
    version: "1.0.0",
    tools: [
      tool(
        "get_cost_and_usage",
        "Get AWS cost breakdown by service for a specified date range. Returns blended and unblended costs grouped by service.",
        {
          startDate: z
            .string()
            .describe("Start date in YYYY-MM-DD format"),
          endDate: z.string().describe("End date in YYYY-MM-DD format"),
          granularity: z
            .enum(["DAILY", "MONTHLY"])
            .default("MONTHLY")
            .describe("Cost aggregation granularity"),
        },
        async (args) =>
          Effect.runPromise(
            awsCall("CostExplorer", "GetCostAndUsage", () =>
              costExplorer.send(
                new GetCostAndUsageCommand({
                  TimePeriod: {
                    Start: args.startDate,
                    End: args.endDate,
                  },
                  Granularity: args.granularity,
                  Metrics: ["BlendedCost", "UnblendedCost", "UsageQuantity"],
                  GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }],
                }),
              ),
            ).pipe(
              Effect.map((response) =>
                toolResponse({
                  timePeriod: {
                    start: args.startDate,
                    end: args.endDate,
                  },
                  granularity: args.granularity,
                  results: (response.ResultsByTime ?? []).map((r) => ({
                    period: r.TimePeriod,
                    groups: (r.Groups ?? []).map((g) => ({
                      service: g.Keys?.[0],
                      blendedCost: g.Metrics?.BlendedCost?.Amount,
                      unblendedCost: g.Metrics?.UnblendedCost?.Amount,
                      unit: g.Metrics?.BlendedCost?.Unit,
                    })),
                    total: r.Total,
                  })),
                }),
              ),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      "Error getting cost and usage",
                      error,
                    ),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "get_cost_forecast",
        "Get projected AWS costs for the upcoming period based on historical usage patterns.",
        {
          days: z
            .number()
            .default(30)
            .describe("Number of days to forecast (default 30)"),
        },
        async (args) =>
          Effect.runPromise(
            Effect.sync(() => ({
              startDate: formatDate(new Date()),
              endDate: formatDate(daysAgo(-args.days)),
            })).pipe(
              Effect.flatMap(({ startDate, endDate }) =>
                awsCall("CostExplorer", "GetCostForecast", () =>
                  costExplorer.send(
                    new GetCostForecastCommand({
                      TimePeriod: { Start: startDate, End: endDate },
                      Metric: "UNBLENDED_COST",
                      Granularity: "MONTHLY",
                    }),
                  ),
                ).pipe(
                  Effect.map((response) =>
                    toolResponse({
                      forecastPeriod: { start: startDate, end: endDate },
                      total: response.Total,
                      forecastResultsByTime: (
                        response.ForecastResultsByTime ?? []
                      ).map((f) => ({
                        period: f.TimePeriod,
                        meanValue: f.MeanValue,
                        predictionIntervalLowerBound:
                          f.PredictionIntervalLowerBound,
                        predictionIntervalUpperBound:
                          f.PredictionIntervalUpperBound,
                      })),
                    }),
                  ),
                ),
              ),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError("Error getting cost forecast", error),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "get_cost_by_usage_type",
        "Break down AWS costs for a specific service by usage type. Use this to drill into high-spend services and understand what is driving the cost (e.g., instance types, storage volumes, data transfer). Returns the top 10 usage types by cost.",
        {
          service: z
            .string()
            .describe("The service name exactly as returned by get_cost_and_usage (e.g., 'Amazon Elastic Compute Cloud - Compute')"),
          startDate: z
            .string()
            .describe("Start date in YYYY-MM-DD format"),
          endDate: z.string().describe("End date in YYYY-MM-DD format"),
        },
        async (args) =>
          Effect.runPromise(
            awsCall("CostExplorer", "GetCostAndUsage", () =>
              costExplorer.send(
                new GetCostAndUsageCommand({
                  TimePeriod: {
                    Start: args.startDate,
                    End: args.endDate,
                  },
                  Granularity: "MONTHLY",
                  Metrics: ["UnblendedCost"],
                  Filter: {
                    Dimensions: {
                      Key: "SERVICE",
                      Values: [args.service],
                    },
                  },
                  GroupBy: [{ Type: "DIMENSION", Key: "USAGE_TYPE" }],
                }),
              ),
            ).pipe(
              Effect.map((response) => {
                // Aggregate costs across time periods by usage type
                const costs = new Map<string, number>();
                for (const result of response.ResultsByTime ?? []) {
                  for (const group of result.Groups ?? []) {
                    const usageType = group.Keys?.[0] ?? "Unknown";
                    const cost = parseFloat(group.Metrics?.UnblendedCost?.Amount ?? "0");
                    costs.set(usageType, (costs.get(usageType) ?? 0) + cost);
                  }
                }
                // Sort by cost descending, take top 10
                const sorted = [...costs.entries()]
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 10)
                  .map(([usageType, cost]) => ({
                    usageType,
                    cost: cost.toFixed(2),
                  }));
                return toolResponse({
                  service: args.service,
                  timePeriod: { start: args.startDate, end: args.endDate },
                  topUsageTypes: sorted,
                  totalUsageTypes: costs.size,
                });
              }),
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError(
                      "Error getting cost by usage type",
                      error,
                    ),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),

      tool(
        "get_cost_anomalies",
        "Detect cost anomalies using dual analysis: (1) trend anomalies comparing two consecutive periods, and (2) daily spike detection using statistical outliers. Returns structured results with configurable thresholds.",
        {
          periodDays: z
            .number()
            .default(30)
            .describe(
              "Length of each comparison period in days (default 30)",
            ),
          minAbsoluteChange: z
            .number()
            .default(DEFAULT_THRESHOLDS.minAbsoluteChange)
            .describe(
              "Minimum absolute dollar change to flag as anomaly (default $10)",
            ),
          percentChangeThreshold: z
            .number()
            .default(DEFAULT_THRESHOLDS.percentChangeThreshold)
            .describe(
              "Minimum percentage change for trend anomalies (default 50%)",
            ),
          dailySpikeStdDevs: z
            .number()
            .default(DEFAULT_THRESHOLDS.dailySpikeStdDevs)
            .describe(
              "Number of standard deviations for daily spike detection (default 2)",
            ),
        },
        async (args) =>
          Effect.runPromise(
            Effect.gen(function* () {
              const now = new Date();
              const currentPeriodEnd = formatDate(now);
              const currentPeriodStart = formatDate(daysAgo(args.periodDays));
              const previousPeriodStart = formatDate(
                daysAgo(args.periodDays * 2),
              );
              const dailyBaselineStart = formatDate(daysAgo(DAILY_BASELINE_DAYS));

              const thresholds: AnomalyThresholds = {
                minAbsoluteChange: args.minAbsoluteChange,
                percentChangeThreshold: args.percentChangeThreshold,
                dailySpikeStdDevs: args.dailySpikeStdDevs,
              };

              // Fetch all three datasets concurrently
              const [currentResponse, previousResponse, dailyResponse] =
                yield* Effect.all(
                  [
                    awsCall("CostExplorer", "GetCostAndUsage", () =>
                      costExplorer.send(
                        new GetCostAndUsageCommand({
                          TimePeriod: {
                            Start: currentPeriodStart,
                            End: currentPeriodEnd,
                          },
                          Granularity: "MONTHLY",
                          Metrics: ["UnblendedCost"],
                          GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }],
                        }),
                      ),
                    ),
                    awsCall("CostExplorer", "GetCostAndUsage", () =>
                      costExplorer.send(
                        new GetCostAndUsageCommand({
                          TimePeriod: {
                            Start: previousPeriodStart,
                            End: currentPeriodStart,
                          },
                          Granularity: "MONTHLY",
                          Metrics: ["UnblendedCost"],
                          GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }],
                        }),
                      ),
                    ),
                    awsCall("CostExplorer", "GetCostAndUsage", () =>
                      costExplorer.send(
                        new GetCostAndUsageCommand({
                          TimePeriod: {
                            Start: dailyBaselineStart,
                            End: currentPeriodEnd,
                          },
                          Granularity: "DAILY",
                          Metrics: ["UnblendedCost"],
                          GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }],
                        }),
                      ),
                    ),
                  ],
                  { concurrency: 3 },
                );

              // Aggregate period costs by service
              const currentCosts = aggregateCosts(currentResponse.ResultsByTime ?? []);
              const previousCosts = aggregateCosts(previousResponse.ResultsByTime ?? []);

              // Build daily cost entries from daily response
              const dailyCosts: DailyCostEntry[] = [];
              for (const result of dailyResponse.ResultsByTime ?? []) {
                const date = result.TimePeriod?.Start ?? "";
                for (const group of result.Groups ?? []) {
                  const service = group.Keys?.[0] ?? "Unknown";
                  const cost = parseFloat(
                    group.Metrics?.UnblendedCost?.Amount ?? "0",
                  );
                  dailyCosts.push({ service, date, cost });
                }
              }

              // Run both detection algorithms
              const trendAnomalies = detectTrendAnomalies(
                currentCosts,
                previousCosts,
                thresholds,
              );
              const dailySpikes = detectDailySpikes(
                dailyCosts,
                currentPeriodStart,
                thresholds,
              );

              return toolResponse({
                currentPeriod: {
                  start: currentPeriodStart,
                  end: currentPeriodEnd,
                },
                previousPeriod: {
                  start: previousPeriodStart,
                  end: currentPeriodStart,
                },
                dailyBaselinePeriod: {
                  start: dailyBaselineStart,
                  end: currentPeriodEnd,
                },
                thresholds,
                trendAnomalies,
                dailySpikes,
                summary: {
                  trendAnomalyCount: trendAnomalies.length,
                  dailySpikeCount: dailySpikes.length,
                },
              });
            }).pipe(
              Effect.catchAll((error) =>
                Effect.succeed(
                  toolError(
                    formatAwsError("Error detecting cost anomalies", error),
                  ),
                ),
              ),
            ),
          ),
        { annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
      ),
    ],
  });
}
