import { describe, it, expect, beforeEach } from "vitest";
import { mockClient } from "aws-sdk-client-mock";
import {
  CostExplorerClient,
  GetCostAndUsageCommand,
  GetCostForecastCommand,
} from "@aws-sdk/client-cost-explorer";
import { createCostToolsServer } from "../../src/tools/cost-tools.js";

const ceMock = mockClient(CostExplorerClient);

describe("Cost Tools - AWS API Mocking", () => {
  beforeEach(() => {
    ceMock.reset();
  });

  it("GetCostAndUsageCommand returns service-level costs", async () => {
    ceMock.on(GetCostAndUsageCommand).resolves({
      ResultsByTime: [
        {
          TimePeriod: { Start: "2026-02-01", End: "2026-03-01" },
          Groups: [
            {
              Keys: ["Amazon EC2"],
              Metrics: {
                BlendedCost: { Amount: "1500.00", Unit: "USD" },
                UnblendedCost: { Amount: "1450.00", Unit: "USD" },
              },
            },
            {
              Keys: ["Amazon S3"],
              Metrics: {
                BlendedCost: { Amount: "200.00", Unit: "USD" },
                UnblendedCost: { Amount: "195.00", Unit: "USD" },
              },
            },
          ],
        },
      ],
    });

    const client = new CostExplorerClient({ region: "us-east-1" });
    const response = await client.send(
      new GetCostAndUsageCommand({
        TimePeriod: { Start: "2026-02-01", End: "2026-03-01" },
        Granularity: "MONTHLY",
        Metrics: ["BlendedCost"],
        GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }],
      }),
    );

    expect(response.ResultsByTime).toHaveLength(1);
    expect(response.ResultsByTime![0].Groups).toHaveLength(2);
    expect(response.ResultsByTime![0].Groups![0].Keys![0]).toBe("Amazon EC2");
  });

  it("GetCostForecastCommand returns forecast", async () => {
    ceMock.on(GetCostForecastCommand).resolves({
      Total: { Amount: "5000.00", Unit: "USD" },
      ForecastResultsByTime: [
        {
          TimePeriod: { Start: "2026-03-07", End: "2026-04-07" },
          MeanValue: "5000.00",
          PredictionIntervalLowerBound: "4200.00",
          PredictionIntervalUpperBound: "5800.00",
        },
      ],
    });

    const client = new CostExplorerClient({ region: "us-east-1" });
    const response = await client.send(
      new GetCostForecastCommand({
        TimePeriod: { Start: "2026-03-07", End: "2026-04-07" },
        Metric: "UNBLENDED_COST",
        Granularity: "MONTHLY",
      }),
    );

    expect(response.Total?.Amount).toBe("5000.00");
    expect(response.ForecastResultsByTime).toHaveLength(1);
  });

  it("handles DataUnavailableException gracefully", async () => {
    ceMock
      .on(GetCostAndUsageCommand)
      .rejects(
        new Error("DataUnavailableException: Cost Explorer is not enabled"),
      );

    const client = new CostExplorerClient({ region: "us-east-1" });
    await expect(
      client.send(
        new GetCostAndUsageCommand({
          TimePeriod: { Start: "2026-02-01", End: "2026-03-01" },
          Granularity: "MONTHLY",
          Metrics: ["BlendedCost"],
        }),
      ),
    ).rejects.toThrow("DataUnavailableException");
  });

  it("createCostToolsServer returns a valid MCP server config", () => {
    const server = createCostToolsServer({ region: "us-east-1" });
    expect(server).toBeDefined();
  });
});
