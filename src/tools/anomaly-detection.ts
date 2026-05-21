/**
 * Pure, testable anomaly detection logic for cost analysis.
 * Extracted from the get_cost_anomalies tool handler.
 */

export interface AnomalyThresholds {
  /** Minimum absolute dollar change to flag (default $10) */
  minAbsoluteChange: number;
  /** Minimum percentage change for trend anomalies (default 50%) */
  percentChangeThreshold: number;
  /** Number of standard deviations for daily spike detection (default 2) */
  dailySpikeStdDevs: number;
}

export const DEFAULT_THRESHOLDS: AnomalyThresholds = {
  minAbsoluteChange: 10,
  percentChangeThreshold: 50,
  dailySpikeStdDevs: 2,
};

export interface TrendAnomaly {
  service: string;
  previousPeriod: number;
  currentPeriod: number;
  percentChange: number;
  absoluteChange: number;
}

export interface DailySpike {
  service: string;
  date: string;
  dailyCost: number;
  dailyMean: number;
  dailyStdDev: number;
  deviations: number;
}

export interface AnomalyResult {
  thresholds: AnomalyThresholds;
  trendAnomalies: TrendAnomaly[];
  dailySpikes: DailySpike[];
  summary: {
    trendAnomalyCount: number;
    dailySpikeCount: number;
  };
}

/**
 * Detect trend anomalies by comparing costs across two consecutive periods.
 * Flags services where BOTH percentage change and absolute dollar change
 * exceed the configured thresholds. Excludes zero-to-zero changes.
 */
export function detectTrendAnomalies(
  currentCosts: Map<string, number>,
  previousCosts: Map<string, number>,
  thresholds: Pick<AnomalyThresholds, "minAbsoluteChange" | "percentChangeThreshold">,
): TrendAnomaly[] {
  const allServices = new Set([
    ...currentCosts.keys(),
    ...previousCosts.keys(),
  ]);

  const anomalies: TrendAnomaly[] = [];

  for (const service of allServices) {
    const current = currentCosts.get(service) ?? 0;
    const previous = previousCosts.get(service) ?? 0;

    // Skip zero-to-zero — no meaningful change
    if (current === 0 && previous === 0) continue;

    const absoluteChange = current - previous;
    const percentChange =
      previous > 0
        ? ((current - previous) / previous) * 100
        : current > 0
          ? 100
          : 0;

    // Flag only when BOTH thresholds are exceeded
    if (
      Math.abs(percentChange) > thresholds.percentChangeThreshold &&
      Math.abs(absoluteChange) > thresholds.minAbsoluteChange
    ) {
      anomalies.push({
        service,
        previousPeriod: round2(previous),
        currentPeriod: round2(current),
        percentChange: round1(percentChange),
        absoluteChange: round2(absoluteChange),
      });
    }
  }

  // Sort by largest absolute change first
  anomalies.sort((a, b) => Math.abs(b.absoluteChange) - Math.abs(a.absoluteChange));

  return anomalies;
}

/** Daily cost entry for a single service on a single day. */
export interface DailyCostEntry {
  service: string;
  date: string;
  cost: number;
}

/**
 * Detect daily cost spikes using statistical outlier analysis.
 *
 * Uses the full dataset (60 days) to compute per-service mean and stddev,
 * but only flags spikes within the recent window (last 30 days).
 */
export function detectDailySpikes(
  dailyCosts: DailyCostEntry[],
  recentWindowStart: string,
  thresholds: Pick<AnomalyThresholds, "minAbsoluteChange" | "dailySpikeStdDevs">,
): DailySpike[] {
  // Group by service
  const byService = new Map<string, DailyCostEntry[]>();
  for (const entry of dailyCosts) {
    const list = byService.get(entry.service);
    if (list) {
      list.push(entry);
    } else {
      byService.set(entry.service, [entry]);
    }
  }

  const spikes: DailySpike[] = [];

  for (const [service, entries] of byService) {
    const costs = entries.map((e) => e.cost);
    const mean = computeMean(costs);
    const stdDev = computeStdDev(costs, mean);

    // Skip services with zero or negligible variance
    if (stdDev < 0.01) continue;

    const spikeThreshold = mean + thresholds.dailySpikeStdDevs * stdDev;

    for (const entry of entries) {
      // Only flag days in the recent window
      if (entry.date < recentWindowStart) continue;

      const deviation = entry.cost - mean;
      if (
        entry.cost > spikeThreshold &&
        deviation > thresholds.minAbsoluteChange
      ) {
        spikes.push({
          service,
          date: entry.date,
          dailyCost: round2(entry.cost),
          dailyMean: round2(mean),
          dailyStdDev: round2(stdDev),
          deviations: round1((entry.cost - mean) / stdDev),
        });
      }
    }
  }

  // Sort by deviations descending
  spikes.sort((a, b) => b.deviations - a.deviations);

  return spikes;
}

export function computeMean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}

export function computeStdDev(values: number[], mean: number): number {
  if (values.length < 2) return 0;
  const variance =
    values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
