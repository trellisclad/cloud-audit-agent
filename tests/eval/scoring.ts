export interface ExpectedFinding {
  id: string;
  domain: string;
  severity: string;
  keywords: string[];
}

export interface EvalResult {
  /** % of expected findings detected (0-1) */
  findingCoverage: number;
  /** % of reported findings that are false positives (0-1) */
  falsePositiveRate: number;
  /** % of matched findings with correct severity (0-1) */
  severityAccuracy: number;
  /** Every detected finding has a recommendation */
  hasRecommendations: boolean;
  /** Weighted composite score (0-1) */
  overallScore: number;
  /** Details of what was matched/missed */
  details: {
    matched: string[];
    missed: string[];
    falsePositives: number;
    totalReported: number;
  };
}

/**
 * Score the agent's markdown report against expected findings.
 *
 * Matching works by checking if the report text contains at least 2
 * of the expected keywords for each finding (case-insensitive).
 */
export function scoreReport(
  report: string,
  expectedFindings: ExpectedFinding[],
): EvalResult {
  const reportLower = report.toLowerCase();

  // Check which expected findings are present in the report
  const matched: string[] = [];
  const missed: string[] = [];

  for (const expected of expectedFindings) {
    const keywordMatches = expected.keywords.filter((kw) =>
      reportLower.includes(kw.toLowerCase()),
    );
    // Require at least 2 keyword matches to count as detected
    if (keywordMatches.length >= 2) {
      matched.push(expected.id);
    } else {
      missed.push(expected.id);
    }
  }

  const findingCoverage =
    expectedFindings.length > 0 ? matched.length / expectedFindings.length : 1;

  // Count reported findings in the report (bullet points under severity headers)
  const findingSections = report.match(
    /###\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)\n([\s\S]*?)(?=###|## |$)/g,
  );
  let totalReported = 0;
  if (findingSections) {
    for (const section of findingSections) {
      // Count bullet points with bold text (actual findings)
      const items = section.match(/^[-*\d.]+\s+\*\*/gm);
      if (items) {
        // Filter out "No ... findings" lines
        const realFindings = items.filter(
          (item) => !item.toLowerCase().includes("no "),
        );
        totalReported += realFindings.length;
      }
    }
  }

  const falsePositives = Math.max(0, totalReported - matched.length);
  const falsePositiveRate =
    totalReported > 0 ? falsePositives / totalReported : 0;

  // Check severity accuracy for matched findings
  let correctSeverity = 0;
  for (const id of matched) {
    const expected = expectedFindings.find((f) => f.id === id);
    if (expected && reportLower.includes(expected.severity.toLowerCase())) {
      correctSeverity++;
    }
  }
  const severityAccuracy = matched.length > 0 ? correctSeverity / matched.length : 1;

  // Check that recommendations exist
  const hasRecommendations =
    reportLower.includes("recommendation") ||
    reportLower.includes("remediation") ||
    reportLower.includes("should") ||
    reportLower.includes("fix");

  // Weighted overall score
  const overallScore =
    findingCoverage * 0.4 +
    (1 - falsePositiveRate) * 0.3 +
    severityAccuracy * 0.2 +
    (hasRecommendations ? 1 : 0) * 0.1;

  return {
    findingCoverage,
    falsePositiveRate,
    severityAccuracy,
    hasRecommendations,
    overallScore,
    details: {
      matched,
      missed,
      falsePositives,
      totalReported,
    },
  };
}
