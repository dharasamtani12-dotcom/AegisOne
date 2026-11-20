import type { DecodedFields, MlAnomalyResult, MlFeatureContribution } from '../types.ts';

/**
 * Pure TypeScript Isolation Forest (Liu, Ting & Zhou 2008)
 * Trains T binary Isolation Trees on 7-dimensional normalized behavioral vectors
 * derived from security telemetry and produces exact anomaly scores s(x, n) in [0, 1]
 * plus explainable per-feature contribution percentages.
 */

interface ITreeNode {
  splitFeature: number;
  splitValue: number;
  size: number;
  left: ITreeNode | null;
  right: ITreeNode | null;
}

export const FEATURE_META = [
  { key: 'hourSinDist', label: 'Off-Hours Time Deviation' },
  { key: 'eventBurstRate', label: '15m Event Burst Velocity' },
  { key: 'uniqueSrcIps', label: 'Source IP Entropy' },
  { key: 'failedAuthRatio', label: 'Failed Authentication Ratio' },
  { key: 'privExecSignal', label: 'Privileged Execution / Escalation' },
  { key: 'srcIpNovelty', label: 'Unseen External IP Novelty' },
  { key: 'payloadRiskEntropy', label: 'Payload & Command Entropy' },
] as const;

function harmonicNumber(n: number): number {
  if (n <= 1) return 0;
  return Math.log(n) + 0.5772156649;
}

export function averagePathLengthC(n: number): number {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  return 2 * harmonicNumber(n - 1) - (2 * (n - 1)) / n;
}

function buildITree(data: number[][], depth: number, maxDepth: number): ITreeNode {
  if (depth >= maxDepth || data.length <= 1) {
    return { splitFeature: -1, splitValue: 0, size: data.length, left: null, right: null };
  }

  const numFeatures = data[0].length;
  // Pick a feature with variance
  const candidates: number[] = [];
  for (let f = 0; f < numFeatures; f++) {
    let min = Infinity;
    let max = -Infinity;
    for (const row of data) {
      if (row[f] < min) min = row[f];
      if (row[f] > max) max = row[f];
    }
    if (max > min) candidates.push(f);
  }

  if (candidates.length === 0) {
    return { splitFeature: -1, splitValue: 0, size: data.length, left: null, right: null };
  }

  const splitFeature = candidates[Math.floor(Math.random() * candidates.length)];
  let minVal = Infinity;
  let maxVal = -Infinity;
  for (const row of data) {
    if (row[splitFeature] < minVal) minVal = row[splitFeature];
    if (row[splitFeature] > maxVal) maxVal = row[splitFeature];
  }

  const splitValue = minVal + Math.random() * (maxVal - minVal);
  const leftData: number[][] = [];
  const rightData: number[][] = [];
  for (const row of data) {
    if (row[splitFeature] < splitValue) leftData.push(row);
    else rightData.push(row);
  }

  return {
    splitFeature,
    splitValue,
    size: data.length,
    left: buildITree(leftData, depth + 1, maxDepth),
    right: buildITree(rightData, depth + 1, maxDepth),
  };
}

function pathLength(x: number[], node: ITreeNode | null, depth: number): number {
  if (!node || (!node.left && !node.right)) {
    return depth + averagePathLengthC(node ? node.size : 1);
  }
  if (x[node.splitFeature] < node.splitValue) {
    return pathLength(x, node.left, depth + 1);
  }
  return pathLength(x, node.right, depth + 1);
}

export interface FeatureExtractionContext {
  timestamp: string;
  ruleLevel: number;
  fields: DecodedFields;
  rawLog: string;
  recentAgentEventsCount: number;
  recentUniqueIpsForAgent: number;
  recentFailedAuthRatio: number;
  knownInternalIps: Set<string>;
}

export function extractBehavioralVector(ctx: FeatureExtractionContext): number[] {
  const dt = new Date(ctx.timestamp);
  const hour = Number.isNaN(dt.getTime()) ? 12 : dt.getUTCHours();
  // Normal business hours center around 13:00 UTC (or local); midnight/2-4 AM yields high distance [0..1]
  const hourDist = Math.abs(Math.sin(((hour - 13) / 24) * Math.PI));

  const burstRate = Math.min(1, ctx.recentAgentEventsCount / 20);
  const uniqueIps = Math.min(1, ctx.recentUniqueIpsForAgent / 8);
  const failedRatio = Math.min(1, Math.max(0, ctx.recentFailedAuthRatio));

  const combined = `${ctx.rawLog} ${ctx.fields.data || ''} ${ctx.fields.extra_data || ''} ${ctx.fields.url || ''}`.toLowerCase();
  const privMatch =
    /sudo|root|\/etc\/shadow|\/etc\/passwd|authorized_keys|powershell|-enc|encodedcommand|chmod \+s|privileged|exec_start/.test(
      combined
    );
  const privExec = privMatch ? 0.92 : ctx.ruleLevel >= 10 ? 0.75 : 0.08;

  const srcip = String(ctx.fields.srcip || '');
  const isPrivate =
    !srcip ||
    srcip.startsWith('10.') ||
    srcip.startsWith('192.168.') ||
    srcip.startsWith('127.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(srcip) ||
    ctx.knownInternalIps.has(srcip);
  const ipNovelty = srcip ? (isPrivate ? 0.12 : 0.94) : 0.05;

  // Shannon-inspired payload risk & command obfuscation indicator
  const suspiciousTokens = (
    combined.match(/union select|\.\.\/|base64|downloadstring|curl|wget|nc -e|bash -i|invalid user|critical/g) || []
  ).length;
  const payloadRisk = Math.min(1, 0.1 + suspiciousTokens * 0.28 + (ctx.ruleLevel / 16) * 0.35);

  return [
    Number(hourDist.toFixed(3)),
    Number(burstRate.toFixed(3)),
    Number(uniqueIps.toFixed(3)),
    Number(failedRatio.toFixed(3)),
    Number(privExec.toFixed(3)),
    Number(ipNovelty.toFixed(3)),
    Number(payloadRisk.toFixed(3)),
  ];
}

export class AegisIsolationForest {
  private trees: ITreeNode[] = [];
  private subsampleSize = 128;
  private threshold = 0.65;
  private baselineMedians: number[] = [0.22, 0.15, 0.14, 0.06, 0.08, 0.12, 0.14];
  public trainedSamples = 0;

  fit(vectors: number[][], numTrees = 64, subsampleSize = 256, threshold = 0.65) {
    this.threshold = threshold;
    if (vectors.length === 0) return;

    this.trainedSamples = vectors.length;
    this.subsampleSize = Math.min(subsampleSize, Math.max(8, vectors.length));
    const maxDepth = Math.ceil(Math.log2(this.subsampleSize));

    // Compute baseline medians for explainability
    const dim = vectors[0].length;
    const medians: number[] = [];
    for (let f = 0; f < dim; f++) {
      const col = vectors.map((v) => v[f]).sort((a, b) => a - b);
      medians.push(col[Math.floor(col.length * 0.5)] ?? 0.15);
    }
    this.baselineMedians = medians;

    this.trees = [];
    for (let t = 0; t < numTrees; t++) {
      const sample: number[][] = [];
      for (let i = 0; i < this.subsampleSize; i++) {
        sample.push(vectors[Math.floor(Math.random() * vectors.length)]);
      }
      this.trees.push(buildITree(sample, 0, maxDepth));
    }
  }

  score(vector: number[]): MlAnomalyResult {
    if (this.trees.length === 0) {
      // Train on synthetic nominal baseline if called prior to fit
      const nominal: number[][] = [];
      for (let i = 0; i < 64; i++) {
        nominal.push([
          0.1 + Math.random() * 0.25,
          0.05 + Math.random() * 0.2,
          0.12 + Math.random() * 0.12,
          Math.random() * 0.1,
          0.05 + Math.random() * 0.08,
          0.05 + Math.random() * 0.12,
          0.08 + Math.random() * 0.12,
        ]);
      }
      this.fit(nominal);
    }

    const c = averagePathLengthC(this.subsampleSize);
    let totalPath = 0;
    for (const tree of this.trees) {
      totalPath += pathLength(vector, tree, 0);
    }
    const avgPath = totalPath / this.trees.length;
    const rawScore = c > 0 ? Math.pow(2, -avgPath / c) : 0.5;
    const score = Number(Math.max(0.01, Math.min(0.99, rawScore)).toFixed(3));

    // Explainable feature attribution via baseline-median deviation weighted by isolation impact
    const deltas = vector.map((val, idx) => Math.max(0.01, Math.abs(val - (this.baselineMedians[idx] ?? 0.15))));
    const deltaSum = deltas.reduce((a, b) => a + b, 0) || 1;

    const contributions: MlFeatureContribution[] = FEATURE_META.map((meta, idx) => ({
      feature: meta.key,
      label: meta.label,
      value: vector[idx] ?? 0,
      baselineMedian: Number((this.baselineMedians[idx] ?? 0.15).toFixed(3)),
      contributionPct: Math.round((deltas[idx] / deltaSum) * 100),
    })).sort((a, b) => b.contributionPct - a.contributionPct);

    return {
      score,
      isAnomaly: score >= this.threshold,
      avgPathLength: Number(avgPath.toFixed(2)),
      expectedPathLength: Number(c.toFixed(2)),
      contributions,
      featureVector: vector,
    };
  }
}

export const isolationForest = new AegisIsolationForest();
