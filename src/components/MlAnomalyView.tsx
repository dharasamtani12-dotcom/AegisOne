import React, { useEffect, useState } from 'react';
import { Bar, Scatter } from 'react-chartjs-2';
import { Cpu, RefreshCw } from 'lucide-react';
import '../lib/charts';
import { CHART_GRID_COLOR, CHART_TICK_COLOR } from '../lib/charts';
import { apiFetch } from '../lib/api';
import type { AegisAlert, RbacRole } from '../types/aegis';
import { SeverityLabel, VChip, formatTimeShort } from './SeverityTag';

interface MlStatsResponse {
  algorithm: string;
  numTrees: number;
  subsampleSize: number;
  threshold: number;
  trainedSamples: number;
  totalEvaluated: number;
  anomaliesCount: number;
  scatterPoints: Array<{
    id: string;
    ruleLevel: number;
    mlScore: number;
    isAnomaly: boolean;
    agent: string;
    description: string;
    topDriver: string;
  }>;
  featureComparison: {
    nominal: Array<{ label: string; value: number }>;
    anomalies: Array<{ label: string; value: number }>;
  };
  topAnomalies: AegisAlert[];
}

export function MlAnomalyView({
  role,
  onSelectAlert,
  onMutated,
}: {
  role: RbacRole;
  onSelectAlert: (alert: AegisAlert) => void;
  onMutated: () => void;
}) {
  const [stats, setStats] = useState<MlStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [retraining, setRetraining] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const res = await apiFetch<MlStatsResponse>('/api/v1/ml/stats');
      setStats(res);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleRetrain = async () => {
    setRetraining(true);
    setMsg(null);
    try {
      const res = await apiFetch<{ trainedSamples: number }>('/api/v1/ml/retrain', { method: 'POST' });
      setMsg(`Retrained 64 Isolation Trees on ${res.trainedSamples} behavioral telemetry vectors.`);
      await load();
      onMutated();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Retrain failed');
    } finally {
      setRetraining(false);
    }
  };

  if (loading || !stats) {
    return (
      <div className="p-8 obsidian-card text-center text-xs font-mono text-gray-400">
        LOADING ISOLATION FOREST TELEMETRY...
      </div>
    );
  }

  const scatterData = {
    datasets: [
      {
        label: 'Nominal Baseline',
        data: stats.scatterPoints.filter((p) => !p.isAnomaly).map((p) => ({ x: p.ruleLevel, y: p.mlScore })),
        backgroundColor: 'rgba(255, 224, 224, 0.35)',
        borderColor: 'rgba(255, 255, 255, 0.4)',
        borderWidth: 1,
        pointRadius: 5,
      },
      {
        label: 'Flagged Anomaly (>= Threshold)',
        data: stats.scatterPoints.filter((p) => p.isAnomaly).map((p) => ({ x: p.ruleLevel, y: p.mlScore })),
        backgroundColor: '#FF4500',
        borderColor: '#ffe0e0',
        borderWidth: 1.5,
        pointRadius: 6.5,
      },
    ],
  };

  const featureBarData = {
    labels: stats.featureComparison.nominal.map((f) => f.label),
    datasets: [
      {
        label: 'Nominal Mean',
        data: stats.featureComparison.nominal.map((f) => f.value),
        backgroundColor: 'rgba(255, 255, 255, 0.16)',
        borderColor: 'rgba(255, 255, 255, 0.35)',
        borderWidth: 1,
      },
      {
        label: 'Anomaly Mean',
        data: stats.featureComparison.anomalies.map((f) => f.value),
        backgroundColor: '#FF4500',
        borderColor: '#ffe0e0',
        borderWidth: 1,
      },
    ],
  };

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
            <Cpu className="w-5 h-5 text-[#FF4500]" />
            <span>Behavioral Anomaly Detection — {stats.algorithm}</span>
          </h2>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <VChip status="info" label={`${stats.numTrees} TREES`} />
            <VChip status="warn" label={`ψ=${stats.subsampleSize}`} />
            <VChip status="pass" label={`THRESHOLD ${stats.threshold}`} />
            <VChip status="info" label={`${stats.trainedSamples} VECTORS`} />
          </div>
        </div>

        <button
          onClick={handleRetrain}
          disabled={retraining || role === 'auditor'}
          className="btn-pill-primary inline-flex items-center gap-1.5 px-5 py-2.5 text-xs disabled:opacity-40 whitespace-nowrap"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${retraining ? 'animate-spin' : ''}`} />
          <span>{retraining ? 'Retraining...' : 'Retrain Isolation Forest'}</span>
        </button>
      </section>

      {msg && (
        <div className="p-3.5 rounded-2xl bg-[#111111] border border-[#FF4500]/50 text-xs font-mono text-[#ffe0e0]">
          {msg}
        </div>
      )}

      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-6 obsidian-card p-6">
          <h3 className="font-serif-display text-lg font-medium text-white">
            Rule Severity (0–16) vs Isolation Score
          </h3>
          <p className="text-xs font-mono text-gray-400 mt-1 mb-4">
            Detects subtle off-hours or novel-IP anomalies even when deterministic rule severity is low
          </p>
          <div className="h-64">
            <Scatter
              data={scatterData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'bottom',
                    labels: { color: CHART_TICK_COLOR, boxWidth: 10, font: { size: 11, family: 'Geist Mono' } },
                  },
                },
                scales: {
                  x: {
                    title: { display: true, text: 'Deterministic Rule Level (0–16)', color: CHART_TICK_COLOR },
                    min: 0,
                    max: 16,
                    grid: { color: CHART_GRID_COLOR },
                    ticks: { color: CHART_TICK_COLOR },
                  },
                  y: {
                    title: { display: true, text: 'Isolation Score s(x)', color: CHART_TICK_COLOR },
                    min: 0,
                    max: 1,
                    grid: { color: CHART_GRID_COLOR },
                    ticks: { color: CHART_TICK_COLOR },
                  },
                },
              }}
            />
          </div>
        </div>

        <div className="lg:col-span-6 obsidian-card p-6">
          <h3 className="font-serif-display text-lg font-medium text-white">
            7-Dimensional Feature Drift (Nominal vs Anomaly)
          </h3>
          <p className="text-xs font-mono text-gray-400 mt-1 mb-4">Normalized behavioral baseline comparison</p>
          <div className="h-64">
            <Bar
              data={featureBarData}
              options={{
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'bottom',
                    labels: { color: CHART_TICK_COLOR, boxWidth: 10, font: { size: 11, family: 'Geist Mono' } },
                  },
                },
                scales: {
                  x: { min: 0, max: 1, grid: { color: CHART_GRID_COLOR }, ticks: { color: CHART_TICK_COLOR } },
                  y: { grid: { color: CHART_GRID_COLOR }, ticks: { color: CHART_TICK_COLOR, font: { size: 11 } } },
                },
              }}
            />
          </div>
        </div>
      </section>

      <section className="obsidian-card overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-serif-display text-lg font-medium text-white">
            Explainable Behavioral Outliers ({stats.anomaliesCount} detected)
          </h3>
          <span className="text-xs font-mono text-gray-400">Click row to inspect Isolation Tree path attribution</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-[#050505] text-gray-400 border-b border-white/10">
              <tr>
                <th className="px-4 py-3 font-medium">TIMESTAMP</th>
                <th className="px-4 py-3 font-medium">AGENT</th>
                <th className="px-4 py-3 font-medium">SEVERITY</th>
                <th className="px-4 py-3 font-medium">PRIMARY BEHAVIORAL DRIVER</th>
                <th className="px-4 py-3 font-medium text-right">AVG PATH E(h(x))</th>
                <th className="px-4 py-3 font-medium text-right">ANOMALY SCORE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {stats.topAnomalies.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => onSelectAlert(a)}
                  className="hover:bg-white/[0.03] cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 text-gray-400 whitespace-nowrap tabular-nums">
                    {formatTimeShort(a.timestamp)}
                  </td>
                  <td className="px-4 py-3 text-white">{a.agent.name}</td>
                  <td className="px-4 py-3">
                    <SeverityLabel level={a.rule.level} />
                  </td>
                  <td className="px-4 py-3 text-gray-200">
                    {a.ml.contributions[0]?.label} ({a.ml.contributions[0]?.contributionPct}%)
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums text-gray-400">
                    {a.ml.avgPathLength} / {a.ml.expectedPathLength}
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums text-[#FF4500]">
                    {a.ml.score.toFixed(3)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
