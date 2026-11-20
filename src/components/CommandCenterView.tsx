import React, { useEffect, useMemo, useState } from 'react';
import { Bar } from 'react-chartjs-2';
import { ArrowRight, ShieldCheck, Sparkles } from 'lucide-react';
import '../lib/charts';
import { CHART_GRID_COLOR, CHART_TICK_COLOR } from '../lib/charts';
import type { AegisAlert, IncidentRecord, NavSectionId, OverviewData } from '../types/aegis';
import {
  IncidentSeverityLabel,
  IncidentStatusLabel,
  TimelineProgressBar,
  VChip,
  formatTimeShort,
} from './SeverityTag';

interface CommandCenterProps {
  data: OverviewData | null;
  loading: boolean;
  onNavigate: (tab: NavSectionId) => void;
  onSelectAlert: (alert: AegisAlert) => void;
  onInvestigateIncident: (inc: IncidentRecord) => void;
}

export function CommandCenterView({
  data,
  loading,
  onNavigate,
  onSelectAlert,
  onInvestigateIncident,
}: CommandCenterProps) {
  const [selectedStreamId, setSelectedStreamId] = useState<string | null>(null);
  const [clockText, setClockText] = useState('');

  useEffect(() => {
    const update = () => {
      const now = new Date();
      setClockText(
        now.toLocaleTimeString(undefined, {
          hour: '2-digit',
          minute: '2-digit',
          hour12: true,
        })
      );
    };
    update();
    const id = setInterval(update, 30_000);
    return () => clearInterval(id);
  }, []);

  const streamAlerts = useMemo(() => data?.recentAlerts || [], [data]);
  const focusedAlert = useMemo(
    () => streamAlerts.find((a) => a.id === selectedStreamId) || streamAlerts[0] || null,
    [streamAlerts, selectedStreamId]
  );

  const streamMetrics = useMemo(() => {
    if (streamAlerts.length === 0) return { minMs: 0, spanMs: 1 };
    const times = streamAlerts.map((a) => Date.parse(a.timestamp) || Date.now());
    const minMs = Math.min(...times);
    const maxMs = Math.max(...times);
    return { minMs, spanMs: Math.max(60_000, maxMs - minMs) };
  }, [streamAlerts]);

  if (loading && !data) {
    return (
      <div className="space-y-8 animate-pulse">
        <div className="h-[72vh] rounded-3xl bg-[#111111] border border-white/10" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-5xl mx-auto">
          <div className="h-80 rounded-3xl bg-[#111111] border border-white/10" />
          <div className="h-80 rounded-3xl bg-[#111111] border border-white/10" />
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-10 obsidian-card text-center text-xs font-mono text-gray-400">
        No telemetry summary available. Upload logs or trigger a scenario from Ingestion.
      </div>
    );
  }

  const { healthScore: hs, counts, timeline, recentIncidents } = data;

  const timelineChartData = {
    labels: timeline.map((t) => t.label),
    datasets: [
      {
        label: 'Total Telemetry',
        data: timeline.map((t) => t.total),
        backgroundColor: 'rgba(255, 255, 255, 0.14)',
        borderColor: 'rgba(255, 255, 255, 0.35)',
        borderWidth: 1,
      },
      {
        label: 'High / Critical (L8–16)',
        data: timeline.map((t) => t.highCritical),
        backgroundColor: '#ffe0e0',
        borderColor: '#ffffff',
        borderWidth: 1,
      },
      {
        label: 'Isolation Forest Anomalies',
        data: timeline.map((t) => t.anomalies),
        backgroundColor: '#FF4500',
        borderColor: '#FF4500',
        borderWidth: 1,
      },
    ],
  };

  return (
    <div className="space-y-24">
      {/* 1. Atmospheric Crimson-to-Obsidian Hero Section */}
      <section className="relative min-h-[78vh] rounded-3xl overflow-hidden flex flex-col items-center justify-center text-center px-6 py-20 border border-white/10 bg-[#050505]">
        {/* Deep Atmospheric Vermilion-Crimson Gradient & Topographic Contour Atmosphere */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'radial-gradient(ellipse 95% 75% at 50% 8%, rgba(255, 69, 0, 0.42) 0%, rgba(112, 16, 8, 0.48) 38%, rgba(28, 6, 6, 0.72) 68%, #050505 100%)',
          }}
        />
        <svg
          className="absolute inset-0 w-full h-full opacity-25 pointer-events-none"
          viewBox="0 0 1200 700"
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          <path
            d="M0,180 C240,110 420,240 650,170 C880,100 1040,210 1200,150 L1200,700 L0,700 Z"
            fill="rgba(255,69,0,0.12)"
          />
          <path
            d="M0,310 C280,240 460,370 720,290 C940,220 1080,320 1200,270 L1200,700 L0,700 Z"
            fill="rgba(160,25,10,0.14)"
          />
          <path
            d="M0,470 C300,410 520,510 780,450 C1000,400 1100,480 1200,440 L1200,700 L0,700 Z"
            fill="rgba(5,5,5,0.65)"
          />
        </svg>
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-[#050505] pointer-events-none" />

        <div className="relative z-10 max-w-4xl mx-auto">
          <h2
            className="headline-editorial text-5xl sm:text-6xl md:text-7xl text-[#ffe0e0]"
            style={{ textShadow: '0 0 18px rgba(255,255,255,0.45)' }}
          >
            AegisOne.
            <br />
            <span className="italic font-light text-[#ffe0e0]">Explainable SIEM &amp; XDR.</span>
          </h2>

          <p className="mt-6 text-base md:text-lg text-[#ffe0e0]/85 max-w-xl mx-auto font-light leading-relaxed">
            Turning raw endpoint telemetry into prioritized, actionable decisions through two-phase XML decoding,
            0–16 deterministic rules, and Isolation Forest behavioral scoring.
          </p>

          <div className="mt-10 flex flex-wrap items-center justify-center gap-4">
            <button
              onClick={() => onNavigate('discover')}
              className="btn-pill-glass px-7 py-2.5 text-xs md:text-sm uppercase tracking-widest"
            >
              <span>Enter AQL Explorer</span>
            </button>
            <button
              onClick={() => onNavigate('incidents')}
              className="btn-pill-primary px-7 py-2.5 text-xs md:text-sm"
            >
              <span>Triage {counts.openIncidents} Incidents</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="mt-12 flex items-center justify-center gap-4 text-[11px] text-white/50 uppercase tracking-widest font-mono">
            <span>{clockText || 'LIVE'}</span>
            <span className="w-px h-3 bg-white/20" />
            <span>HEALTH {hs.healthScore}/100</span>
            <span className="w-px h-3 bg-white/20" />
            <span>MEDICAPS SOC</span>
          </div>
        </div>
      </section>

      {/* 2. Editorial Posture Statement & Fleet Metrics Strip */}
      <section className="max-w-5xl mx-auto text-center space-y-14 px-2">
        <div className="space-y-6">
          <h3 className="headline-editorial text-3xl sm:text-5xl text-white/95">
            Signal over noise across every monitored host.
          </h3>
          <p className="text-lg md:text-xl text-gray-500 font-light max-w-2xl mx-auto leading-relaxed">
            Every SSH attempt, Sysmon process tree, Docker container action, and file integrity hash is decoded,
            scored, and correlated in real time.
          </p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 pt-4">
          <button onClick={() => onNavigate('incidents')} className="text-center group">
            <div className="text-3xl md:text-4xl font-serif-display text-white group-hover:text-[#FF4500] transition-colors tabular-nums">
              {hs.healthScore}/100
            </div>
            <div className="mt-1.5 text-xs font-mono text-gray-500 uppercase tracking-widest">
              Health Score ({hs.grade})
            </div>
          </button>

          <button onClick={() => onNavigate('discover')} className="text-center group">
            <div className="text-3xl md:text-4xl font-serif-display text-white group-hover:text-[#FF4500] transition-colors tabular-nums">
              {counts.totalAlerts}
            </div>
            <div className="mt-1.5 text-xs font-mono text-gray-500 uppercase tracking-widest">
              Indexed Alerts
            </div>
          </button>

          <button onClick={() => onNavigate('ml')} className="text-center group">
            <div className="text-3xl md:text-4xl font-serif-display text-[#FF4500] tabular-nums">
              {counts.anomaliesDetected}
            </div>
            <div className="mt-1.5 text-xs font-mono text-gray-500 uppercase tracking-widest">
              ML Anomalies ({hs.metrics.anomalyRatePct}%)
            </div>
          </button>

          <button onClick={() => onNavigate('agents')} className="text-center group">
            <div className="text-3xl md:text-4xl font-serif-display text-white group-hover:text-[#FF4500] transition-colors tabular-nums">
              {counts.activeAgents}/{counts.totalAgents}
            </div>
            <div className="mt-1.5 text-xs font-mono text-gray-500 uppercase tracking-widest">
              Active Agents
            </div>
          </button>
        </div>
      </section>

      {/* 3. Signature Dual-Card Showcase (Vermilion #FF4500 + Obsidian #111111) with Dot-Matrix Backdrop */}
      <section className="relative py-12">
        <div className="absolute inset-0 dot-matrix-bg opacity-35 pointer-events-none" />
        <div className="relative z-10 max-w-5xl mx-auto">
          <h3 className="headline-editorial text-4xl sm:text-6xl text-center text-white mb-16">
            Define your
            <br />
            <span className="italic font-light text-[#ffe0e0]">defense posture</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
            {/* Card 01: Vermilion-Orange Signature Card */}
            <div
              onClick={() => onNavigate('discover')}
              className="bg-[#FF4500] rounded-3xl p-8 md:p-11 flex flex-col justify-between min-h-[380px] shadow-2xl hover:shadow-[0_20px_50px_rgba(255,69,0,0.3)] transition-all duration-300 group cursor-pointer"
            >
              <div className="flex justify-between items-start">
                <div className="w-12 h-12 rounded-full bg-black/15 flex items-center justify-center group-hover:rotate-12 transition-transform duration-300">
                  <ShieldCheck className="w-5 h-5 text-black" />
                </div>
                <span className="text-black font-mono text-xs border border-black/25 px-3 py-1 rounded-full">01</span>
              </div>

              <div className="my-8">
                <h4 className="font-serif-display text-4xl md:text-5xl text-black leading-none tracking-tight">
                  Deterministic
                  <br />
                  Detection
                </h4>
                <p className="mt-4 text-black/80 text-base leading-snug">
                  22 XML two-phase decoders and 23 stateful 0–16 rules with MITRE ATT&amp;CK mapping across{' '}
                  <strong className="font-mono">{counts.totalAlerts}</strong> live alerts.
                </p>
              </div>

              <div className="pt-4 border-t border-black/15 flex items-center justify-between text-xs font-mono text-black/80">
                <span>OPEN AQL &amp; SANDBOX</span>
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </div>
            </div>

            {/* Card 02: Obsidian Elevated Card */}
            <div
              onClick={() => onNavigate('ml')}
              className="bg-[#111111] border border-white/10 hover:border-[#FF4500]/60 rounded-3xl p-8 md:p-11 md:mt-16 flex flex-col justify-between min-h-[380px] shadow-2xl transition-all duration-300 group cursor-pointer"
            >
              <div className="flex justify-between items-start">
                <div className="w-12 h-12 rounded-full bg-white/5 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <Sparkles className="w-5 h-5 text-[#FF4500]" />
                </div>
                <span className="text-white/60 font-mono text-xs border border-white/15 px-3 py-1 rounded-full">02</span>
              </div>

              <div className="my-8">
                <h4 className="font-serif-display text-4xl md:text-5xl text-white leading-none tracking-tight">
                  Behavioral
                  <br />
                  Intelligence
                </h4>
                <p className="mt-4 text-gray-400 text-base leading-snug">
                  64-tree Isolation Forest behavioral scoring ({counts.anomaliesDetected} flagged outliers) paired with
                  evidence-grounded Gemini AI investigation.
                </p>
              </div>

              <div className="pt-4 border-t border-white/10 flex items-center justify-between text-xs font-mono text-gray-400 group-hover:text-white">
                <span>EXPLORE ISOLATION FOREST</span>
                <ArrowRight className="w-4 h-4 text-[#FF4500] group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 4. Live Event Stream Split Table */}
      <section className="obsidian-card overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <h3 className="text-lg font-medium text-white font-serif-display">Live Telemetry Stream</h3>
            {focusedAlert && (
              <>
                <VChip status="info" label={focusedAlert.id} />
                <VChip
                  status={focusedAlert.ml.isAnomaly ? 'info' : 'pass'}
                  label={`ML ${focusedAlert.ml.score.toFixed(3)}`}
                />
              </>
            )}
          </div>
          {focusedAlert && (
            <button
              onClick={() => onSelectAlert(focusedAlert)}
              className="btn-pill-primary px-4 py-1.5 text-xs whitespace-nowrap"
            >
              <span>Inspect JSON</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[240px_1fr]">
          <div className="border-b lg:border-b-0 lg:border-r border-white/10 max-h-[360px] overflow-y-auto divide-y divide-white/5">
            {streamAlerts.map((a) => {
              const active = focusedAlert?.id === a.id;
              const dotColor =
                a.rule.level >= 12
                  ? 'bg-[#FF4500]'
                  : a.rule.level >= 8
                    ? 'bg-[#ffe0e0]'
                    : a.ml.isAnomaly
                      ? 'bg-gray-400'
                      : 'bg-emerald-400';

              return (
                <button
                  key={a.id}
                  onClick={() => setSelectedStreamId(a.id)}
                  className={`w-full text-left px-4 py-3 flex items-center justify-between gap-2 transition-colors ${
                    active ? 'bg-white/10' : 'hover:bg-white/5'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotColor}`} />
                    <span className="font-mono text-xs text-white truncate">{a.id}</span>
                  </div>
                  <span className="font-mono text-[11px] text-gray-400 shrink-0">L{a.rule.level}</span>
                </button>
              );
            })}
          </div>

          <div className="overflow-x-auto max-h-[360px]">
            <table className="w-full text-xs text-left">
              <thead className="border-b border-white/10 text-gray-400 bg-[#050505] sticky top-0 z-10">
                <tr>
                  <th className="px-4 py-3 font-medium">SPAN</th>
                  <th className="px-4 py-3 font-medium w-60">START (TIMELINE OFFSET)</th>
                  <th className="px-4 py-3 font-medium text-right">ML SCORE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {streamAlerts.map((a) => {
                  const active = focusedAlert?.id === a.id;
                  const tsMs = Date.parse(a.timestamp) || streamMetrics.minMs;
                  const startPct = ((tsMs - streamMetrics.minMs) / streamMetrics.spanMs) * 84;
                  const widthPct = Math.max(8, (a.rule.level / 16) * 24);

                  return (
                    <tr
                      key={a.id}
                      onClick={() => {
                        setSelectedStreamId(a.id);
                        onSelectAlert(a);
                      }}
                      className={`cursor-pointer transition-colors ${active ? 'bg-white/5' : 'hover:bg-white/[0.03]'}`}
                    >
                      <td className="px-4 py-3 font-mono">
                        <div className="text-white truncate max-w-md">
                          <span className="text-[#FF4500] mr-2">[{a.decoder.name}]</span>
                          {a.rule.description}
                        </div>
                        <div className="text-[11px] text-gray-400 mt-0.5">
                          {a.agent.name} · RULE #{a.rule.id} · {formatTimeShort(a.timestamp)}
                        </div>
                      </td>
                      <td className="px-4 py-3 align-middle">
                        <TimelineProgressBar startPct={startPct} widthPct={widthPct} active={active} />
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums whitespace-nowrap">
                        <span className={a.ml.isAnomaly ? 'text-[#FF4500]' : 'text-gray-400'}>
                          {a.ml.score.toFixed(3)} s(x)
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* 5. Hourly Velocity Chart & Active Incidents Queue */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 obsidian-card p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-lg font-medium text-white font-serif-display">
                Hourly Telemetry &amp; Anomaly Velocity
              </h3>
              <p className="text-xs font-mono text-gray-400">Deterministic rule hits vs Isolation Forest outliers</p>
            </div>
            <button
              onClick={() => onNavigate('discover')}
              className="btn-pill-glass px-4 py-1.5 text-xs whitespace-nowrap"
            >
              <span>AQL Query</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
          <div className="h-64">
            <Bar
              data={timelineChartData}
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
                  x: { grid: { color: CHART_GRID_COLOR }, ticks: { color: CHART_TICK_COLOR, font: { size: 11 } } },
                  y: {
                    beginAtZero: true,
                    grid: { color: CHART_GRID_COLOR },
                    ticks: { color: CHART_TICK_COLOR, precision: 0, font: { size: 11 } },
                  },
                },
              }}
            />
          </div>
        </div>

        <div className="lg:col-span-5 obsidian-card overflow-hidden flex flex-col">
          <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
            <h3 className="text-lg font-medium text-white font-serif-display">Prioritized Incidents</h3>
            <button
              onClick={() => onNavigate('incidents')}
              className="text-xs font-mono text-[#FF4500] hover:underline whitespace-nowrap"
            >
              View All →
            </button>
          </div>
          <div className="divide-y divide-white/5 flex-1">
            {recentIncidents.map((inc) => (
              <div
                key={inc.id}
                className="px-5 py-3.5 hover:bg-white/[0.03] transition-colors flex items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-gray-400">{inc.id}</span>
                    <IncidentSeverityLabel severity={inc.severity} />
                    <IncidentStatusLabel status={inc.status} />
                  </div>
                  <div className="mt-1.5 text-xs font-medium text-white truncate">{inc.title}</div>
                  <div className="mt-0.5 text-[11px] font-mono text-gray-400 truncate">
                    {inc.primaryAgentName} · {inc.alertCount} ALERTS · {inc.mitreIds.join(', ') || 'ML'}
                  </div>
                </div>
                <button
                  onClick={() => onInvestigateIncident(inc)}
                  className="btn-pill-primary px-3.5 py-1.5 text-xs whitespace-nowrap shrink-0"
                >
                  <span>Ask AI</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
