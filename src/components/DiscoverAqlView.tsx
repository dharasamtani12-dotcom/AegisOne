import React, { useEffect, useState } from 'react';
import { ArrowRight, Download, HelpCircle, Search } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { AegisAlert } from '../types/aegis';
import { SeverityLabel, VChip, formatTimeShort } from './SeverityTag';

interface DiscoverAqlProps {
  onSelectAlert: (alert: AegisAlert) => void;
  initialQuery?: string;
}

const PRESET_QUERIES = [
  { label: 'All Alerts', q: '' },
  { label: 'High & Critical (L8+)', q: 'rule.level >= 8 | sort -timestamp' },
  { label: 'ML Anomalies', q: 'ml.anomaly == true | sort -ml.score' },
  { label: 'IP 185.220.101.42', q: 'data.srcip == "185.220.101.42"' },
  { label: 'SSH & T1110', q: 'rule.mitre.id ~ "T1110" OR decoder.name ~ "sshd"' },
  { label: 'Sysmon & PowerShell', q: 'decoder.parent == "windows-sysmon" OR rule.mitre.id == "T1059.001"' },
];

export function DiscoverAqlView({ onSelectAlert, initialQuery = '' }: DiscoverAqlProps) {
  const [query, setQuery] = useState(initialQuery);
  const [alerts, setAlerts] = useState<AegisAlert[]>([]);
  const [totalMatched, setTotalMatched] = useState(0);
  const [parsedSummary, setParsedSummary] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showSyntax, setShowSyntax] = useState(false);

  const runQuery = async (qStr: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch<{
        alerts: AegisAlert[];
        totalMatched: number;
        parsedSummary: string;
        error?: string;
      }>('/api/v1/aql/query', {
        method: 'POST',
        body: JSON.stringify({ query: qStr }),
      });
      setAlerts(res.alerts);
      setTotalMatched(res.totalMatched);
      setParsedSummary(res.parsedSummary);
      if (res.error) setError(res.error);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Query execution failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runQuery(query);
  }, []);

  const exportCsv = () => {
    const header = ['AlertID', 'Timestamp', 'RuleID', 'Level', 'Agent', 'Decoder', 'SrcIP', 'User', 'MLScore', 'MITRE', 'Description'];
    const rows = alerts.map((a) => [
      a.id,
      a.timestamp,
      a.rule.id,
      a.rule.level,
      a.agent.name,
      a.decoder.name,
      a.data.srcip || '',
      a.data.srcuser || a.data.user || '',
      a.ml.score,
      a.rule.mitre?.id || '',
      `"${a.rule.description.replace(/"/g, '""')}"`,
    ]);
    const csv = [header.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `aegisone-aql-export-${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="headline-editorial text-2xl sm:text-3xl text-white">
              AQL — AegisOne Query Language Explorer
            </h2>
            <p className="text-xs font-mono text-gray-400 mt-1.5">
              Filter indexed SIEM alerts using nested JSON paths, boolean operators, regex (~), and sort/limit pipes.
            </p>
          </div>
          <div className="flex items-center gap-2.5">
            <button
              onClick={() => setShowSyntax((s) => !s)}
              className="btn-pill-glass inline-flex items-center gap-1.5 px-4 py-2 text-xs whitespace-nowrap"
            >
              <HelpCircle className="w-3.5 h-3.5" />
              <span>AQL Syntax</span>
            </button>
            <button
              onClick={exportCsv}
              disabled={alerts.length === 0}
              className="btn-pill-glass inline-flex items-center gap-1.5 px-4 py-2 text-xs disabled:opacity-40 whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            runQuery(query);
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-gray-500 absolute left-4 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder='rule.level >= 10 AND agent.name == "web-gw-01" | sort -timestamp | limit 50'
              className="w-full pl-11 pr-4 py-3 rounded-full bg-[#050505] border border-white/10 focus:border-[#FF4500] text-xs font-mono text-white placeholder:text-gray-500 focus:outline-none transition-colors"
            />
          </div>
          <button
            type="submit"
            className="btn-pill-primary inline-flex items-center justify-center gap-1.5 px-6 py-3 text-xs whitespace-nowrap shrink-0"
          >
            <span>Run AQL</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2">
          {PRESET_QUERIES.map((p) => (
            <button
              key={p.label}
              onClick={() => {
                setQuery(p.q);
                runQuery(p.q);
              }}
              className={`px-3.5 py-1.5 text-xs font-mono rounded-full border transition-colors whitespace-nowrap ${
                query === p.q
                  ? 'bg-[#FF4500]/15 border-[#FF4500] text-[#ffe0e0]'
                  : 'bg-[#050505] border-white/10 text-gray-400 hover:text-white hover:border-white/25'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>

        {showSyntax && (
          <div className="p-4 rounded-2xl bg-[#050505] border border-white/10 text-xs text-gray-400 space-y-1.5 font-mono">
            <div>Operators: ==, !=, &gt;=, &lt;=, &gt;, &lt;, ~ (regex/contains), AND, OR, NOT, (...)</div>
            <div>Fields: rule.level, rule.id, rule.mitre.id, agent.name, decoder.name, data.srcip, data.srcuser, ml.score, ml.anomaly</div>
            <div>Pipes: | sort -timestamp | sort -rule.level | sort -ml.score | limit 100</div>
          </div>
        )}

        {error && (
          <div className="p-3.5 rounded-2xl bg-[#FF4500]/10 border border-[#FF4500]/40 text-xs font-mono text-[#ffe0e0]">
            {error}
          </div>
        )}
      </section>

      <section className="obsidian-card overflow-hidden">
        <div className="px-6 py-3.5 border-b border-white/10 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
          <VChip status="info" label={`${alerts.length} / ${totalMatched} MATCHED`} />
          <span className="text-gray-400 truncate max-w-xl">{parsedSummary}</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs font-mono text-gray-400">EXECUTING AQL QUERY...</div>
        ) : alerts.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-gray-400">
            No alerts matched this AQL expression. Clear filter or select a preset.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#050505] text-gray-400 border-b border-white/10">
                <tr>
                  <th className="px-4 py-3 font-medium">TIMESTAMP</th>
                  <th className="px-4 py-3 font-medium">SEVERITY</th>
                  <th className="px-4 py-3 font-medium">AGENT</th>
                  <th className="px-4 py-3 font-medium">DECODER</th>
                  <th className="px-4 py-3 font-medium">SRC IP / USER</th>
                  <th className="px-4 py-3 font-medium">RULE &amp; DESCRIPTION</th>
                  <th className="px-4 py-3 font-medium">MITRE</th>
                  <th className="px-4 py-3 font-medium text-right">ML SCORE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {alerts.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => onSelectAlert(a)}
                    className="hover:bg-white/[0.03] cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap tabular-nums">
                      {formatTimeShort(a.timestamp)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <SeverityLabel level={a.rule.level} />
                    </td>
                    <td className="px-4 py-3 text-white whitespace-nowrap">{a.agent.name}</td>
                    <td className="px-4 py-3 text-[#FF4500] whitespace-nowrap">{a.decoder.name}</td>
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                      {a.data.srcip ? String(a.data.srcip) : '—'}
                      {a.data.srcuser || a.data.user ? ` · ${String(a.data.srcuser || a.data.user)}` : ''}
                    </td>
                    <td className="px-4 py-3 text-gray-200 max-w-sm truncate">
                      <span className="text-gray-500 mr-1.5">#{a.rule.id}</span>
                      {a.rule.description}
                    </td>
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                      {a.rule.mitre?.id || '—'}
                    </td>
                    <td
                      className={`px-4 py-3 text-right tabular-nums whitespace-nowrap ${
                        a.ml.isAnomaly ? 'text-[#FF4500]' : 'text-gray-400'
                      }`}
                    >
                      {a.ml.score.toFixed(3)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
