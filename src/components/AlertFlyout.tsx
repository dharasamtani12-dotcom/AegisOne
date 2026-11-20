import React, { useState } from 'react';
import { ArrowRight, Check, Copy, Cpu, FileJson, Terminal, X } from 'lucide-react';
import type { AegisAlert } from '../types/aegis';
import { SeverityLabel, VChip, formatTimeShort } from './SeverityTag';

interface AlertFlyoutProps {
  alert: AegisAlert | null;
  onClose: () => void;
  onAskAi?: (alert: AegisAlert) => void;
}

export function AlertFlyout({ alert, onClose, onAskAi }: AlertFlyoutProps) {
  const [tab, setTab] = useState<'fields' | 'json' | 'ml'>('fields');
  const [copied, setCopied] = useState(false);

  if (!alert) return null;

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const dataEntries = Object.entries(alert.data || {}).filter(([, v]) => v !== undefined && v !== '');

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm" onClick={onClose}>
      <aside
        className="w-full max-w-2xl bg-[#111111] border-l border-white/10 h-full flex flex-col shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        aria-label="Alert inspection drawer"
      >
        <div className="px-6 py-5 border-b border-white/10 flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400 font-mono">
              <span className="text-[#ffe0e0]">{alert.id}</span>
              <span aria-hidden="true">·</span>
              <span>{formatTimeShort(alert.timestamp)}</span>
              <SeverityLabel level={alert.rule.level} />
            </div>
            <h2 className="mt-2 text-xl font-medium text-white font-serif-display leading-snug">
              {alert.rule.description}
            </h2>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs font-mono text-gray-400">
              <span>AGENT:{alert.agent.name} ({alert.agent.ip})</span>
              <span aria-hidden="true">·</span>
              <span className="text-[#FF4500]">DECODER:{alert.decoder.name}</span>
              {alert.rule.mitre && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="text-[#ffe0e0]">
                    {alert.rule.mitre.id} ({alert.rule.mitre.tactic})
                  </span>
                </>
              )}
            </div>
          </div>

          <button
            onClick={onClose}
            className="btn-pill-glass p-2 shrink-0"
            aria-label="Close drawer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-3 border-b border-white/10 flex flex-wrap items-center justify-between gap-3 bg-[#050505]">
          <div className="flex items-center gap-1.5">
            {(['fields', 'ml', 'json'] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-3.5 py-1.5 text-xs font-mono rounded-full transition-colors whitespace-nowrap border ${
                  tab === t
                    ? 'bg-white text-black border-white font-medium'
                    : 'bg-white/5 text-gray-400 border-white/10 hover:text-white'
                }`}
              >
                {t === 'fields' ? 'DECODED FIELDS' : t === 'ml' ? 'ISOLATION FOREST' : 'ALERT JSON'}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {onAskAi && (
              <button
                onClick={() => onAskAi(alert)}
                className="btn-pill-primary px-4 py-1.5 text-xs whitespace-nowrap"
              >
                <span>Investigate AI</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            )}
            <button
              onClick={copyJson}
              className="btn-pill-glass px-3.5 py-1.5 text-xs whitespace-nowrap"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {tab === 'fields' && (
            <>
              <div>
                <h3 className="text-xs font-mono text-gray-400 uppercase mb-2 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-[#FF4500]" />
                  Raw Event Log
                </h3>
                <pre className="p-4 bg-[#050505] border border-white/10 rounded-xl text-xs font-mono text-[#ffe0e0] whitespace-pre-wrap break-all leading-relaxed">
                  {alert.full_log}
                </pre>
              </div>

              <div>
                <h3 className="text-xs font-mono text-gray-400 uppercase mb-2">
                  Extracted Static &amp; Dynamic Fields ({dataEntries.length})
                </h3>
                <div className="border border-white/10 rounded-xl overflow-hidden bg-[#050505]">
                  <table className="w-full text-xs">
                    <tbody className="divide-y divide-white/10">
                      <tr>
                        <td className="px-3.5 py-2.5 font-mono text-gray-400 w-48">rule.id / firedtimes</td>
                        <td className="px-3.5 py-2.5 font-mono text-white tabular-nums">
                          {alert.rule.id} (fired {alert.rule.firedtimes}x)
                        </td>
                      </tr>
                      <tr>
                        <td className="px-3.5 py-2.5 font-mono text-gray-400">decoder.parent / name</td>
                        <td className="px-3.5 py-2.5 font-mono text-white">
                          {alert.decoder.parent || 'root'} → {alert.decoder.name}
                        </td>
                      </tr>
                      <tr>
                        <td className="px-3.5 py-2.5 font-mono text-gray-400">rule.groups</td>
                        <td className="px-3.5 py-2.5 font-mono text-gray-400">{alert.rule.groups.join(', ')}</td>
                      </tr>
                      {dataEntries.map(([k, v]) => (
                        <tr key={k} className="hover:bg-white/5">
                          <td className="px-3.5 py-2.5 font-mono text-[#FF4500]">data.{k}</td>
                          <td className="px-3.5 py-2.5 font-mono text-white break-all">{String(v)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {tab === 'ml' && (
            <div className="space-y-5">
              <div className="grid grid-cols-3 gap-3">
                <div className="p-4 bg-[#050505] border border-white/10 rounded-2xl">
                  <div className="text-xs font-mono text-gray-400">ANOMALY SCORE</div>
                  <div
                    className={`mt-1.5 text-2xl font-mono tabular-nums ${
                      alert.ml.isAnomaly ? 'text-[#FF4500]' : 'text-emerald-400'
                    }`}
                  >
                    {alert.ml.score.toFixed(3)}
                  </div>
                  <div className="mt-2">
                    <VChip
                      status={alert.ml.isAnomaly ? 'info' : 'pass'}
                      label={alert.ml.isAnomaly ? 'ANOMALY' : 'NOMINAL'}
                    />
                  </div>
                </div>
                <div className="p-4 bg-[#050505] border border-white/10 rounded-2xl">
                  <div className="text-xs font-mono text-gray-400">AVG PATH E(h(x))</div>
                  <div className="mt-1.5 text-2xl font-mono tabular-nums text-white">
                    {alert.ml.avgPathLength}
                  </div>
                  <div className="mt-2 text-xs font-mono text-gray-400">c(n): {alert.ml.expectedPathLength}</div>
                </div>
                <div className="p-4 bg-[#050505] border border-white/10 rounded-2xl">
                  <div className="text-xs font-mono text-gray-400">INCIDENT</div>
                  <div className="mt-1.5 text-lg font-mono text-[#ffe0e0]">
                    {alert.incidentId || 'STANDALONE'}
                  </div>
                  <div className="mt-2 text-xs font-mono text-gray-400">64-Tree Forest</div>
                </div>
              </div>

              <div>
                <h3 className="text-xs font-mono text-gray-400 uppercase mb-3 flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-[#FF4500]" />
                  Explainable Feature Attribution
                </h3>
                <div className="space-y-2.5">
                  {alert.ml.contributions.map((c) => (
                    <div key={c.feature} className="p-3.5 bg-[#050505] border border-white/10 rounded-xl">
                      <div className="flex items-center justify-between text-xs font-mono mb-2">
                        <span className="text-white">{c.label}</span>
                        <span className="tabular-nums text-gray-400">
                          {c.value.toFixed(2)} vs {c.baselineMedian.toFixed(2)} ·{' '}
                          <strong className="text-[#FF4500]">{c.contributionPct}%</strong>
                        </span>
                      </div>
                      <div className="h-1.5 w-full bg-white/10 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${alert.ml.isAnomaly ? 'bg-[#FF4500]' : 'bg-emerald-400'}`}
                          style={{ width: `${Math.min(100, c.contributionPct)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {tab === 'json' && (
            <div>
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-2 flex items-center gap-1.5">
                <FileJson className="w-3.5 h-3.5 text-[#FF4500]" />
                Canonical AegisOne Alert Document
              </h3>
              <pre className="p-4 bg-[#050505] border border-white/10 rounded-xl text-xs font-mono text-[#ffe0e0] overflow-x-auto leading-relaxed">
                {JSON.stringify(alert, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}
