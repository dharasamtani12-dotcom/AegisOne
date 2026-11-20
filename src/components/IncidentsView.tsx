import React, { useEffect, useState } from 'react';
import { ArrowRight, CheckCircle2, Layers } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { AegisAlert, IncidentRecord, RbacRole } from '../types/aegis';
import { IncidentSeverityLabel, IncidentStatusLabel, SeverityLabel, formatTimeShort } from './SeverityTag';

interface IncidentsViewProps {
  role: RbacRole;
  onSelectAlert: (alert: AegisAlert) => void;
  onAskAiForIncident: (inc: IncidentRecord) => void;
  onMutated: () => void;
}

export function IncidentsView({ role, onSelectAlert, onAskAiForIncident, onMutated }: IncidentsViewProps) {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [linkedAlerts, setLinkedAlerts] = useState<AegisAlert[]>([]);
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const loadIncidents = async () => {
    setLoading(true);
    try {
      const res = await apiFetch<{ incidents: IncidentRecord[] }>('/api/v1/incidents');
      setIncidents(res.incidents);
      if (!selectedId && res.incidents[0]) setSelectedId(res.incidents[0].id);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    apiFetch<{ incident: IncidentRecord; alerts: AegisAlert[] }>(`/api/v1/incidents/${selectedId}`)
      .then((res) => setLinkedAlerts(res.alerts))
      .catch(() => setLinkedAlerts([]));
  }, [selectedId]);

  const updateStatus = async (id: string, status: IncidentRecord['status']) => {
    setErr(null);
    try {
      await apiFetch(`/api/v1/incidents/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      });
      await loadIncidents();
      onMutated();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Status update denied');
    }
  };

  const filtered = incidents.filter((i) => filterStatus === 'all' || i.status === filterStatus);
  const selected = incidents.find((i) => i.id === selectedId) || null;

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
            <Layers className="w-5 h-5 text-[#FF4500]" />
            <span>Incident-Centric Case Management</span>
          </h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Correlated alerts grouped by source IP, compromised endpoint, and MITRE ATT&amp;CK progression.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {(['all', 'open', 'investigating', 'contained', 'resolved'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              className={`px-3.5 py-1.5 text-xs font-mono uppercase rounded-full border transition-colors whitespace-nowrap ${
                filterStatus === st
                  ? 'bg-white text-[#050505] border-white font-medium'
                  : 'bg-[#050505] text-gray-400 border-white/10 hover:text-white hover:border-white/25'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </section>

      {err && (
        <div className="p-3.5 rounded-2xl bg-[#FF4500]/10 border border-[#FF4500]/40 text-xs font-mono text-[#ffe0e0]">
          {err}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-5 obsidian-card overflow-hidden divide-y divide-white/5">
          {loading ? (
            <div className="p-6 text-center text-xs font-mono text-gray-400">LOADING INCIDENTS...</div>
          ) : filtered.length === 0 ? (
            <div className="p-6 text-center text-xs font-mono text-gray-400">
              No incidents match this lifecycle filter.
            </div>
          ) : (
            filtered.map((inc) => (
              <button
                key={inc.id}
                onClick={() => setSelectedId(inc.id)}
                className={`w-full text-left p-5 transition-colors ${
                  selectedId === inc.id ? 'bg-white/[0.06] border-l-2 border-[#FF4500]' : 'hover:bg-white/[0.03]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 text-xs font-mono">
                  <span className="text-gray-400">{inc.id}</span>
                  <div className="flex items-center gap-1.5">
                    <IncidentSeverityLabel severity={inc.severity} />
                    <IncidentStatusLabel status={inc.status} />
                  </div>
                </div>
                <div className="mt-2.5 text-sm font-medium text-white leading-snug">{inc.title}</div>
                <div className="mt-1 text-xs font-mono text-gray-400 tabular-nums">
                  {inc.primaryAgentName} · {inc.alertCount} ALERTS · RISK {inc.riskImpact}/100
                </div>
              </button>
            ))
          )}
        </div>

        <div className="lg:col-span-7 obsidian-card p-6 md:p-8 space-y-6">
          {selected ? (
            <>
              <div className="flex flex-wrap items-start justify-between gap-4 pb-5 border-b border-white/10">
                <div>
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-gray-400">
                    <span className="text-gray-200">{selected.id}</span>
                    <IncidentSeverityLabel severity={selected.severity} />
                    <span>ASSIGNED: {selected.assignedTo}</span>
                  </div>
                  <h3 className="mt-2.5 font-serif-display text-2xl font-medium text-white">{selected.title}</h3>
                </div>

                <button
                  onClick={() => onAskAiForIncident(selected)}
                  className="btn-pill-primary inline-flex items-center gap-1.5 px-5 py-2 text-xs whitespace-nowrap shrink-0"
                >
                  <span>Investigate AI</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 rounded-2xl overflow-hidden border border-white/10 divide-y sm:divide-y-0 sm:divide-x divide-white/10 bg-[#050505] text-xs font-mono">
                <div className="p-4">
                  <div className="text-gray-500">TARGET AGENT</div>
                  <div className="mt-1 text-white">{selected.primaryAgentName}</div>
                </div>
                <div className="p-4">
                  <div className="text-gray-500">SOURCE IP</div>
                  <div className="mt-1 text-white">{selected.primarySrcip || 'INTERNAL'}</div>
                </div>
                <div className="p-4">
                  <div className="text-gray-500">CONF / RISK</div>
                  <div className="mt-1 tabular-nums text-[#FF4500]">
                    {Math.round(selected.confidence * 100)}% · {selected.riskImpact}/100
                  </div>
                </div>
                <div className="p-4">
                  <div className="text-gray-500">MITRE IDS</div>
                  <div className="mt-1 text-gray-200">{selected.mitreIds.join(', ') || 'ANOMALY'}</div>
                </div>
              </div>

              <div>
                <h4 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-1.5">Incident Summary</h4>
                <p className="text-sm text-gray-200 font-light leading-relaxed">{selected.summary}</p>
              </div>

              <div>
                <h4 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-2.5">
                  Recommended Containment
                </h4>
                <ul className="space-y-2">
                  {selected.recommendedActions.map((act, idx) => (
                    <li key={idx} className="flex items-start gap-2.5 text-xs text-gray-200">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                      <span>{act}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-4 border-t border-white/10 flex flex-wrap items-center justify-between gap-3">
                <span className="text-xs font-mono text-gray-400">LIFECYCLE TRANSITION:</span>
                <div className="flex flex-wrap items-center gap-1.5">
                  {(['open', 'investigating', 'contained', 'resolved'] as const).map((st) => (
                    <button
                      key={st}
                      disabled={role === 'auditor' || selected.status === st}
                      onClick={() => updateStatus(selected.id, st)}
                      className={`px-3.5 py-1.5 text-xs font-mono uppercase rounded-full border transition-colors whitespace-nowrap ${
                        selected.status === st
                          ? 'bg-[#FF4500]/15 border-[#FF4500] text-[#ffe0e0]'
                          : 'bg-[#050505] border-white/10 text-gray-200 hover:bg-white/5 disabled:opacity-40'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-2.5">
                  Correlated Evidence Alerts ({linkedAlerts.length})
                </h4>
                <div className="rounded-2xl border border-white/10 divide-y divide-white/5 max-h-64 overflow-y-auto bg-[#050505]">
                  {linkedAlerts.map((a) => (
                    <div
                      key={a.id}
                      onClick={() => onSelectAlert(a)}
                      className="px-4 py-3 hover:bg-white/[0.04] cursor-pointer flex items-center justify-between gap-3 text-xs font-mono transition-colors"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 text-gray-400 tabular-nums">
                          <span>{formatTimeShort(a.timestamp)}</span>
                          <SeverityLabel level={a.rule.level} />
                        </div>
                        <div className="mt-1.5 text-gray-200 truncate">{a.rule.description}</div>
                      </div>
                      <span className="text-[#FF4500] tabular-nums shrink-0">ML {a.ml.score.toFixed(3)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="p-8 text-center text-xs font-mono text-gray-400">
              Select an incident to inspect case details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
