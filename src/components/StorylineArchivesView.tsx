import React, { useEffect, useState } from 'react';
import { Archive, GitCommitHorizontal, Search } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { AegisAlert, ArchiveEntry, IncidentRecord } from '../types/aegis';
import { IncidentSeverityLabel, SeverityLabel, VChip, formatTimeShort } from './SeverityTag';

export function StorylineView({
  onSelectAlert,
}: {
  onSelectAlert: (alert: AegisAlert) => void;
}) {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [selectedIncId, setSelectedIncId] = useState<string>('');
  const [alerts, setAlerts] = useState<AegisAlert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const res = await apiFetch<{ incidents: IncidentRecord[] }>('/api/v1/incidents');
        setIncidents(res.incidents);
        if (res.incidents[0]) setSelectedIncId(res.incidents[0].id);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  useEffect(() => {
    if (!selectedIncId) return;
    (async () => {
      const res = await apiFetch<{ incident: IncidentRecord; alerts: AegisAlert[] }>(
        `/api/v1/incidents/${selectedIncId}`
      );
      setAlerts([...res.alerts].sort((a, b) => a.timestamp.localeCompare(b.timestamp)));
    })();
  }, [selectedIncId]);

  const activeInc = incidents.find((i) => i.id === selectedIncId);

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white">Unified Attack Storyline</h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Chronological kill-chain linking raw logs, decoded entities, 0–16 rule hits, Isolation Forest spikes, and MITRE tactics.
          </p>
        </div>
        <select
          value={selectedIncId}
          onChange={(e) => setSelectedIncId(e.target.value)}
          className="px-4 py-2.5 rounded-full bg-[#050505] border border-white/10 text-xs font-mono text-white focus:outline-none focus:border-[#FF4500]"
        >
          {incidents.map((inc) => (
            <option key={inc.id} value={inc.id}>
              {inc.id} — {inc.title}
            </option>
          ))}
        </select>
      </section>

      {loading ? (
        <div className="p-8 obsidian-card text-center text-xs font-mono text-gray-400">
          LOADING CORRELATED STORYLINE...
        </div>
      ) : activeInc ? (
        <section className="obsidian-card p-6 md:p-8 space-y-6">
          <div className="pb-5 border-b border-white/10 flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                <span className="text-gray-300">{activeInc.id}</span>
                <IncidentSeverityLabel severity={activeInc.severity} />
                <VChip status="info" label={`CONF ${Math.round(activeInc.confidence * 100)}%`} />
              </div>
              <h3 className="mt-2.5 font-serif-display text-2xl font-medium text-white">{activeInc.title}</h3>
              <p className="mt-1.5 text-sm text-gray-400 font-light">{activeInc.summary}</p>
            </div>
            <div className="text-right font-mono text-xs text-gray-400 tabular-nums">
              <div className="text-[#FF4500]">MITRE: {activeInc.mitreTactics.join(' → ')}</div>
              <div className="mt-1">
                {formatTimeShort(activeInc.firstSeen)} → {formatTimeShort(activeInc.lastSeen)}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {alerts.map((a, idx) => (
              <div
                key={a.id}
                onClick={() => onSelectAlert(a)}
                className="p-5 rounded-2xl bg-[#050505] border border-white/10 hover:border-[#FF4500]/60 cursor-pointer transition-colors"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                  <div className="flex items-center gap-2.5">
                    <GitCommitHorizontal className="w-4 h-4 text-[#FF4500] shrink-0" />
                    <VChip status="info" label={`STAGE ${idx + 1}`} />
                    <span className="text-gray-400 tabular-nums">{formatTimeShort(a.timestamp)}</span>
                    <SeverityLabel level={a.rule.level} />
                  </div>
                  <div className="flex items-center gap-2">
                    {a.rule.mitre && <VChip status="warn" label={`${a.rule.mitre.id} · ${a.rule.mitre.tactic}`} />}
                    <VChip
                      status={a.ml.isAnomaly ? 'info' : 'pass'}
                      label={`ML ${a.ml.score.toFixed(3)}`}
                    />
                  </div>
                </div>
                <div className="mt-3 text-sm font-medium text-white">{a.rule.description}</div>
                <div className="mt-1 text-xs font-mono text-gray-400 truncate">
                  AGENT:{a.agent.name} · DECODER:{a.decoder.name} ·{' '}
                  {a.data.srcip ? `srcip=${a.data.srcip} ` : ''}
                  {a.data.srcuser || a.data.user ? `user=${a.data.srcuser || a.data.user}` : ''}
                </div>
                <pre className="mt-3 p-3.5 rounded-xl bg-[#111111] border border-white/10 text-[11px] font-mono text-gray-200 overflow-x-auto">
                  {a.full_log}
                </pre>
              </div>
            ))}
          </div>
        </section>
      ) : (
        <div className="p-8 obsidian-card text-center text-xs font-mono text-gray-400">
          No correlated incidents available yet.
        </div>
      )}
    </div>
  );
}

export function ArchivesView() {
  const [entries, setEntries] = useState<ArchiveEntry[]>([]);
  const [storage, setStorage] = useState<{ logGzBytes: number; jsonGzBytes: number; totalArchivedRows: number } | null>(
    null
  );
  const [config, setConfig] = useState<{ logall: boolean; logallJson: boolean } | null>(null);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  const loadArchives = async (q = '') => {
    setLoading(true);
    try {
      const res = await apiFetch<{
        entries: ArchiveEntry[];
        storage: { logGzBytes: number; jsonGzBytes: number; totalArchivedRows: number };
        config: { logall: boolean; logallJson: boolean };
      }>(`/api/v1/archives?q=${encodeURIComponent(q)}`);
      setEntries(res.entries);
      setStorage(res.storage);
      setConfig(res.config);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadArchives();
  }, []);

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
            <Archive className="w-5 h-5 text-[#FF4500]" />
            <span>Retrospective Event Archives</span>
          </h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Compressed raw telemetry retained in archives.log.gz and archives.json.gz for retrospective threat hunting (logall / logall_json).
          </p>
        </div>
        {storage && config && (
          <div className="flex flex-wrap items-center gap-2">
            <VChip status={config.logall ? 'pass' : 'warn'} label={`LOGALL ${config.logall ? 'ON' : 'OFF'}`} />
            <VChip status="info" label={`LOG.GZ ${(storage.logGzBytes / 1024).toFixed(1)} KB`} />
            <VChip status="info" label={`JSON.GZ ${(storage.jsonGzBytes / 1024).toFixed(1)} KB`} />
          </div>
        )}
      </section>

      <section className="obsidian-card overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 flex flex-wrap items-center justify-between gap-4">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              loadArchives(search);
            }}
            className="flex items-center gap-2.5 flex-1 max-w-md"
          >
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-gray-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search raw archived logs, program_name, agent..."
                className="w-full pl-9 pr-4 py-2 rounded-full bg-[#050505] border border-white/10 text-xs font-mono text-white placeholder:text-gray-500 focus:outline-none focus:border-[#FF4500]"
              />
            </div>
            <button type="submit" className="btn-pill-primary px-5 py-2 text-xs whitespace-nowrap">
              Filter
            </button>
          </form>
          <span className="text-xs font-mono text-gray-400 tabular-nums">{entries.length} RECORDS</span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs font-mono text-gray-400">LOADING ARCHIVES...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#050505] text-gray-400 border-b border-white/10">
                <tr>
                  <th className="px-4 py-3 font-medium">TIMESTAMP</th>
                  <th className="px-4 py-3 font-medium">AGENT</th>
                  <th className="px-4 py-3 font-medium">PROGRAM</th>
                  <th className="px-4 py-3 font-medium">STATUS</th>
                  <th className="px-4 py-3 font-medium">RAW ARCHIVED LINE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {entries.map((e) => (
                  <tr key={e.id} className="hover:bg-white/[0.03] transition-colors">
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap tabular-nums">
                      {formatTimeShort(e.timestamp)}
                    </td>
                    <td className="px-4 py-3 text-white whitespace-nowrap">{e.agentName}</td>
                    <td className="px-4 py-3 text-[#FF4500] whitespace-nowrap">{e.programName}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <VChip status={e.alerted ? 'info' : 'warn'} label={e.alerted ? 'ALERTED' : 'ARCHIVED'} />
                    </td>
                    <td className="px-4 py-3 text-gray-400 max-w-2xl truncate">{e.rawLog}</td>
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
