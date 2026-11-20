import React, { useEffect, useState } from 'react';
import { Download, Printer, Save, Settings, Shield } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { AegisAlert, IncidentRecord, OverviewData, RbacRole } from '../types/aegis';
import { IncidentSeverityLabel, IncidentStatusLabel, VChip, formatTimeShort } from './SeverityTag';

const RBAC_MATRIX: Array<{ role: RbacRole; label: string; capabilities: string }> = [
  {
    role: 'admin',
    label: 'Administrator',
    capabilities: 'Full control: edit aegisone.conf, modify local XML rules/decoders, retrain ML, manage incidents, ingest logs.',
  },
  {
    role: 'analyst',
    label: 'SOC Analyst',
    capabilities: 'Investigate incidents, transition case status, run AQL queries, ingest/simulate logs, query AI Analyst.',
  },
  {
    role: 'auditor',
    label: 'Auditor (Read-Only)',
    capabilities: 'Inspect Command Center, Discover AQL, Incidents, Archives, and export PDF/CSV compliance reports.',
  },
];

export function ConfigRbacView({
  role,
  onChangeRole,
  onMutated,
}: {
  role: RbacRole;
  onChangeRole: (r: RbacRole) => void;
  onMutated: () => void;
}) {
  const [rawXml, setRawXml] = useState('');
  const [auditLogs, setAuditLogs] = useState<Array<Record<string, string>>>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    const [cfgRes, audRes] = await Promise.all([
      apiFetch<{ rawXml: string }>('/api/v1/config'),
      apiFetch<{ logs: Array<Record<string, string>> }>('/api/v1/audit'),
    ]);
    setRawXml(cfgRes.rawXml);
    setAuditLogs(audRes.logs);
  };

  useEffect(() => {
    load();
  }, []);

  const saveConfig = async () => {
    setMsg(null);
    setErr(null);
    try {
      await apiFetch('/api/v1/config', {
        method: 'PUT',
        body: JSON.stringify({ rawXml }),
      });
      setMsg('Saved etc/aegisone.conf successfully.');
      await load();
      onMutated();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Save failed');
    }
  };

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 space-y-5">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-[#FF4500]" />
            <span>Role-Based Access Control (RBAC)</span>
          </h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Switch active session role to test real server-side RBAC enforcement across ingestion, incident mutations, and config endpoints.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {RBAC_MATRIX.map((r) => (
            <button
              key={r.role}
              onClick={() => onChangeRole(r.role)}
              className={`text-left p-5 rounded-2xl border transition-colors ${
                role === r.role
                  ? 'bg-[#FF4500]/10 border-[#FF4500] text-white'
                  : 'bg-[#050505] border-white/10 text-gray-200 hover:border-white/25'
              }`}
            >
              <div className="flex items-center justify-between text-sm font-medium">
                <span>{r.label}</span>
                {role === r.role && <VChip status="info" label="ACTIVE" />}
              </div>
              <div className="mt-2.5 text-xs text-gray-400 leading-relaxed">{r.capabilities}</div>
            </button>
          ))}
        </div>
      </section>

      <section className="obsidian-card p-6 md:p-8 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="font-serif-display text-xl font-medium text-white flex items-center gap-2">
              <Settings className="w-4 h-4 text-[#FF4500]" />
              <span>etc/aegisone.conf — Server &amp; Archiving Configuration</span>
            </h3>
            <p className="text-xs font-mono text-gray-400 mt-1">
              Controls domain, logall / logall_json gzip archiving, bounded queue capacity, and Isolation Forest hyperparameters.
            </p>
          </div>
          <button
            onClick={saveConfig}
            disabled={role !== 'admin'}
            className="btn-pill-primary inline-flex items-center gap-1.5 px-5 py-2 text-xs disabled:opacity-40 whitespace-nowrap"
          >
            <Save className="w-3.5 h-3.5" />
            <span>Save aegisone.conf</span>
          </button>
        </div>

        {err && (
          <div className="p-3.5 rounded-2xl bg-[#FF4500]/10 border border-[#FF4500]/40 text-xs font-mono text-[#ffe0e0]">
            {err}
          </div>
        )}
        {msg && (
          <div className="p-3.5 rounded-2xl bg-emerald-500/10 border border-emerald-400/50 text-xs font-mono text-emerald-300">
            {msg}
          </div>
        )}

        <textarea
          rows={14}
          value={rawXml}
          readOnly={role !== 'admin'}
          onChange={(e) => setRawXml(e.target.value)}
          className="w-full p-4 rounded-2xl bg-[#050505] border border-white/10 text-xs font-mono text-gray-200 focus:outline-none focus:border-[#FF4500] leading-relaxed"
        />
      </section>

      <section className="obsidian-card overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 font-serif-display text-lg font-medium text-white">
          RBAC Governance &amp; Audit Trail
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-[#050505] text-gray-400 border-b border-white/10">
              <tr>
                <th className="px-4 py-3 font-medium">TIMESTAMP</th>
                <th className="px-4 py-3 font-medium">ROLE</th>
                <th className="px-4 py-3 font-medium">ACTION</th>
                <th className="px-4 py-3 font-medium">TARGET</th>
                <th className="px-4 py-3 font-medium">DETAILS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-gray-400">
                    No administrative audit entries recorded yet.
                  </td>
                </tr>
              ) : (
                auditLogs.map((l) => (
                  <tr key={l.id} className="hover:bg-white/[0.03] transition-colors">
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap tabular-nums">
                      {formatTimeShort(l.timestamp)}
                    </td>
                    <td className="px-4 py-3 text-[#FF4500]">{l.role}</td>
                    <td className="px-4 py-3 text-white">{l.action}</td>
                    <td className="px-4 py-3 text-gray-200">{l.target}</td>
                    <td className="px-4 py-3 text-gray-400">{l.details}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export function ReportsView({ overview }: { overview: OverviewData | null }) {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [alerts, setAlerts] = useState<AegisAlert[]>([]);

  useEffect(() => {
    Promise.all([
      apiFetch<{ incidents: IncidentRecord[] }>('/api/v1/incidents'),
      apiFetch<{ alerts: AegisAlert[] }>('/api/v1/alerts?limit=100'),
    ]).then(([iRes, aRes]) => {
      setIncidents(iRes.incidents);
      setAlerts(aRes.alerts);
    });
  }, []);

  const exportFullCsv = () => {
    const header = ['IncidentID', 'Severity', 'Status', 'Agent', 'SrcIP', 'Alerts', 'RiskImpact', 'Title'];
    const rows = incidents.map((i) => [
      i.id,
      i.severity,
      i.status,
      i.primaryAgentName,
      i.primarySrcip || '',
      i.alertCount,
      i.riskImpact,
      `"${i.title.replace(/"/g, '""')}"`,
    ]);
    const csv = [header.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegisone-executive-incidents-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <section className="no-print obsidian-card p-6 md:p-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white">Executive &amp; SOC Compliance Reports</h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Print-formatted PDF posture brief and machine-readable CSV exports powered by AegisOne Data Store.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={exportFullCsv}
            className="btn-pill-glass inline-flex items-center gap-1.5 px-5 py-2 text-xs whitespace-nowrap"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={() => window.print()}
            className="btn-pill-primary inline-flex items-center gap-1.5 px-5 py-2 text-xs whitespace-nowrap"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / Save PDF</span>
          </button>
        </div>
      </section>

      <section className="obsidian-card p-8 space-y-6">
        <div className="pb-5 border-b border-white/10 flex flex-wrap items-start justify-between gap-4">
          <div>
            <VChip status="info" label="AEGISONE POSTURE BRIEF" />
            <h3 className="mt-3 headline-editorial text-3xl text-white">
              Infrastructure Telemetry &amp; Incident Summary
            </h3>
            <p className="mt-1.5 text-xs font-mono text-gray-400">
              Generated {new Date().toLocaleString()} · Medicaps University Lab SOC
            </p>
          </div>
          {overview && (
            <div className="text-right">
              <div className="text-xs font-mono text-gray-400">COMPOSITE HEALTH</div>
              <div className="text-4xl font-serif-display tabular-nums text-white mt-1">
                {overview.healthScore.healthScore}/100
              </div>
              <div className="mt-1.5">
                <VChip
                  status={overview.healthScore.healthScore >= 65 ? 'pass' : 'info'}
                  label={overview.healthScore.grade.toUpperCase()}
                />
              </div>
            </div>
          )}
        </div>

        <div>
          <h4 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-3">Correlated Incidents Register</h4>
          <div className="overflow-x-auto rounded-2xl border border-white/10">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#050505] text-gray-400 border-b border-white/10">
                <tr>
                  <th className="px-4 py-3 font-medium">ID</th>
                  <th className="px-4 py-3 font-medium">SEVERITY</th>
                  <th className="px-4 py-3 font-medium">STATUS</th>
                  <th className="px-4 py-3 font-medium">AGENT</th>
                  <th className="px-4 py-3 font-medium">TITLE</th>
                  <th className="px-4 py-3 font-medium text-right">ALERTS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {incidents.map((i) => (
                  <tr key={i.id}>
                    <td className="px-4 py-3 text-gray-400">{i.id}</td>
                    <td className="px-4 py-3">
                      <IncidentSeverityLabel severity={i.severity} />
                    </td>
                    <td className="px-4 py-3">
                      <IncidentStatusLabel status={i.status} />
                    </td>
                    <td className="px-4 py-3 text-gray-200">{i.primaryAgentName}</td>
                    <td className="px-4 py-3 text-white">{i.title}</td>
                    <td className="px-4 py-3 text-right tabular-nums text-gray-200">{i.alertCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="text-xs font-mono text-gray-400 pt-4 border-t border-white/10">
          Report Scope: {alerts.length} indexed alerts · AegisOne SIEM &amp; XDR — Developed by Kushagra Sen, Harsh Verma &amp; Dhara Samtani under the guidance of Priyasha Gupta at Medicaps University, Indore (2026–27).
        </div>
      </section>
    </div>
  );
}
