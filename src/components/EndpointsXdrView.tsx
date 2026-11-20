import React, { useEffect, useState } from 'react';
import { FileWarning, Server, ShieldAlert } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { AgentRecord, FimEvent, RbacRole, VulnerabilityRecord } from '../types/aegis';
import { SeverityLabel, VChip, formatTimeShort } from './SeverityTag';

export function AgentsView() {
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch<{ agents: AgentRecord[] }>('/api/v1/agents')
      .then((res) => setAgents(res.agents))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
            <Server className="w-5 h-5 text-[#FF4500]" />
            <span>AegisOne Agents &amp; Endpoint Inventory</span>
          </h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Monitored Linux, Windows Sysmon, Docker, and academic lab endpoints reporting to AegisOne Server.
          </p>
        </div>
        <VChip
          status="pass"
          label={`ACTIVE ${agents.filter((a) => a.status === 'active').length}/${agents.length}`}
        />
      </section>

      <section className="obsidian-card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-xs font-mono text-gray-400">LOADING AEGISONE AGENTS...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#050505] text-gray-400 border-b border-white/10">
                <tr>
                  <th className="px-4 py-3 font-medium">ID</th>
                  <th className="px-4 py-3 font-medium">HOSTNAME</th>
                  <th className="px-4 py-3 font-medium">IP ADDRESS</th>
                  <th className="px-4 py-3 font-medium">OPERATING SYSTEM</th>
                  <th className="px-4 py-3 font-medium">GROUP</th>
                  <th className="px-4 py-3 font-medium">STATUS</th>
                  <th className="px-4 py-3 font-medium text-right">CPU %</th>
                  <th className="px-4 py-3 font-medium text-right">MEMFREE</th>
                  <th className="px-4 py-3 font-medium text-right">KEEPALIVE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {agents.map((a) => (
                  <tr key={a.id} className="hover:bg-white/[0.03] transition-colors">
                    <td className="px-4 py-3 text-gray-400 tabular-nums">{a.id}</td>
                    <td className="px-4 py-3 text-white">{a.name}</td>
                    <td className="px-4 py-3 text-gray-400 tabular-nums">{a.ip}</td>
                    <td className="px-4 py-3 text-gray-200">{a.os}</td>
                    <td className="px-4 py-3 text-[#FF4500]">{a.groupName}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <VChip
                        status={a.status === 'active' ? 'pass' : 'info'}
                        label={a.status === 'active' ? 'ACTIVE' : 'OFFLINE'}
                      />
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-gray-200">
                      {a.cpuPct.toFixed(1)}%
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-gray-400">
                      {a.memFreeMb}/{a.memTotalMb} MB
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-gray-400 whitespace-nowrap">
                      {formatTimeShort(a.lastKeepAlive)}
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

export function FimView() {
  const [events, setEvents] = useState<FimEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch<{ events: FimEvent[] }>('/api/v1/fim')
      .then((res) => setEvents(res.events))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8">
        <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
          <FileWarning className="w-5 h-5 text-[#FF4500]" />
          <span>File Integrity Monitoring (FIM)</span>
        </h2>
        <p className="text-xs font-mono text-gray-400 mt-1.5">
          Cryptographic SHA-256 baseline drift tracking across critical authentication, privilege, and system paths.
        </p>
      </section>

      <section className="obsidian-card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-xs font-mono text-gray-400">LOADING FIM EVENTS...</div>
        ) : events.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-gray-400">
            No file integrity modifications detected.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#050505] text-gray-400 border-b border-white/10">
                <tr>
                  <th className="px-4 py-3 font-medium">TIMESTAMP</th>
                  <th className="px-4 py-3 font-medium">SEVERITY</th>
                  <th className="px-4 py-3 font-medium">AGENT</th>
                  <th className="px-4 py-3 font-medium">ACTION</th>
                  <th className="px-4 py-3 font-medium">MONITORED PATH</th>
                  <th className="px-4 py-3 font-medium">UID</th>
                  <th className="px-4 py-3 font-medium">SHA-256 BEFORE → AFTER</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {events.map((f) => (
                  <tr key={f.id} className="hover:bg-white/[0.03] transition-colors">
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap tabular-nums">
                      {formatTimeShort(f.timestamp)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <SeverityLabel level={f.severity} />
                    </td>
                    <td className="px-4 py-3 text-white">{f.agentName}</td>
                    <td className="px-4 py-3 text-[#FF4500]">{f.action}</td>
                    <td className="px-4 py-3 text-gray-200">{f.path}</td>
                    <td className="px-4 py-3 text-gray-400 tabular-nums">{f.uid}</td>
                    <td className="px-4 py-3 text-gray-400">
                      <span>{f.sha256Before}</span> → <span className="text-[#ffe0e0]">{f.sha256After}</span>
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

export function VulnerabilitiesView({
  role,
  onMutated,
}: {
  role: RbacRole;
  onMutated: () => void;
}) {
  const [vulns, setVulns] = useState<VulnerabilityRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const res = await apiFetch<{ vulnerabilities: VulnerabilityRecord[] }>('/api/v1/vulnerabilities');
      setVulns(res.vulnerabilities);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const toggleStatus = async (v: VulnerabilityRecord) => {
    setErr(null);
    const next = v.status === 'open' ? 'patched' : 'open';
    try {
      await apiFetch(`/api/v1/vulnerabilities/${v.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: next }),
      });
      await load();
      onMutated();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Update failed');
    }
  };

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-[#FF4500]" />
            <span>Vulnerability Detection &amp; Package Posture</span>
          </h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Active CVE inventory mapped across agent packages with CVSS v3 scores and remediation versions.
          </p>
        </div>
        <VChip status="info" label={`OPEN CVES ${vulns.filter((v) => v.status === 'open').length}`} />
      </section>

      {err && (
        <div className="p-3.5 rounded-2xl bg-[#FF4500]/10 border border-[#FF4500]/40 text-xs font-mono text-[#ffe0e0]">
          {err}
        </div>
      )}

      <section className="obsidian-card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-xs font-mono text-gray-400">LOADING CVE POSTURE...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-[#050505] text-gray-400 border-b border-white/10">
                <tr>
                  <th className="px-4 py-3 font-medium">CVE ID</th>
                  <th className="px-4 py-3 font-medium">SEVERITY</th>
                  <th className="px-4 py-3 font-medium text-right">CVSS</th>
                  <th className="px-4 py-3 font-medium">AGENT</th>
                  <th className="px-4 py-3 font-medium">PACKAGE</th>
                  <th className="px-4 py-3 font-medium">INSTALLED → FIXED</th>
                  <th className="px-4 py-3 font-medium">STATUS</th>
                  <th className="px-4 py-3 font-medium text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {vulns.map((v) => (
                  <tr key={v.id} className="hover:bg-white/[0.03] transition-colors">
                    <td className="px-4 py-3 text-[#FF4500]">{v.cveId}</td>
                    <td className="px-4 py-3">
                      <VChip
                        status={v.severity === 'critical' ? 'info' : v.severity === 'high' ? 'error' : 'warn'}
                        label={v.severity.toUpperCase()}
                      />
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-white">{v.cvssScore.toFixed(1)}</td>
                    <td className="px-4 py-3 text-gray-200">{v.agentName}</td>
                    <td className="px-4 py-3 text-gray-400">{v.packageName}</td>
                    <td className="px-4 py-3 text-gray-400">
                      {v.installedVersion} → <span className="text-emerald-400">{v.fixedVersion}</span>
                    </td>
                    <td className="px-4 py-3">
                      <VChip
                        status={v.status === 'patched' ? 'pass' : 'info'}
                        label={v.status === 'patched' ? 'PATCHED' : 'OPEN'}
                      />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => toggleStatus(v)}
                        disabled={role === 'auditor'}
                        className="btn-pill-glass px-3.5 py-1 text-xs disabled:opacity-40 whitespace-nowrap"
                      >
                        {v.status === 'open' ? 'Mark Patched' : 'Reopen'}
                      </button>
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
