import React, { useState } from 'react';
import { ArrowRight, Upload } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { AegisAlert, RbacRole } from '../types/aegis';
import { SeverityLabel, VChip } from './SeverityTag';

const SCENARIOS = [
  {
    id: 'ssh_bruteforce',
    title: 'SSH Brute Force + Compromise',
    desc: 'Simulates 4 invalid-user SSH failures followed by a valid backup account login from 198.51.100.77.',
  },
  {
    id: 'sysmon_powershell',
    title: 'Windows Sysmon PowerShell + C2',
    desc: 'Ingests Sysmon EventID 1 encoded PowerShell execution and EventID 3 outbound C2 connection.',
  },
  {
    id: 'fim_tamper',
    title: 'Sudo Escalation + Critical FIM Tamper',
    desc: 'Simulates root usermod execution followed by unauthorized /etc/passwd SHA-256 modification.',
  },
  {
    id: 'docker_journald',
    title: 'Docker Exec + Journald Persistence',
    desc: 'Simulates interactive root container exec and systemd-journald rogue service persistence.',
  },
  {
    id: 'sibling_kv',
    title: 'Dynamic Sibling KV Telemetry',
    desc: 'Tests order-independent sibling decoder extraction across shifting attribute order.',
  },
];

export function IngestionView({
  role,
  onSelectAlert,
  onMutated,
}: {
  role: RbacRole;
  onSelectAlert: (alert: AegisAlert) => void;
  onMutated: () => void;
}) {
  const [agentName, setAgentName] = useState('web-gw-01');
  const [rawInput, setRawInput] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{
    ingestedLines: number;
    alertsGenerated: number;
    alerts: AegisAlert[];
  } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const handleIngest = async (linesText = rawInput) => {
    if (!linesText.trim()) return;
    setSubmitting(true);
    setErr(null);
    try {
      const res = await apiFetch<{
        ingestedLines: number;
        alertsGenerated: number;
        alerts: AegisAlert[];
      }>('/api/v1/ingest', {
        method: 'POST',
        body: JSON.stringify({ agentName, log: linesText }),
      });
      setResult(res);
      onMutated();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Ingestion failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setRawInput(text);
    await handleIngest(text);
  };

  const runScenario = async (scenarioId: string) => {
    setSubmitting(true);
    setErr(null);
    try {
      const res = await apiFetch<{
        ingestedLines: number;
        alertsGenerated: number;
        alerts: AegisAlert[];
      }>('/api/v1/ingest/simulate', {
        method: 'POST',
        body: JSON.stringify({ scenario: scenarioId }),
      });
      setResult(res);
      onMutated();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Simulation failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 space-y-5">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
            <Upload className="w-5 h-5 text-[#FF4500]" />
            <span>Web Log Uploader &amp; Ingestion Gateway</span>
          </h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Upload .log, .json, or .jsonl telemetry datasets or paste raw lines to run live decoding, rule evaluation, Isolation Forest scoring, and incident correlation.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-mono text-gray-400 mb-2">TARGET AGENT</label>
            <select
              value={agentName}
              onChange={(e) => setAgentName(e.target.value)}
              className="w-full px-4 py-2.5 rounded-full bg-[#050505] border border-white/10 text-xs font-mono text-white focus:outline-none focus:border-[#FF4500]"
            >
              <option value="web-gw-01">web-gw-01 (10.10.1.10)</option>
              <option value="auth-sso-01">auth-sso-01 (10.10.2.15)</option>
              <option value="db-postgres-01">db-postgres-01 (10.10.3.22)</option>
              <option value="docker-app-02">docker-app-02 (10.10.4.31)</option>
              <option value="win-finance-04">win-finance-04 (10.10.5.44)</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-xs font-mono text-gray-400 mb-2">UPLOAD LOG / JSONL FILE</label>
            <input
              type="file"
              accept=".log,.txt,.json,.jsonl"
              disabled={role === 'auditor' || submitting}
              onChange={handleFileUpload}
              className="block w-full text-xs font-mono text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border file:border-white/15 file:text-xs file:font-medium file:bg-[#050505] file:text-white hover:file:bg-white/10"
            />
          </div>
        </div>

        <textarea
          rows={5}
          value={rawInput}
          onChange={(e) => setRawInput(e.target.value)}
          placeholder="Paste multi-line syslog, systemd-journald JSON, Windows Sysmon JSON, or nginx access logs..."
          className="w-full p-4 rounded-2xl bg-[#050505] border border-white/10 focus:border-[#FF4500] text-xs font-mono text-white placeholder:text-gray-500 focus:outline-none"
        />

        <div className="flex flex-wrap items-center justify-between gap-4">
          <span className="text-xs font-mono text-gray-400">GATEWAY: POST /api/v1/ingest</span>
          <button
            onClick={() => handleIngest()}
            disabled={role === 'auditor' || submitting || !rawInput.trim()}
            className="btn-pill-primary inline-flex items-center gap-1.5 px-6 py-2.5 text-xs disabled:opacity-40 whitespace-nowrap"
          >
            <span>{submitting ? 'Ingesting...' : 'Ingest & Analyze'}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </section>

      {err && (
        <div className="p-3.5 rounded-2xl bg-[#FF4500]/10 border border-[#FF4500]/40 text-xs font-mono text-[#ffe0e0]">
          {err}
        </div>
      )}

      <section className="obsidian-card p-6 md:p-8 space-y-5">
        <div>
          <h3 className="font-serif-display text-xl font-medium text-white">Live Multi-Source Telemetry Simulators</h3>
          <p className="text-xs font-mono text-gray-400 mt-1">
            Inject authentic attack and behavioral scenarios directly into the ingestion gateway.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {SCENARIOS.map((sc) => (
            <div
              key={sc.id}
              className="p-5 rounded-2xl bg-[#050505] border border-white/10 hover:border-[#FF4500]/50 transition-colors flex flex-col justify-between gap-4"
            >
              <div>
                <div className="text-sm font-medium text-white">{sc.title}</div>
                <div className="mt-2 text-xs text-gray-400 leading-relaxed">{sc.desc}</div>
              </div>
              <button
                onClick={() => runScenario(sc.id)}
                disabled={role === 'auditor' || submitting}
                className="btn-pill-glass inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs disabled:opacity-40 whitespace-nowrap"
              >
                <span>Inject Scenario</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      </section>

      {result && (
        <section className="obsidian-card overflow-hidden">
          <div className="px-6 py-3.5 border-b border-white/10 flex items-center gap-3">
            <VChip status="pass" label={`INGESTED ${result.ingestedLines} LINES`} />
            <VChip status="info" label={`${result.alertsGenerated} ALERTS CREATED`} />
          </div>
          <div className="divide-y divide-white/5">
            {result.alerts.map((a) => (
              <div
                key={a.id}
                onClick={() => onSelectAlert(a)}
                className="px-6 py-3.5 hover:bg-white/[0.03] cursor-pointer flex items-center justify-between gap-4 text-xs font-mono transition-colors"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <SeverityLabel level={a.rule.level} />
                    <span className="text-gray-400">#{a.rule.id}</span>
                    <span className="text-white">{a.agent.name}</span>
                  </div>
                  <div className="mt-1.5 text-gray-200 truncate">{a.rule.description}</div>
                </div>
                <span className="text-[#FF4500] tabular-nums shrink-0">ML {a.ml.score.toFixed(3)}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
