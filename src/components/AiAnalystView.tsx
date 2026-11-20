import React, { useEffect, useState } from 'react';
import { ArrowRight, Bot, ShieldCheck } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { IncidentRecord } from '../types/aegis';
import { VChip } from './SeverityTag';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  citedAlerts?: Array<{ id: string; ruleId: string; level: number; agent: string }>;
  citedIncidents?: Array<{ id: string; title: string; severity: string }>;
}

const SUGGESTED_PROMPTS = [
  'Summarize the active critical incidents, root cause IP addresses, and immediate containment actions.',
  'Which endpoints show behavioral anomalies in Isolation Forest and what features drove those scores?',
  'Trace the full attack sequence on web-gw-01 including brute force, login, sudo, and FIM changes.',
  'Which unpatched CVEs currently pose the highest risk to our active agents?',
];

export function AiAnalystView({
  initialIncidentId,
  onSelectAlertById,
}: {
  initialIncidentId?: string | null;
  onSelectAlertById: (alertId: string) => void;
}) {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [incidentId, setIncidentId] = useState<string>(initialIncidentId || '');
  const [question, setQuestion] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<{ incidents: IncidentRecord[] }>('/api/v1/incidents').then((res) => {
      setIncidents(res.incidents);
    });
  }, []);

  useEffect(() => {
    if (initialIncidentId) setIncidentId(initialIncidentId);
  }, [initialIncidentId]);

  const sendQuestion = async (qText: string) => {
    const trimmed = qText.trim();
    if (!trimmed || loading) return;

    setError(null);
    const nextHistory: ChatMessage[] = [...messages, { role: 'user', content: trimmed }];
    setMessages(nextHistory);
    setQuestion('');
    setLoading(true);

    try {
      const res = await apiFetch<{
        answer: string;
        citedAlerts: Array<{ id: string; ruleId: string; level: number; agent: string }>;
        citedIncidents: Array<{ id: string; title: string; severity: string }>;
      }>('/api/v1/ai/investigate', {
        method: 'POST',
        body: JSON.stringify({
          question: trimmed,
          incidentId: incidentId || null,
          history: messages.map((m) => ({ role: m.role, content: m.content })),
        }),
      });

      setMessages([
        ...nextHistory,
        {
          role: 'assistant',
          content: res.answer,
          citedAlerts: res.citedAlerts,
          citedIncidents: res.citedIncidents,
        },
      ]);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'AI investigation failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <section className="obsidian-card p-6 md:p-8 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="headline-editorial text-2xl sm:text-3xl text-white flex items-center gap-2.5">
            <Bot className="w-5 h-5 text-[#FF4500]" />
            <span>AegisOne Evidence-Grounded AI Analyst</span>
          </h2>
          <p className="text-xs font-mono text-gray-400 mt-1.5 flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span>Strictly grounded in live SQLite alerts, incidents, FIM events, and Isolation Forest scores.</span>
          </p>
        </div>

        <select
          value={incidentId}
          onChange={(e) => setIncidentId(e.target.value)}
          className="px-4 py-2.5 rounded-full bg-[#050505] border border-white/10 text-xs font-mono text-white focus:outline-none focus:border-[#FF4500]"
        >
          <option value="">SCOPE: ENTIRE FLEET &amp; ALL INCIDENTS</option>
          {incidents.map((inc) => (
            <option key={inc.id} value={inc.id}>
              FOCUS: {inc.id} — {inc.title}
            </option>
          ))}
        </select>
      </section>

      <section className="obsidian-card overflow-hidden flex flex-col min-h-[460px] max-h-[65vh]">
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.length === 0 && (
            <div className="space-y-4 py-4">
              <div className="text-xs font-mono text-gray-400">
                SELECT AN EVIDENCE-BACKED INVESTIGATION PROMPT OR ASK A QUESTION BELOW:
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {SUGGESTED_PROMPTS.map((p) => (
                  <button
                    key={p}
                    onClick={() => sendQuestion(p)}
                    className="text-left p-5 rounded-2xl bg-[#050505] hover:bg-white/[0.04] border border-white/10 hover:border-[#FF4500]/60 text-xs text-gray-200 transition-colors leading-relaxed"
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((m, idx) => (
            <div
              key={idx}
              className={`p-5 rounded-2xl border ${
                m.role === 'user'
                  ? 'bg-white/[0.04] border-[#FF4500]/50 ml-8'
                  : 'bg-[#050505] border-white/10 mr-8'
              }`}
            >
              <div className="mb-2.5">
                <VChip status={m.role === 'user' ? 'info' : 'pass'} label={m.role === 'user' ? 'ANALYST' : 'AEGISONE AI'} />
              </div>
              <div className="text-xs text-gray-200 whitespace-pre-wrap leading-relaxed">{m.content}</div>

              {m.citedAlerts && m.citedAlerts.length > 0 && (
                <div className="mt-4 pt-3 border-t border-white/10 flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-mono text-gray-400">CITED EVIDENCE:</span>
                  {m.citedAlerts.map((c) => (
                    <button
                      key={c.id}
                      onClick={() => onSelectAlertById(c.id)}
                      className="btn-pill-glass px-3 py-1 text-[11px] font-mono text-[#ffe0e0]"
                    >
                      {c.id} (R{c.ruleId} · L{c.level})
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="p-4 rounded-2xl bg-[#050505] border border-white/10 mr-8 text-xs font-mono text-gray-400">
              QUERYING AEGISONE DATA STORE EVIDENCE AND SYNTHESIZING RESPONSE...
            </div>
          )}
        </div>

        {error && (
          <div className="mx-6 mb-3 p-3.5 rounded-2xl bg-[#FF4500]/10 border border-[#FF4500]/40 text-xs font-mono text-[#ffe0e0]">
            {error}
          </div>
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendQuestion(question);
          }}
          className="p-4 border-t border-white/10 flex items-center gap-3 bg-[#050505]"
        >
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask about correlated alerts, source IPs, MITRE tactics, or remediation steps..."
            className="flex-1 px-4 py-2.5 rounded-full bg-[#111111] border border-white/10 focus:border-[#FF4500] text-xs font-mono text-white placeholder:text-gray-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading || !question.trim()}
            className="btn-pill-primary inline-flex items-center gap-1.5 px-5 py-2.5 text-xs disabled:opacity-40 whitespace-nowrap"
          >
            <span>Analyze</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </form>
      </section>
    </div>
  );
}
