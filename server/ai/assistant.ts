import { GoogleGenAI } from '@google/genai';
import { computeHealthScore, getAgents, getAlerts, getFimEvents, getIncidents, getVulnerabilities } from '../db/store.ts';

export interface AiQueryInput {
  question: string;
  incidentId?: string | null;
  history?: Array<{ role: 'user' | 'assistant'; content: string }>;
}

export async function runEvidenceGroundedInvestigation(input: AiQueryInput) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    throw new Error('GEMINI_API_KEY is not configured in environment secrets.');
  }

  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });

  const health = computeHealthScore();
  const incidents = getIncidents();
  const alerts = getAlerts(80);
  const agents = getAgents();
  const fim = getFimEvents().slice(0, 15);
  const vulns = getVulnerabilities().slice(0, 15);

  const focusedIncident = input.incidentId ? incidents.find((i) => i.id === input.incidentId) : null;
  const focusedAlerts = focusedIncident
    ? alerts.filter((a) => a.incidentId === focusedIncident.id)
    : alerts.slice(0, 20);

  const evidenceBundle = {
    securityHealth: health,
    focusedIncident: focusedIncident || null,
    activeIncidentsSummary: incidents.slice(0, 8).map((i) => ({
      id: i.id,
      title: i.title,
      severity: i.severity,
      status: i.status,
      agent: i.primaryAgentName,
      srcip: i.primarySrcip,
      user: i.primaryUser,
      mitreIds: i.mitreIds,
      alertCount: i.alertCount,
      firstSeen: i.firstSeen,
      lastSeen: i.lastSeen,
    })),
    evidenceAlerts: focusedAlerts.slice(0, 18).map((a) => ({
      id: a.id,
      timestamp: a.timestamp,
      ruleId: a.rule.id,
      level: a.rule.level,
      description: a.rule.description,
      mitre: a.rule.mitre,
      agent: a.agent.name,
      decoder: a.decoder.name,
      data: a.data,
      mlScore: a.ml.score,
      mlAnomaly: a.ml.isAnomaly,
      topMlDriver: a.ml.contributions[0]?.label,
      incidentId: a.incidentId,
    })),
    agents: agents.map((a) => ({
      id: a.id,
      name: a.name,
      ip: a.ip,
      os: a.os,
      status: a.status,
      memFreeMb: a.memFreeMb,
    })),
    recentFim: fim,
    openVulnerabilities: vulns.filter((v) => v.status === 'open'),
  };

  const systemInstruction = [
    'You are the AegisOne AI Security Analyst embedded inside the AegisOne SIEM/XDR platform.',
    'STRICT EVIDENCE GROUNDING RULE: Answer ONLY using the JSON telemetry evidence provided below from AegisOne Data Store.',
    'Always cite exact Alert IDs (e.g. ALT-...), Incident IDs (e.g. INC-...), Rule IDs, Agent hostnames, IP addresses, and MITRE ATT&CK technique IDs present in the evidence.',
    'If the user asks about an entity, IP, or event not present in the provided evidence bundle, explicitly state that no matching telemetry was found in AegisOne Data Store rather than guessing.',
    'Keep responses concise, structured, and actionable for a small IT/security team without a dedicated SOC.',
  ].join(' ');

  const conversationBlock = (input.history || [])
    .slice(-6)
    .map((m) => `${m.role === 'user' ? 'Analyst' : 'AegisOne AI'}: ${m.content}`)
    .join('\n');

  const prompt = `AEGISONE_DB_EVIDENCE:\n${JSON.stringify(evidenceBundle, null, 2)}\n\n${
    conversationBlock ? `PRIOR_CONVERSATION:\n${conversationBlock}\n\n` : ''
  }ANALYST_QUESTION: ${input.question}`;

  const response = await ai.models.generateContent({
    model: 'gemini-4-hydrogen',
    contents: prompt,
    config: {
      systemInstruction,
    },
  });

  const answer = response.text || 'Unable to generate an answer from the current telemetry context.';

  // Extract cited IDs present in the answer for clickable UI evidence chips
  const citedAlerts = focusedAlerts
    .filter((a) => answer.includes(a.id))
    .map((a) => ({ id: a.id, ruleId: a.rule.id, level: a.rule.level, agent: a.agent.name }));
  const citedIncidents = incidents
    .filter((i) => answer.includes(i.id))
    .map((i) => ({ id: i.id, title: i.title, severity: i.severity }));

  return {
    answer,
    citedAlerts,
    citedIncidents,
    evidenceAlertCount: focusedAlerts.length,
  };
}
