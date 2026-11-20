import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import type {
  AegisAlert,
  AgentRecord,
  ArchiveEntry,
  FimEvent,
  HealthScoreBreakdown,
  IncidentRecord,
  RbacRole,
  VulnerabilityRecord,
} from '../types.ts';
import { loadAegisConfig } from '../engine/config.ts';
import { decodeLog } from '../engine/decoder.ts';
import { evaluateRules } from '../engine/rules.ts';
import { extractBehavioralVector, isolationForest } from '../ml/isolationForest.ts';

const DATA_DIR = path.join(process.cwd(), 'data');
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
fs.mkdirSync(ARCHIVE_DIR, { recursive: true });

export const db = new DatabaseSync(path.join(DATA_DIR, 'aegisone.db'));

export function initDatabaseSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      ip TEXT NOT NULL,
      os TEXT NOT NULL,
      version TEXT NOT NULL,
      group_name TEXT NOT NULL,
      status TEXT NOT NULL,
      last_keepalive TEXT NOT NULL,
      cpu_pct REAL NOT NULL,
      mem_free_mb INTEGER NOT NULL,
      mem_total_mb INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      rule_level INTEGER NOT NULL,
      rule_description TEXT NOT NULL,
      mitre_id TEXT,
      mitre_tactic TEXT,
      agent_id TEXT NOT NULL,
      agent_name TEXT NOT NULL,
      decoder_name TEXT NOT NULL,
      srcip TEXT,
      srcuser TEXT,
      ml_score REAL NOT NULL,
      ml_anomaly INTEGER NOT NULL,
      incident_id TEXT,
      raw_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL,
      confidence REAL NOT NULL,
      risk_impact INTEGER NOT NULL,
      primary_agent_id TEXT NOT NULL,
      primary_agent_name TEXT NOT NULL,
      primary_srcip TEXT,
      primary_user TEXT,
      mitre_tactics TEXT NOT NULL,
      mitre_ids TEXT NOT NULL,
      alert_count INTEGER NOT NULL,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      summary TEXT NOT NULL,
      recommended_actions TEXT NOT NULL,
      assigned_to TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS fim_events (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      agent_name TEXT NOT NULL,
      action TEXT NOT NULL,
      path TEXT NOT NULL,
      uid TEXT NOT NULL,
      sha256_before TEXT NOT NULL,
      sha256_after TEXT NOT NULL,
      severity INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      cve_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      agent_name TEXT NOT NULL,
      package_name TEXT NOT NULL,
      installed_version TEXT NOT NULL,
      fixed_version TEXT NOT NULL,
      cvss_score REAL NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL,
      detected_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS archives (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      agent_name TEXT NOT NULL,
      program_name TEXT NOT NULL,
      raw_log TEXT NOT NULL,
      decoded_json TEXT NOT NULL,
      alerted INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      role TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      details TEXT NOT NULL
    );
  `);
}

export function getAgents(): AgentRecord[] {
  const rows = db.prepare('SELECT * FROM agents ORDER BY name ASC').all() as Record<string, unknown>[];
  return rows.map((r) => ({
    id: String(r.id),
    name: String(r.name),
    ip: String(r.ip),
    os: String(r.os),
    version: String(r.version),
    groupName: String(r.group_name),
    status: r.status as AgentRecord['status'],
    lastKeepAlive: String(r.last_keepalive),
    cpuPct: Number(r.cpu_pct),
    memFreeMb: Number(r.mem_free_mb),
    memTotalMb: Number(r.mem_total_mb),
  }));
}

export function getAlerts(limit = 500): AegisAlert[] {
  const rows = db.prepare('SELECT raw_json FROM alerts ORDER BY timestamp DESC LIMIT ?').all(limit) as { raw_json: string }[];
  return rows.map((r) => JSON.parse(r.raw_json) as AegisAlert);
}

export function getIncidents(): IncidentRecord[] {
  const rows = db.prepare('SELECT * FROM incidents ORDER BY last_seen DESC').all() as Record<string, unknown>[];
  return rows.map((r) => ({
    id: String(r.id),
    title: String(r.title),
    severity: r.severity as IncidentRecord['severity'],
    status: r.status as IncidentRecord['status'],
    confidence: Number(r.confidence),
    riskImpact: Number(r.risk_impact),
    primaryAgentId: String(r.primary_agent_id),
    primaryAgentName: String(r.primary_agent_name),
    primarySrcip: r.primary_srcip ? String(r.primary_srcip) : null,
    primaryUser: r.primary_user ? String(r.primary_user) : null,
    mitreTactics: JSON.parse(String(r.mitre_tactics)) as string[],
    mitreIds: JSON.parse(String(r.mitre_ids)) as string[],
    alertCount: Number(r.alert_count),
    firstSeen: String(r.first_seen),
    lastSeen: String(r.last_seen),
    summary: String(r.summary),
    recommendedActions: JSON.parse(String(r.recommended_actions)) as string[],
    assignedTo: String(r.assigned_to),
  }));
}

export function getFimEvents(): FimEvent[] {
  const rows = db.prepare('SELECT * FROM fim_events ORDER BY timestamp DESC LIMIT 200').all() as Record<string, unknown>[];
  return rows.map((r) => ({
    id: String(r.id),
    timestamp: String(r.timestamp),
    agentId: String(r.agent_id),
    agentName: String(r.agent_name),
    action: r.action as FimEvent['action'],
    path: String(r.path),
    uid: String(r.uid),
    sha256Before: String(r.sha256_before),
    sha256After: String(r.sha256_after),
    severity: Number(r.severity),
  }));
}

export function getVulnerabilities(): VulnerabilityRecord[] {
  const rows = db.prepare('SELECT * FROM vulnerabilities ORDER BY cvss_score DESC').all() as Record<string, unknown>[];
  return rows.map((r) => ({
    id: String(r.id),
    cveId: String(r.cve_id),
    agentId: String(r.agent_id),
    agentName: String(r.agent_name),
    packageName: String(r.package_name),
    installedVersion: String(r.installed_version),
    fixedVersion: String(r.fixed_version),
    cvssScore: Number(r.cvss_score),
    severity: r.severity as VulnerabilityRecord['severity'],
    status: r.status as VulnerabilityRecord['status'],
    detectedAt: String(r.detected_at),
  }));
}

export function getArchives(limit = 200): ArchiveEntry[] {
  const rows = db.prepare('SELECT * FROM archives ORDER BY timestamp DESC LIMIT ?').all(limit) as Record<string, unknown>[];
  return rows.map((r) => ({
    id: String(r.id),
    timestamp: String(r.timestamp),
    agentName: String(r.agent_name),
    programName: String(r.program_name),
    rawLog: String(r.raw_log),
    decodedJson: String(r.decoded_json),
    alerted: Boolean(r.alerted),
  }));
}

export function appendAuditLog(role: RbacRole, action: string, target: string, details: string) {
  db.prepare(
    'INSERT INTO audit_logs (id, timestamp, role, action, target, details) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(`AUD-${crypto.randomBytes(3).toString('hex').toUpperCase()}`, new Date().toISOString(), role, action, target, details);
}

export function getAuditLogs() {
  return db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100').all();
}

function appendGzipArchive(rawLine: string, archiveObj: Record<string, unknown>, logall: boolean, logallJson: boolean) {
  if (logall) {
    const gzPath = path.join(ARCHIVE_DIR, 'archives.log.gz');
    const existing = fs.existsSync(gzPath) ? zlib.gunzipSync(fs.readFileSync(gzPath)).toString('utf8') : '';
    const updated = `${existing}${rawLine}\n`;
    fs.writeFileSync(gzPath, zlib.gzipSync(Buffer.from(updated, 'utf8')));
  }
  if (logallJson) {
    const gzJsonPath = path.join(ARCHIVE_DIR, 'archives.json.gz');
    const existing = fs.existsSync(gzJsonPath) ? zlib.gunzipSync(fs.readFileSync(gzJsonPath)).toString('utf8') : '';
    const updated = `${existing}${JSON.stringify(archiveObj)}\n`;
    fs.writeFileSync(gzJsonPath, zlib.gzipSync(Buffer.from(updated, 'utf8')));
  }
}

export function getArchiveStorageStats() {
  const logGz = path.join(ARCHIVE_DIR, 'archives.log.gz');
  const jsonGz = path.join(ARCHIVE_DIR, 'archives.json.gz');
  return {
    logGzBytes: fs.existsSync(logGz) ? fs.statSync(logGz).size : 0,
    jsonGzBytes: fs.existsSync(jsonGz) ? fs.statSync(jsonGz).size : 0,
    totalArchivedRows: (db.prepare('SELECT COUNT(*) as c FROM archives').get() as { c: number }).c,
  };
}

function severityLabelFromLevel(level: number): IncidentRecord['severity'] {
  if (level >= 12) return 'critical';
  if (level >= 9) return 'high';
  if (level >= 6) return 'medium';
  return 'low';
}

function recommendActionsForRule(ruleId: string, srcip: string | null, mitreId?: string): string[] {
  if (ruleId === '5712' || ruleId === '5720' || mitreId?.startsWith('T1110')) {
    return [
      `Block offending external IP ${srcip || 'source'} at edge firewall / fail2ban`,
      'Audit /var/log/auth.log for any post-brute-force Accepted login',
      'Enforce SSH key-only authentication and disable root SSH login',
    ];
  }
  if (ruleId === '554' || ruleId === '550') {
    return [
      'Inspect unauthorized file diff against golden configuration baseline',
      'Rotate compromised SSH keys or credentials immediately',
      'Isolate host via AegisOne Agent quarantine if tamper is unapproved',
    ];
  }
  if (ruleId === '61603' || ruleId === '61605') {
    return [
      'Terminate suspicious PowerShell process tree and capture volatile memory',
      'Block destination C2 IP on outbound egress filter',
      'Scan endpoint for scheduled tasks or registry run-key persistence',
    ];
  }
  return [
    'Review correlated alert timeline and verify user authorization',
    'Cross-check agent FIM and active vulnerability posture',
    'Escalate to containment if activity matches lateral movement',
  ];
}

export function retrainIsolationForestFromStore() {
  const existing = getAlerts(400);
  if (existing.length < 10) return { trainedSamples: 0 };
  const cfg = loadAegisConfig();
  const vectors = existing.map((a) => a.ml.featureVector);
  // Anchor with nominal baseline samples so small labs still isolate high-deviation vectors cleanly
  const anchoredVectors = [...vectors];
  for (let i = 0; i < 80; i++) {
    anchoredVectors.push([
      0.08 + Math.random() * 0.2,
      0.05 + Math.random() * 0.16,
      0.12 + Math.random() * 0.08,
      Math.random() * 0.06,
      0.04 + Math.random() * 0.06,
      0.05 + Math.random() * 0.1,
      0.08 + Math.random() * 0.1,
    ]);
  }
  isolationForest.fit(anchoredVectors, cfg.mlNumTrees, Math.min(cfg.mlSubsampleSize, anchoredVectors.length), cfg.mlAnomalyThreshold);

  const upd = db.prepare('UPDATE alerts SET ml_score = ?, ml_anomaly = ?, raw_json = ? WHERE id = ?');
  for (const a of existing) {
    const rescored = isolationForest.score(a.ml.featureVector);
    const updatedAlert: AegisAlert = { ...a, ml: rescored };
    upd.run(rescored.score, rescored.isAnomaly ? 1 : 0, JSON.stringify(updatedAlert), a.id);
  }
  return { trainedSamples: anchoredVectors.length };
}

/**
 * Full end-to-end ingestion pipeline:
 * 1. Two-phase XML Decode
 * 2. Deterministic 0-16 Rule Engine
 * 3. Archive logall / logall_json (if enabled)
 * 4. Isolation Forest behavioral scoring
 * 5. Incident Correlation
 */
export function ingestTelemetryLine(
  rawLine: string,
  agentHint?: string,
  overrideTimestamp?: string
): { alert: AegisAlert | null; archived: boolean } {
  const cfg = loadAegisConfig();
  const trace = decodeLog(rawLine, agentHint || 'web-gw-01');
  if (overrideTimestamp) {
    trace.phase1.timestamp = overrideTimestamp;
  }

  // Resolve Agent
  const agents = getAgents();
  const matchedAgent =
    agents.find((a) => a.name.toLowerCase() === trace.phase1.hostname.toLowerCase()) ||
    agents.find((a) => a.name.toLowerCase() === (agentHint || '').toLowerCase()) ||
    agents[0] || {
      id: '001',
      name: trace.phase1.hostname,
      ip: '10.10.1.10',
    };

  const eventTs = trace.phase1.timestamp || new Date().toISOString();
  const eventMs = Date.parse(eventTs) || Date.now();
  const rule = evaluateRules(trace, rawLine, eventMs);
  const willAlert = rule.level > 0;

  // Archive if logall or logallJson enabled
  let archived = false;
  if (cfg.logall || cfg.logallJson) {
    const archId = `ARC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    db.prepare(
      'INSERT INTO archives (id, timestamp, agent_name, program_name, raw_log, decoded_json, alerted) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(
      archId,
      eventTs,
      matchedAgent.name,
      trace.phase1.programName,
      rawLine,
      JSON.stringify(trace.phase2.extractedFields),
      willAlert ? 1 : 0
    );
    appendGzipArchive(
      rawLine,
      {
        id: archId,
        timestamp: eventTs,
        agent: matchedAgent.name,
        program: trace.phase1.programName,
        decoded: trace.phase2.extractedFields,
        rule_level: rule.level,
      },
      cfg.logall,
      cfg.logallJson
    );
    archived = true;
  }

  if (!willAlert) {
    return { alert: null, archived };
  }

  // Compute Behavioral Feature Context from recent alerts on this agent
  const recentRows = db
    .prepare('SELECT srcip, rule_id FROM alerts WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 30')
    .all(matchedAgent.id) as { srcip: string | null; rule_id: string }[];

  const uniqueIps = new Set(recentRows.map((r) => r.srcip).filter(Boolean));
  if (trace.phase2.extractedFields.srcip) uniqueIps.add(String(trace.phase2.extractedFields.srcip));
  const failedCount = recentRows.filter((r) => ['5710', '5716', '5712', '5720', '100010'].includes(r.rule_id)).length;
  const knownInternalIps = new Set(agents.map((a) => a.ip));

  const vec = extractBehavioralVector({
    timestamp: eventTs,
    ruleLevel: rule.level,
    fields: trace.phase2.extractedFields,
    rawLog: rawLine,
    recentAgentEventsCount: recentRows.length + 1,
    recentUniqueIpsForAgent: uniqueIps.size,
    recentFailedAuthRatio: recentRows.length > 0 ? failedCount / recentRows.length : rule.level >= 5 ? 0.5 : 0.05,
    knownInternalIps,
  });
  const ml = isolationForest.score(vec);

  // Correlate Incident if high severity or behavioral anomaly
  let incidentId: string | null = null;
  const srcip = trace.phase2.extractedFields.srcip ? String(trace.phase2.extractedFields.srcip) : null;
  const srcuser = trace.phase2.extractedFields.srcuser
    ? String(trace.phase2.extractedFields.srcuser)
    : trace.phase2.extractedFields.user
      ? String(trace.phase2.extractedFields.user)
      : null;

  if (cfg.autoCorrelateIncidents && (rule.level >= 7 || ml.isAnomaly)) {
    const openIncidents = getIncidents().filter((i) => i.status !== 'resolved');
    const existing = openIncidents.find(
      (inc) =>
        (srcip && inc.primarySrcip === srcip) ||
        (inc.primaryAgentId === matchedAgent.id && (!srcuser || inc.primaryUser === srcuser || !inc.primaryUser))
    );

    if (existing) {
      incidentId = existing.id;
      const tactics = Array.from(new Set([...existing.mitreTactics, ...(rule.mitre ? [rule.mitre.tactic] : [])]));
      const ids = Array.from(new Set([...existing.mitreIds, ...(rule.mitre ? [rule.mitre.id] : [])]));
      const newSev =
        rule.level >= 12 || existing.severity === 'critical'
          ? 'critical'
          : rule.level >= 9 || existing.severity === 'high'
            ? 'high'
            : existing.severity;

      db.prepare(
        `UPDATE incidents SET
          alert_count = alert_count + 1,
          last_seen = ?,
          severity = ?,
          mitre_tactics = ?,
          mitre_ids = ?,
          confidence = ?,
          risk_impact = ?
        WHERE id = ?`
      ).run(
        eventTs > existing.lastSeen ? eventTs : existing.lastSeen,
        newSev,
        JSON.stringify(tactics),
        JSON.stringify(ids),
        Math.min(0.99, Number((Math.max(existing.confidence, ml.score) + 0.04).toFixed(2))),
        Math.min(100, Math.max(existing.riskImpact, Math.round(rule.level * 5.2 + ml.score * 20))),
        existing.id
      );
    } else {
      incidentId = `INC-${String(Math.floor(1000 + Math.random() * 8999))}`;
      const sev = severityLabelFromLevel(Math.max(rule.level, ml.isAnomaly ? 9 : rule.level));
      db.prepare(
        `INSERT INTO incidents (
          id, title, severity, status, confidence, risk_impact,
          primary_agent_id, primary_agent_name, primary_srcip, primary_user,
          mitre_tactics, mitre_ids, alert_count, first_seen, last_seen,
          summary, recommended_actions, assigned_to
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        incidentId,
        `${rule.description.replace(/\.$/, '')} on ${matchedAgent.name}`,
        sev,
        'open',
        Number(Math.max(0.72, ml.score).toFixed(2)),
        Math.min(100, Math.round(rule.level * 5.5 + ml.score * 22)),
        matchedAgent.id,
        matchedAgent.name,
        srcip,
        srcuser,
        JSON.stringify(rule.mitre ? [rule.mitre.tactic] : ['Discovery']),
        JSON.stringify(rule.mitre ? [rule.mitre.id] : []),
        1,
        eventTs,
        eventTs,
        `Correlated telemetry from ${matchedAgent.name}${srcip ? ` originating from ${srcip}` : ''}. Triggered Rule ${rule.id} (Level ${rule.level}) with Isolation Forest score ${ml.score}.`,
        JSON.stringify(recommendActionsForRule(rule.id, srcip, rule.mitre?.id)),
        'Kushagra Sen (SOC Lead)'
      );
    }
  }

  // Record FIM event if decoded as FIM
  if (trace.phase2.effectiveDecoderName === 'aegisone-fim' && trace.phase2.extractedFields.url) {
    db.prepare(
      `INSERT INTO fim_events (id, timestamp, agent_id, agent_name, action, path, uid, sha256_before, sha256_after, severity)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      `FIM-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
      eventTs,
      matchedAgent.id,
      matchedAgent.name,
      String(trace.phase2.extractedFields.action || 'modified'),
      String(trace.phase2.extractedFields.url),
      String(trace.phase2.extractedFields.user || '0'),
      String(trace.phase2.extractedFields.data || 'none'),
      String(trace.phase2.extractedFields.extra_data || 'none'),
      rule.level
    );
  }

  // Record MemFree / Agent telemetry update if aegisone-command
  if (trace.phase2.effectiveDecoderName === 'aegisone-command' && trace.phase2.extractedFields.id === 'MemFree') {
    const mb = Number(trace.phase2.extractedFields.data);
    if (!Number.isNaN(mb)) {
      db.prepare('UPDATE agents SET mem_free_mb = ?, last_keepalive = ? WHERE id = ?').run(mb, eventTs, matchedAgent.id);
    }
  }

  const alertId = `ALT-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  const alert: AegisAlert = {
    id: alertId,
    timestamp: eventTs,
    rule,
    agent: {
      id: matchedAgent.id,
      name: matchedAgent.name,
      ip: matchedAgent.ip,
    },
    decoder: {
      name: trace.phase2.effectiveDecoderName,
      parent: trace.phase2.parentDecoder,
    },
    data: trace.phase2.extractedFields,
    ml,
    incidentId,
    location: `${trace.phase1.format}:${trace.phase1.programName}`,
    full_log: rawLine,
  };

  db.prepare(
    `INSERT INTO alerts (
      id, timestamp, rule_id, rule_level, rule_description, mitre_id, mitre_tactic,
      agent_id, agent_name, decoder_name, srcip, srcuser, ml_score, ml_anomaly, incident_id, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    alert.id,
    alert.timestamp,
    alert.rule.id,
    alert.rule.level,
    alert.rule.description,
    alert.rule.mitre?.id || null,
    alert.rule.mitre?.tactic || null,
    alert.agent.id,
    alert.agent.name,
    alert.decoder.name,
    srcip,
    srcuser,
    alert.ml.score,
    alert.ml.isAnomaly ? 1 : 0,
    alert.incidentId,
    JSON.stringify(alert)
  );

  return { alert, archived };
}

/**
 * Computes AegisOne's transparent Composite 0–100 Risk/Security Health Score
 */
export function computeHealthScore(): HealthScoreBreakdown {
  const incidents = getIncidents();
  const alerts = getAlerts(200);
  const agents = getAgents();
  const fim = getFimEvents();
  const vulns = getVulnerabilities();

  const openIncidents = incidents.filter((i) => i.status !== 'resolved');
  const openCriticalIncidents = openIncidents.filter((i) => i.severity === 'critical').length;
  const openHighIncidents = openIncidents.filter((i) => i.severity === 'high').length;
  const openMediumIncidents = openIncidents.filter((i) => i.severity === 'medium').length;

  // Pillar 1 (max 42 pts penalty): Open Incident Severity Density
  const incidentSeverityPenalty = Math.min(
    42,
    openCriticalIncidents * 14 + openHighIncidents * 8 + openMediumIncidents * 4
  );

  // Pillar 2 (max 24 pts penalty): Behavioral Isolation Forest Anomaly Index
  const avgMlScore = alerts.length > 0 ? alerts.reduce((s, a) => s + a.ml.score, 0) / alerts.length : 0.25;
  const anomalyCount = alerts.filter((a) => a.ml.isAnomaly).length;
  const anomalyRatePct = alerts.length > 0 ? Math.round((anomalyCount / alerts.length) * 100) : 0;
  const behavioralAnomalyPenalty = Math.min(24, Math.round(avgMlScore * 20 + anomalyRatePct * 0.35));

  // Pillar 3 (max 18 pts penalty): Endpoint Posture & Critical FIM Drift
  const offlineAgents = agents.filter((a) => a.status !== 'active').length;
  const criticalFimChanges = fim.filter((f) => f.severity >= 10).length;
  const endpointAndFimPenalty = Math.min(18, offlineAgents * 6 + criticalFimChanges * 4);

  // Pillar 4 (max 16 pts penalty): Unpatched Critical/High CVEs
  const openVulns = vulns.filter((v) => v.status === 'open');
  const criticalCves = openVulns.filter((v) => v.severity === 'critical').length;
  const highCves = openVulns.filter((v) => v.severity === 'high').length;
  const vulnerabilityPenalty = Math.min(16, criticalCves * 4 + highCves * 2);

  const totalPenalty =
    incidentSeverityPenalty + behavioralAnomalyPenalty + endpointAndFimPenalty + vulnerabilityPenalty;
  const healthScore = Math.max(0, Math.min(100, 100 - totalPenalty));
  const riskExposure = 100 - healthScore;

  const grade: HealthScoreBreakdown['grade'] =
    healthScore >= 85 ? 'Optimal' : healthScore >= 65 ? 'Guarded' : healthScore >= 40 ? 'Elevated' : 'Critical';

  return {
    healthScore,
    riskExposure,
    grade,
    pillars: {
      incidentSeverityPenalty,
      behavioralAnomalyPenalty,
      endpointAndFimPenalty,
      vulnerabilityPenalty,
    },
    metrics: {
      openCriticalIncidents,
      openHighIncidents,
      openMediumIncidents,
      avgMlScore: Number(avgMlScore.toFixed(3)),
      anomalyRatePct,
      offlineAgents,
      criticalFimChanges,
      criticalCves,
    },
  };
}
