export type RbacRole = 'admin' | 'analyst' | 'auditor';

export type NavSectionId =
  | 'overview'
  | 'discover'
  | 'storyline'
  | 'archives'
  | 'agents'
  | 'fim'
  | 'vulnerabilities'
  | 'incidents'
  | 'ml'
  | 'ai'
  | 'sandbox'
  | 'ingestion'
  | 'config'
  | 'reports';

export interface MlFeatureContribution {
  feature: string;
  label: string;
  value: number;
  baselineMedian: number;
  contributionPct: number;
}

export interface AegisAlert {
  id: string;
  timestamp: string;
  rule: {
    id: string;
    level: number;
    description: string;
    groups: string[];
    firedtimes: number;
    mitre?: {
      id: string;
      tactic: string;
    };
  };
  agent: {
    id: string;
    name: string;
    ip: string;
  };
  decoder: {
    name: string;
    parent: string | null;
  };
  data: Record<string, string | number | boolean | undefined>;
  ml: {
    score: number;
    isAnomaly: boolean;
    avgPathLength: number;
    expectedPathLength: number;
    contributions: MlFeatureContribution[];
    featureVector: number[];
  };
  incidentId: string | null;
  location: string;
  full_log: string;
}

export interface IncidentRecord {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  confidence: number;
  riskImpact: number;
  primaryAgentId: string;
  primaryAgentName: string;
  primarySrcip: string | null;
  primaryUser: string | null;
  mitreTactics: string[];
  mitreIds: string[];
  alertCount: number;
  firstSeen: string;
  lastSeen: string;
  summary: string;
  recommendedActions: string[];
  assignedTo: string;
}

export interface AgentRecord {
  id: string;
  name: string;
  ip: string;
  os: string;
  version: string;
  groupName: string;
  status: 'active' | 'disconnected' | 'pending';
  lastKeepAlive: string;
  cpuPct: number;
  memFreeMb: number;
  memTotalMb: number;
}

export interface FimEvent {
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  action: 'added' | 'modified' | 'deleted';
  path: string;
  uid: string;
  sha256Before: string;
  sha256After: string;
  severity: number;
}

export interface VulnerabilityRecord {
  id: string;
  cveId: string;
  agentId: string;
  agentName: string;
  packageName: string;
  installedVersion: string;
  fixedVersion: string;
  cvssScore: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'patched';
  detectedAt: string;
}

export interface ArchiveEntry {
  id: string;
  timestamp: string;
  agentName: string;
  programName: string;
  rawLog: string;
  decodedJson: string;
  alerted: boolean;
}

export interface HealthScoreBreakdown {
  healthScore: number;
  riskExposure: number;
  grade: 'Optimal' | 'Guarded' | 'Elevated' | 'Critical';
  pillars: {
    incidentSeverityPenalty: number;
    behavioralAnomalyPenalty: number;
    endpointAndFimPenalty: number;
    vulnerabilityPenalty: number;
  };
  metrics: {
    openCriticalIncidents: number;
    openHighIncidents: number;
    openMediumIncidents: number;
    avgMlScore: number;
    anomalyRatePct: number;
    offlineAgents: number;
    criticalFimChanges: number;
    criticalCves: number;
  };
}

export interface OverviewData {
  healthScore: HealthScoreBreakdown;
  counts: {
    totalAlerts: number;
    openIncidents: number;
    activeAgents: number;
    totalAgents: number;
    anomaliesDetected: number;
    fimEvents: number;
    openVulnerabilities: number;
  };
  severityDistribution: Array<{ label: string; min: number; max: number; count: number }>;
  timeline: Array<{ label: string; total: number; highCritical: number; anomalies: number }>;
  topSourceIps: Array<{ ip: string; count: number }>;
  topUsers: Array<{ user: string; count: number }>;
  topMitre: Array<{ id: string; tactic: string; count: number }>;
  recentIncidents: IncidentRecord[];
  recentAlerts: AegisAlert[];
}
