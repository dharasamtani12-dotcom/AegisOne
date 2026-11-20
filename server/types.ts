export type RbacRole = 'admin' | 'analyst' | 'auditor';

export interface AegisConfig {
  domain: string;
  organization: string;
  logall: boolean;
  logallJson: boolean;
  archiveCompression: string;
  retentionDays: number;
  ingestionQueueMax: number;
  workerPoolSize: number;
  mlNumTrees: number;
  mlSubsampleSize: number;
  mlAnomalyThreshold: number;
  autoCorrelateIncidents: boolean;
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

export interface DecodedFields {
  user?: string;
  srcuser?: string;
  srcip?: string;
  dstip?: string;
  srcport?: string;
  dstport?: string;
  protocol?: string;
  action?: string;
  id?: string;
  url?: string;
  data?: string;
  extra_data?: string;
  status?: string;
  system_name?: string;
  [key: string]: string | number | boolean | undefined;
}

export interface DecoderTrace {
  phase1: {
    timestamp: string;
    hostname: string;
    programName: string;
    logBody: string;
    format: 'syslog' | 'journald_json' | 'sysmon_json' | 'raw';
  };
  phase2: {
    parentDecoder: string | null;
    matchedDecoders: string[];
    effectiveDecoderName: string;
    extractedFields: DecodedFields;
    siblingApplied: boolean;
  };
}

export interface MlFeatureContribution {
  feature: string;
  label: string;
  value: number;
  baselineMedian: number;
  contributionPct: number;
}

export interface MlAnomalyResult {
  score: number;
  isAnomaly: boolean;
  avgPathLength: number;
  expectedPathLength: number;
  contributions: MlFeatureContribution[];
  featureVector: number[];
}

export interface AlertRuleInfo {
  id: string;
  level: number;
  description: string;
  groups: string[];
  firedtimes: number;
  mitre?: {
    id: string;
    tactic: string;
  };
}

export interface AegisAlert {
  id: string;
  timestamp: string;
  rule: AlertRuleInfo;
  agent: {
    id: string;
    name: string;
    ip: string;
  };
  decoder: {
    name: string;
    parent: string | null;
  };
  data: DecodedFields;
  ml: MlAnomalyResult;
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
