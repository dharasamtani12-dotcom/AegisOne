import fs from 'node:fs';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';
import type { AegisConfig } from '../types.ts';

const ROOT_DIR = process.cwd();
const CONF_PATH = path.join(ROOT_DIR, 'etc', 'aegisone.conf');

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  allowBooleanAttributes: true,
  parseTagValue: false,
});

export function loadAegisConfig(): AegisConfig {
  try {
    const raw = fs.readFileSync(CONF_PATH, 'utf8');
    const parsed = xmlParser.parse(raw);
    const cfg = parsed.aegisone_config || {};
    const g = cfg.global || {};
    const gw = cfg.ingestion_gateway || {};
    const ml = cfg.ml_engine || {};

    return {
      domain: String(g.domain || 'aegisone.local'),
      organization: String(g.organization || 'Medicaps University Lab SOC'),
      logall: String(g.logall || 'yes').toLowerCase() === 'yes',
      logallJson: String(g.logall_json || 'yes').toLowerCase() === 'yes',
      archiveCompression: String(g.archive_compression || 'gzip'),
      retentionDays: Number(g.retention_days || 90),
      ingestionQueueMax: Number(gw.bounded_queue_max || 2048),
      workerPoolSize: Number(gw.worker_pool_size || 4),
      mlNumTrees: Number(ml.num_trees || 64),
      mlSubsampleSize: Number(ml.subsample_size || 256),
      mlAnomalyThreshold: Number(ml.anomaly_threshold || 0.65),
      autoCorrelateIncidents: String(ml.auto_correlate_incidents || 'yes').toLowerCase() === 'yes',
    };
  } catch {
    return {
      domain: 'aegisone.local',
      organization: 'Medicaps University Lab SOC',
      logall: true,
      logallJson: true,
      archiveCompression: 'gzip',
      retentionDays: 90,
      ingestionQueueMax: 2048,
      workerPoolSize: 4,
      mlNumTrees: 64,
      mlSubsampleSize: 256,
      mlAnomalyThreshold: 0.65,
      autoCorrelateIncidents: true,
    };
  }
}

export function readRawConfigFile(): string {
  return fs.readFileSync(CONF_PATH, 'utf8');
}

export function saveAegisConfigXml(xmlContent: string): AegisConfig {
  // Validate XML parses cleanly before saving
  const parsed = xmlParser.parse(xmlContent);
  if (!parsed || !parsed.aegisone_config) {
    throw new Error('Invalid configuration XML: missing <aegisone_config> root element.');
  }
  fs.writeFileSync(CONF_PATH, xmlContent, 'utf8');
  return loadAegisConfig();
}

export function listRulesetFiles() {
  const files = [
    { id: 'builtin-decoders', path: 'ruleset/decoders/00-built-in-decoders.xml', kind: 'decoder', editable: false },
    { id: 'local-decoders', path: 'etc/decoders/local_decoders.xml', kind: 'decoder', editable: true },
    { id: 'builtin-rules', path: 'ruleset/rules/00-aegisone-rules.xml', kind: 'rule', editable: false },
    { id: 'local-rules', path: 'etc/rules/local_rules.xml', kind: 'rule', editable: true },
  ];
  return files.map((f) => ({
    ...f,
    content: fs.existsSync(path.join(ROOT_DIR, f.path))
      ? fs.readFileSync(path.join(ROOT_DIR, f.path), 'utf8')
      : '',
  }));
}

export function saveLocalRulesetFile(id: string, content: string) {
  const allowed: Record<string, string> = {
    'local-decoders': path.join(ROOT_DIR, 'etc/decoders/local_decoders.xml'),
    'local-rules': path.join(ROOT_DIR, 'etc/rules/local_rules.xml'),
  };
  const target = allowed[id];
  if (!target) {
    throw new Error('Only upgrade-safe local files (etc/decoders/local_decoders.xml, etc/rules/local_rules.xml) can be modified.');
  }
  const parsed = xmlParser.parse(content);
  if (!parsed) {
    throw new Error('Invalid XML syntax.');
  }
  fs.writeFileSync(target, content, 'utf8');
}
