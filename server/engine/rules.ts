import fs from 'node:fs';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';
import type { AlertRuleInfo, DecoderTrace } from '../types.ts';

interface RawXmlRule {
  '@_id': string;
  '@_level': string;
  '@_frequency'?: string;
  '@_timeframe'?: string;
  decoded_as?: string;
  if_sid?: string;
  if_matched_sid?: string;
  same_source_ip?: string;
  match?: string;
  regex?: string;
  description?: string;
  group?: string;
  mitre?: { id?: string; tactic?: string };
}

export interface CompiledRule {
  id: string;
  level: number;
  frequency: number;
  timeframeSec: number;
  decodedAs: string | null;
  ifSid: string | null;
  ifMatchedSid: string | null;
  sameSourceIp: boolean;
  matchRegex: RegExp | null;
  description: string;
  groups: string[];
  mitre?: { id: string; tactic: string };
}

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  isArray: (name) => name === 'group' || name === 'rule',
});

let cachedRules: CompiledRule[] = [];
const statefulWindow = new Map<string, number[]>();
const firedCounts = new Map<string, number>();

export function reloadRules(): CompiledRule[] {
  const root = process.cwd();
  const files = [
    path.join(root, 'ruleset/rules/00-aegisone-rules.xml'),
    path.join(root, 'etc/rules/local_rules.xml'),
  ];

  const compiled: CompiledRule[] = [];
  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    const raw = fs.readFileSync(file, 'utf8');
    const parsed = xmlParser.parse(raw);
    const groups = Array.isArray(parsed?.group) ? parsed.group : parsed?.group ? [parsed.group] : [];

    for (const grp of groups) {
      const grpBase = String(grp['@_name'] || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const rulesList: RawXmlRule[] = Array.isArray(grp.rule) ? grp.rule : grp.rule ? [grp.rule] : [];

      for (const r of rulesList) {
        if (!r['@_id']) continue;
        const ruleGroups = String(r.group || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        const combinedGroups = Array.from(new Set([...grpBase, ...ruleGroups]));

        compiled.push({
          id: String(r['@_id']),
          level: Math.max(0, Math.min(16, Number(r['@_level'] ?? 3))),
          frequency: Number(r['@_frequency'] || 0),
          timeframeSec: Number(r['@_timeframe'] || 120),
          decodedAs: r.decoded_as ? String(r.decoded_as).trim() : null,
          ifSid: r.if_sid ? String(r.if_sid).trim() : null,
          ifMatchedSid: r.if_matched_sid ? String(r.if_matched_sid).trim() : null,
          sameSourceIp: r.same_source_ip !== undefined,
          matchRegex: r.match ? new RegExp(String(r.match), 'i') : r.regex ? new RegExp(String(r.regex), 'i') : null,
          description: String(r.description || 'AegisOne security rule triggered'),
          groups: combinedGroups,
          mitre: r.mitre?.id
            ? {
                id: String(r.mitre.id),
                tactic: String(r.mitre.tactic || 'Execution'),
              }
            : undefined,
        });
      }
    }
  }

  cachedRules = compiled;
  return cachedRules;
}

export function getLoadedRules(): CompiledRule[] {
  if (cachedRules.length === 0) {
    reloadRules();
  }
  return cachedRules;
}

export function clearStatefulRuleWindow() {
  statefulWindow.clear();
  firedCounts.clear();
}

export function evaluateRules(trace: DecoderTrace, rawLog: string, eventTimeMs = Date.now()): AlertRuleInfo {
  const rules = getLoadedRules();
  const decoderNames = new Set([
    trace.phase2.effectiveDecoderName,
    trace.phase2.parentDecoder || '',
    ...trace.phase2.matchedDecoders,
  ]);

  const searchable = `${trace.phase1.logBody} ${rawLog} ${JSON.stringify(trace.phase2.extractedFields)}`;

  // 1. Find highest-level atomic rule matching decoder & parent chain
  let matchedRule: CompiledRule | null = null;
  const matchedIds = new Set<string>();

  // Base rules (decoded_as)
  for (const r of rules) {
    if (r.decodedAs && decoderNames.has(r.decodedAs)) {
      if (!r.matchRegex || r.matchRegex.test(searchable)) {
        matchedIds.add(r.id);
        if (!matchedRule || r.level >= matchedRule.level) {
          matchedRule = r;
        }
      }
    }
  }

  // Child rules (if_sid) - run 2 passes so multi-level chains resolve
  for (let pass = 0; pass < 2; pass++) {
    for (const r of rules) {
      if (r.ifSid && matchedIds.has(r.ifSid)) {
        if (!r.matchRegex || r.matchRegex.test(searchable)) {
          matchedIds.add(r.id);
          if (!matchedRule || r.level >= matchedRule.level) {
            matchedRule = r;
          }
        }
      }
    }
  }

  // 2. Stateful frequency/timeframe correlation rules (if_matched_sid)
  const srcip = String(trace.phase2.extractedFields.srcip || 'unknown');
  for (const r of rules) {
    if (r.ifMatchedSid && matchedIds.has(r.ifMatchedSid)) {
      const key = r.sameSourceIp ? `${r.id}:${srcip}` : r.id;
      const arr = (statefulWindow.get(key) || []).filter((ts) => eventTimeMs - ts <= r.timeframeSec * 1000);
      arr.push(eventTimeMs);
      statefulWindow.set(key, arr);

      if (arr.length >= Math.max(2, r.frequency)) {
        matchedRule = r;
      }
    }
  }

  if (!matchedRule) {
    return {
      id: '1000',
      level: 2,
      description: `Telemetry event decoded by ${trace.phase2.effectiveDecoderName}`,
      groups: ['telemetry', trace.phase2.effectiveDecoderName],
      firedtimes: 1,
    };
  }

  const count = (firedCounts.get(matchedRule.id) || 0) + 1;
  firedCounts.set(matchedRule.id, count);

  return {
    id: matchedRule.id,
    level: matchedRule.level,
    description: matchedRule.description,
    groups: matchedRule.groups,
    firedtimes: count,
    mitre: matchedRule.mitre,
  };
}
