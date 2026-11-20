import fs from 'node:fs';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';
import type { DecodedFields, DecoderTrace } from '../types.ts';

interface RawXmlDecoder {
  '@_name': string;
  '@_use_own_name'?: string;
  parent?: string;
  program_name?: string;
  prematch?: string | { '#text': string; '@_offset'?: string };
  regex?: string | { '#text': string; '@_offset'?: string; '@_type'?: string };
  order?: string;
}

export interface CompiledDecoder {
  name: string;
  useOwnName: boolean;
  parent: string | null;
  programNameRegex: RegExp | null;
  prematchPattern: string | null;
  prematchOffset: string | null;
  regexPattern: string | null;
  regexOffset: string | null;
  orderFields: string[];
}

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  isArray: (name) => name === 'decoder',
});

let cachedDecoders: CompiledDecoder[] = [];

function compilePattern(pattern: string): RegExp {
  // Support both pcre2 and Wazuh osregex-like expressions safely
  return new RegExp(pattern);
}

export function reloadDecoders(): CompiledDecoder[] {
  const root = process.cwd();
  const files = [
    path.join(root, 'ruleset/decoders/00-built-in-decoders.xml'),
    path.join(root, 'etc/decoders/local_decoders.xml'),
  ];

  const compiled: CompiledDecoder[] = [];
  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    const raw = fs.readFileSync(file, 'utf8');
    const parsed = xmlParser.parse(raw);
    const list: RawXmlDecoder[] = parsed?.decoders?.decoder || [];
    for (const d of list) {
      if (!d['@_name']) continue;
      const prematchObj = typeof d.prematch === 'object' ? d.prematch : undefined;
      const prematchStr = typeof d.prematch === 'string' ? d.prematch : prematchObj?.['#text'] || null;
      const prematchOffset = prematchObj?.['@_offset'] || null;

      const regexObj = typeof d.regex === 'object' ? d.regex : undefined;
      const regexStr = typeof d.regex === 'string' ? d.regex : regexObj?.['#text'] || null;
      const regexOffset = regexObj?.['@_offset'] || null;

      const orderFields = d.order
        ? String(d.order)
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean)
        : [];

      compiled.push({
        name: d['@_name'],
        useOwnName: String(d['@_use_own_name'] || '').toLowerCase() === 'true',
        parent: d.parent ? String(d.parent).trim() : null,
        programNameRegex: d.program_name ? compilePattern(String(d.program_name).trim()) : null,
        prematchPattern: prematchStr,
        prematchOffset,
        regexPattern: regexStr,
        regexOffset,
        orderFields,
      });
    }
  }
  cachedDecoders = compiled;
  return cachedDecoders;
}

export function getLoadedDecoders(): CompiledDecoder[] {
  if (cachedDecoders.length === 0) {
    reloadDecoders();
  }
  return cachedDecoders;
}

/**
 * Phase 1: Pre-decoding (strips syslog/journald/Sysmon headers into timestamp, hostname, program_name, logBody)
 */
export function preDecodeLog(rawLine: string, fallbackHostname = 'localhost'): DecoderTrace['phase1'] {
  const trimmed = rawLine.trim();

  // Check if structured JSON (systemd-journald or Sysmon JSON)
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      if (obj._HOSTNAME || obj.SYSLOG_IDENTIFIER || obj.MESSAGE) {
        const ts = obj.__REALTIME_TIMESTAMP
          ? new Date(Number(obj.__REALTIME_TIMESTAMP) / 1000).toISOString()
          : String(obj.timestamp || new Date().toISOString());
        const host = String(obj._HOSTNAME || obj.hostname || fallbackHostname);
        const prog = String(obj.SYSLOG_IDENTIFIER || 'systemd-journald');
        const body = `_HOSTNAME=${host} SYSLOG_IDENTIFIER=${prog} _SYSTEMD_UNIT=${obj._SYSTEMD_UNIT || 'unknown.service'} SYSLOG_PID=${obj.SYSLOG_PID || obj._PID || '0'} MESSAGE=${obj.MESSAGE || ''}`;
        return {
          timestamp: ts,
          hostname: host,
          programName: 'systemd-journald',
          logBody: body,
          format: 'journald_json',
        };
      }
      if (obj.Channel === 'Microsoft-Windows-Sysmon/Operational' || obj.EventID) {
        const ts = String(obj.UtcTime || obj.timestamp || new Date().toISOString());
        const host = String(obj.Computer || obj.hostname || fallbackHostname);
        const kvParts = Object.entries(obj)
          .filter(([k]) => !['Channel', 'Computer', 'UtcTime', 'timestamp'].includes(k))
          .map(([k, v]) => (typeof v === 'string' && v.includes(' ') ? `${k}="${v}"` : `${k}=${v}`));
        return {
          timestamp: ts,
          hostname: host,
          programName: 'Microsoft-Windows-Sysmon/Operational',
          logBody: kvParts.join('; '),
          format: 'sysmon_json',
        };
      }
    } catch {
      // Fallback to syslog/raw parsing
    }
  }

  // ISO8601 Syslog: 2026-11-20T02:41:10Z web-gw-01 sshd[4412]: Failed password...
  const isoMatch = trimmed.match(
    /^(\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$/
  );
  if (isoMatch) {
    return {
      timestamp: isoMatch[1],
      hostname: isoMatch[2],
      programName: isoMatch[3],
      logBody: isoMatch[5],
      format: 'syslog',
    };
  }

  // RFC3164 Syslog: Nov 20 02:41:10 web-gw-01 sshd[4412]: Failed password...
  const rfcMatch = trimmed.match(
    /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s*(.*)$/
  );
  if (rfcMatch) {
    return {
      timestamp: new Date().toISOString(),
      hostname: rfcMatch[2],
      programName: rfcMatch[3],
      logBody: rfcMatch[5],
      format: 'syslog',
    };
  }

  return {
    timestamp: new Date().toISOString(),
    hostname: fallbackHostname,
    programName: 'raw-telemetry',
    logBody: trimmed,
    format: 'raw',
  };
}

/**
 * Phase 2: Parent, Child, and Sibling Decoder Execution with sequential offset chaining
 */
export function decodeLog(rawLine: string, fallbackHostname = 'localhost'): DecoderTrace {
  const decoders = getLoadedDecoders();
  const phase1 = preDecodeLog(rawLine, fallbackHostname);
  const body = phase1.logBody;

  const extracted: DecodedFields = {};
  const matchedDecoders: string[] = [];
  let parentDecoder: CompiledDecoder | null = null;
  let effectiveDecoderName = 'generic';
  let siblingApplied = false;

  // Dynamic JSON fields extraction if rawLine is JSON
  if (rawLine.trim().startsWith('{')) {
    try {
      const jsonObj = JSON.parse(rawLine.trim()) as Record<string, unknown>;
      for (const [k, v] of Object.entries(jsonObj)) {
        if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
          extracted[k] = v;
        }
      }
    } catch {
      // ignore
    }
  }

  // Step 1: Find matching parent decoder
  const parents = decoders.filter((d) => !d.parent);
  for (const p of parents) {
    const progMatches = p.programNameRegex ? p.programNameRegex.test(phase1.programName) : false;
    const preMatches = p.prematchPattern ? new RegExp(p.prematchPattern).test(body) : true;
    if ((p.programNameRegex && progMatches && preMatches) || (!p.programNameRegex && p.prematchPattern && preMatches)) {
      parentDecoder = p;
      matchedDecoders.push(p.name);
      effectiveDecoderName = p.name;

      // Apply parent regex if present
      if (p.regexPattern) {
        const m = body.match(new RegExp(p.regexPattern));
        if (m) {
          p.orderFields.forEach((field, idx) => {
            if (m[idx + 1] !== undefined) extracted[field] = m[idx + 1];
          });
        }
      }
      break;
    }
  }

  // Step 2: Evaluate all child & sibling decoders under the matched parent
  if (parentDecoder) {
    const children = decoders.filter((d) => d.parent === parentDecoder!.name);
    let siblingMatches = 0;

    for (const child of children) {
      let slice = body;
      let prematchEnd = 0;

      if (child.prematchPattern) {
        const pm = slice.match(new RegExp(child.prematchPattern));
        if (!pm || pm.index === undefined) continue;
        prematchEnd = pm.index + pm[0].length;
        if (child.prematchOffset === 'after_prematch') {
          slice = slice.slice(prematchEnd);
        }
      }

      if (child.regexPattern) {
        const workSlice = child.regexOffset === 'after_prematch' && prematchEnd > 0 ? body.slice(prematchEnd) : slice;
        const rm = workSlice.match(new RegExp(child.regexPattern));
        if (!rm) continue;

        matchedDecoders.push(child.name);
        siblingMatches++;
        if (child.useOwnName) {
          effectiveDecoderName = child.name;
        }
        child.orderFields.forEach((field, idx) => {
          if (rm[idx + 1] !== undefined) {
            extracted[field] = rm[idx + 1];
          }
        });
      } else {
        matchedDecoders.push(child.name);
        if (child.useOwnName) {
          effectiveDecoderName = child.name;
        }
      }
    }

    if (siblingMatches > 1) {
      siblingApplied = true;
    }
  }

  return {
    phase1,
    phase2: {
      parentDecoder: parentDecoder ? parentDecoder.name : null,
      matchedDecoders,
      effectiveDecoderName,
      extractedFields: extracted,
      siblingApplied,
    },
  };
}
