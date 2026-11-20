import type { AegisAlert } from '../types.ts';

type Token =
  | { type: 'LPAREN' }
  | { type: 'RPAREN' }
  | { type: 'AND' }
  | { type: 'OR' }
  | { type: 'NOT' }
  | { type: 'OP'; value: string }
  | { type: 'IDENT'; value: string }
  | { type: 'STRING'; value: string }
  | { type: 'NUMBER'; value: number }
  | { type: 'BOOL'; value: boolean };

function tokenize(expr: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < expr.length) {
    const ch = expr[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '(') {
      tokens.push({ type: 'LPAREN' });
      i++;
      continue;
    }
    if (ch === ')') {
      tokens.push({ type: 'RPAREN' });
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const quote = ch;
      i++;
      let str = '';
      while (i < expr.length && expr[i] !== quote) {
        str += expr[i++];
      }
      i++;
      tokens.push({ type: 'STRING', value: str });
      continue;
    }

    const twoChar = expr.slice(i, i + 2);
    if (['==', '!=', '>=', '<='].includes(twoChar)) {
      tokens.push({ type: 'OP', value: twoChar });
      i += 2;
      continue;
    }
    if (['>', '<', '~', '='].includes(ch)) {
      tokens.push({ type: 'OP', value: ch === '=' ? '==' : ch });
      i++;
      continue;
    }

    if (/[0-9-]/.test(ch)) {
      const m = expr.slice(i).match(/^-?\d+(?:\.\d+)?/);
      if (m) {
        tokens.push({ type: 'NUMBER', value: Number(m[0]) });
        i += m[0].length;
        continue;
      }
    }

    const wordMatch = expr.slice(i).match(/^[A-Za-z_][A-Za-z0-9_.*:-]*/);
    if (wordMatch) {
      const w = wordMatch[0];
      const upper = w.toUpperCase();
      if (upper === 'AND') tokens.push({ type: 'AND' });
      else if (upper === 'OR') tokens.push({ type: 'OR' });
      else if (upper === 'NOT') tokens.push({ type: 'NOT' });
      else if (upper === 'TRUE') tokens.push({ type: 'BOOL', value: true });
      else if (upper === 'FALSE') tokens.push({ type: 'BOOL', value: false });
      else tokens.push({ type: 'IDENT', value: w });
      i += w.length;
      continue;
    }

    i++;
  }
  return tokens;
}

function getNestedValue(obj: unknown, path: string): unknown {
  const parts = path.split('.');
  let curr: unknown = obj;
  for (const p of parts) {
    if (curr == null || typeof curr !== 'object') return undefined;
    curr = (curr as Record<string, unknown>)[p];
  }
  return curr;
}

function compareValues(actual: unknown, op: string, expected: string | number | boolean): boolean {
  if (Array.isArray(actual)) {
    if (op === '~' || op === '==') {
      return actual.some((item) => String(item).toLowerCase().includes(String(expected).toLowerCase()));
    }
    if (op === '!=') {
      return !actual.some((item) => String(item).toLowerCase() === String(expected).toLowerCase());
    }
    return false;
  }

  if (actual === undefined || actual === null) {
    return op === '!=';
  }

  if (typeof expected === 'number') {
    const num = Number(actual);
    if (Number.isNaN(num)) return false;
    if (op === '==') return num === expected;
    if (op === '!=') return num !== expected;
    if (op === '>=') return num >= expected;
    if (op === '<=') return num <= expected;
    if (op === '>') return num > expected;
    if (op === '<') return num < expected;
    return false;
  }

  if (typeof expected === 'boolean') {
    const boolVal = Boolean(actual);
    return op === '==' ? boolVal === expected : boolVal !== expected;
  }

  const aStr = String(actual).toLowerCase();
  const eStr = String(expected).toLowerCase();
  if (op === '==') return aStr === eStr;
  if (op === '!=') return aStr !== eStr;
  if (op === '~') {
    try {
      return new RegExp(String(expected), 'i').test(String(actual));
    } catch {
      return aStr.includes(eStr);
    }
  }
  return false;
}

type Predicate = (alert: AegisAlert) => boolean;

function parseTokens(tokens: Token[]): Predicate {
  let pos = 0;

  function parseOr(): Predicate {
    let left = parseAnd();
    while (tokens[pos]?.type === 'OR') {
      pos++;
      const right = parseAnd();
      const prev = left;
      left = (a) => prev(a) || right(a);
    }
    return left;
  }

  function parseAnd(): Predicate {
    let left = parseNot();
    while (tokens[pos]?.type === 'AND') {
      pos++;
      const right = parseNot();
      const prev = left;
      left = (a) => prev(a) && right(a);
    }
    return left;
  }

  function parseNot(): Predicate {
    if (tokens[pos]?.type === 'NOT') {
      pos++;
      const inner = parseNot();
      return (a) => !inner(a);
    }
    return parsePrimary();
  }

  function parsePrimary(): Predicate {
    const t = tokens[pos];
    if (!t) return () => true;

    if (t.type === 'LPAREN') {
      pos++;
      const inner = parseOr();
      if (tokens[pos]?.type === 'RPAREN') pos++;
      return inner;
    }

    if (t.type === 'IDENT' && tokens[pos + 1]?.type === 'OP') {
      const field = t.value;
      const op = (tokens[pos + 1] as { type: 'OP'; value: string }).value;
      const rhs = tokens[pos + 2];
      pos += 3;
      if (!rhs) return () => true;

      const expected =
        rhs.type === 'NUMBER'
          ? rhs.value
          : rhs.type === 'BOOL'
            ? rhs.value
            : rhs.type === 'STRING' || rhs.type === 'IDENT'
              ? rhs.value
              : '';

      return (alert) => {
        const val = getNestedValue(alert, field);
        return compareValues(val, op, expected);
      };
    }

    // Free-text fallback term
    if (t.type === 'STRING' || t.type === 'IDENT') {
      const needle = t.value.toLowerCase();
      pos++;
      return (alert) => JSON.stringify(alert).toLowerCase().includes(needle);
    }

    pos++;
    return () => true;
  }

  if (tokens.length === 0) return () => true;
  return parseOr();
}

export interface AqlResult {
  alerts: AegisAlert[];
  totalMatched: number;
  parsedSummary: string;
  error?: string;
}

export function executeAqlQuery(allAlerts: AegisAlert[], query: string): AqlResult {
  const trimmed = query.trim();
  if (!trimmed) {
    return {
      alerts: [...allAlerts].sort((a, b) => b.timestamp.localeCompare(a.timestamp)),
      totalMatched: allAlerts.length,
      parsedSummary: 'All telemetry alerts sorted by -timestamp',
    };
  }

  try {
    const segments = trimmed.split('|').map((s) => s.trim());
    const filterExpr = segments[0];
    const tokens = tokenize(filterExpr);
    const predicate = parseTokens(tokens);

    let filtered = allAlerts.filter(predicate);
    const totalMatched = filtered.length;

    let sortField = 'timestamp';
    let sortDesc = true;
    let limit = 250;

    for (let i = 1; i < segments.length; i++) {
      const pipe = segments[i];
      const sortMatch = pipe.match(/^sort\s+(-?)([A-Za-z0-9_.]+)$/i);
      if (sortMatch) {
        sortDesc = sortMatch[1] === '-';
        sortField = sortMatch[2];
      }
      const limitMatch = pipe.match(/^limit\s+(\d+)$/i);
      if (limitMatch) {
        limit = Math.max(1, Math.min(1000, Number(limitMatch[1])));
      }
    }

    filtered = filtered.sort((a, b) => {
      const av = getNestedValue(a, sortField);
      const bv = getNestedValue(b, sortField);
      if (typeof av === 'number' && typeof bv === 'number') {
        return sortDesc ? bv - av : av - bv;
      }
      const as = String(av ?? '');
      const bs = String(bv ?? '');
      return sortDesc ? bs.localeCompare(as) : as.localeCompare(bs);
    });

    return {
      alerts: filtered.slice(0, limit),
      totalMatched,
      parsedSummary: `Filter: ${filterExpr || '*'} | Sort: ${sortDesc ? '-' : '+'}${sortField} | Limit: ${limit}`,
    };
  } catch (err) {
    return {
      alerts: [],
      totalMatched: 0,
      parsedSummary: 'Invalid AQL syntax',
      error: err instanceof Error ? err.message : 'Failed to parse AQL query',
    };
  }
}
