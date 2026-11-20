import React from 'react';

export type ChipStatus = 'pass' | 'warn' | 'error' | 'info';

export function VChip({
  status = 'warn',
  label,
  className = '',
}: {
  status?: ChipStatus;
  label: string;
  className?: string;
}) {
  const dotColor =
    status === 'pass'
      ? 'bg-emerald-400'
      : status === 'info'
        ? 'bg-[#FF4500]'
        : status === 'error'
          ? 'bg-[#ffe0e0]'
          : 'bg-gray-400';

  return (
    <span className={`v-chip uppercase ${className}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotColor}`} aria-hidden="true" />
      <span>{label}</span>
    </span>
  );
}

export function TimelineProgressBar({
  startPct,
  widthPct,
  active = false,
}: {
  startPct: number;
  widthPct: number;
  active?: boolean;
}) {
  const safeStart = Math.max(0, Math.min(96, startPct));
  const safeWidth = Math.max(4, Math.min(100 - safeStart, widthPct));

  return (
    <div className="w-full h-1.5 bg-white/5 rounded-full relative overflow-hidden">
      <div
        className="absolute top-0 h-full rounded-full transition-colors"
        style={{
          left: `${safeStart}%`,
          width: `${safeWidth}%`,
          backgroundColor: active ? '#FF4500' : 'rgba(255, 224, 224, 0.28)',
        }}
      />
    </div>
  );
}

export function SeverityLabel({ level }: { level: number }) {
  let status: ChipStatus = 'pass';
  let text = `LOW L${level}`;

  if (level >= 12) {
    status = 'info';
    text = `CRIT L${level}`;
  } else if (level >= 8) {
    status = 'error';
    text = `HIGH L${level}`;
  } else if (level >= 5) {
    status = 'warn';
    text = `MED L${level}`;
  } else {
    status = 'pass';
    text = `LOW L${level}`;
  }

  return <VChip status={status} label={text} />;
}

export function IncidentSeverityLabel({ severity }: { severity: 'critical' | 'high' | 'medium' | 'low' }) {
  const map: Record<typeof severity, { status: ChipStatus; label: string }> = {
    critical: { status: 'info', label: 'CRITICAL' },
    high: { status: 'error', label: 'HIGH' },
    medium: { status: 'warn', label: 'MEDIUM' },
    low: { status: 'pass', label: 'LOW' },
  };
  const cfg = map[severity];
  return <VChip status={cfg.status} label={cfg.label} />;
}

export function IncidentStatusLabel({ status }: { status: 'open' | 'investigating' | 'contained' | 'resolved' }) {
  const map: Record<typeof status, { chip: ChipStatus; label: string }> = {
    open: { chip: 'info', label: 'OPEN' },
    investigating: { chip: 'warn', label: 'INVESTIGATING' },
    contained: { chip: 'error', label: 'CONTAINED' },
    resolved: { chip: 'pass', label: 'RESOLVED' },
  };
  const cfg = map[status];
  return <VChip status={cfg.chip} label={cfg.label} />;
}

export function formatTimeShort(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}
