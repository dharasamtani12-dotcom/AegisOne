import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  Archive,
  ArrowRight,
  Bot,
  Code2,
  Cpu,
  FileText,
  FileWarning,
  GitCommitHorizontal,
  Layers,
  Menu,
  Search,
  Server,
  Settings,
  ShieldAlert,
  Upload,
  X,
} from 'lucide-react';
import { apiFetch, setApiRole } from './lib/api';
import type { AegisAlert, IncidentRecord, NavSectionId, OverviewData, RbacRole } from './types/aegis';
import { AlertFlyout } from './components/AlertFlyout';
import { CommandCenterView } from './components/CommandCenterView';
import { DiscoverAqlView } from './components/DiscoverAqlView';
import { ArchivesView, StorylineView } from './components/StorylineArchivesView';
import { AgentsView, FimView, VulnerabilitiesView } from './components/EndpointsXdrView';
import { IncidentsView } from './components/IncidentsView';
import { MlAnomalyView } from './components/MlAnomalyView';
import { AiAnalystView } from './components/AiAnalystView';
import { SandboxRulesView } from './components/SandboxRulesView';
import { IngestionView } from './components/IngestionView';
import { ConfigRbacView, ReportsView } from './components/GovernanceReportsView';

interface NavGroup {
  label: string;
  items: Array<{ id: NavSectionId; label: string; icon: React.ComponentType<{ className?: string }> }>;
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Command Center',
    items: [{ id: 'overview', label: 'Overview & Stream', icon: Activity }],
  },
  {
    label: 'Threat Detection',
    items: [
      { id: 'discover', label: 'Discover & AQL', icon: Search },
      { id: 'storyline', label: 'Attack Storyline', icon: GitCommitHorizontal },
      { id: 'archives', label: 'Event Archives', icon: Archive },
    ],
  },
  {
    label: 'Endpoint & XDR',
    items: [
      { id: 'agents', label: 'AegisOne Agents', icon: Server },
      { id: 'fim', label: 'File Integrity', icon: FileWarning },
      { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
    ],
  },
  {
    label: 'Intelligence & AI',
    items: [
      { id: 'incidents', label: 'Incidents', icon: Layers },
      { id: 'ml', label: 'Behavioral ML', icon: Cpu },
      { id: 'ai', label: 'AI Analyst', icon: Bot },
    ],
  },
  {
    label: 'Governance',
    items: [
      { id: 'sandbox', label: 'Decoders & Rules', icon: Code2 },
      { id: 'ingestion', label: 'Ingestion', icon: Upload },
      { id: 'config', label: 'RBAC & Config', icon: Settings },
      { id: 'reports', label: 'Reports', icon: FileText },
    ],
  },
];

const HEADER_NAV_LINKS: Array<{ id: NavSectionId; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'discover', label: 'AQL Explorer' },
  { id: 'incidents', label: 'Incidents' },
  { id: 'ml', label: 'Behavioral ML' },
  { id: 'ai', label: 'AI Analyst' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<NavSectionId>('overview');
  const [role, setRole] = useState<RbacRole>('admin');
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [loadingOverview, setLoadingOverview] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<AegisAlert | null>(null);
  const [aiIncidentFocus, setAiIncidentFocus] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  const loadOverview = useCallback(async () => {
    setLoadingOverview(true);
    try {
      const res = await apiFetch<OverviewData>('/api/v1/overview');
      setOverview(res);
    } finally {
      setLoadingOverview(false);
    }
  }, []);

  useEffect(() => {
    loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 36);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const handleRoleChange = (next: RbacRole) => {
    setApiRole(next);
    setRole(next);
  };

  const handleSelectAlertById = async (alertId: string) => {
    const res = await apiFetch<{ alerts: AegisAlert[] }>(`/api/v1/alerts?q=${encodeURIComponent(`id == "${alertId}"`)}`);
    if (res.alerts[0]) {
      setSelectedAlert(res.alerts[0]);
    }
  };

  const navigateTo = (id: NavSectionId) => {
    setActiveTab(id);
    setMobileMenuOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#050505] text-white selection:bg-[#FF4500] selection:text-white flex flex-col">
      {/* Subtle Global Noise Texture */}
      <div className="noise-overlay" aria-hidden="true" />

      {/* Scroll-Reactive Navigation Header */}
      <header
        className={`no-print sticky top-0 z-40 transition-all duration-300 border-b border-white/5 ${
          scrolled ? 'bg-[#050505]/90 backdrop-blur-md py-3.5' : 'bg-[#050505]/70 backdrop-blur-sm py-5'
        }`}
      >
        <div className="max-w-[1440px] mx-auto px-6 lg:px-12 flex items-center justify-between gap-6">
          <button
            onClick={() => navigateTo('overview')}
            className="font-serif-display text-2xl font-bold tracking-tighter text-white hover:text-[#FF4500] transition-colors whitespace-nowrap shrink-0"
          >
            AegisOne.
          </button>

          <nav className="hidden md:flex items-center gap-8 text-sm font-medium" aria-label="Primary">
            {HEADER_NAV_LINKS.map((link) => (
              <button
                key={link.id}
                onClick={() => navigateTo(link.id)}
                className={`transition-colors whitespace-nowrap shrink-0 ${
                  activeTab === link.id ? 'text-[#FF4500]' : 'text-gray-400 hover:text-white'
                }`}
              >
                {link.label}
              </button>
            ))}
          </nav>

          <div className="flex items-center gap-3 shrink-0">
            <select
              aria-label="Active RBAC role"
              value={role}
              onChange={(e) => handleRoleChange(e.target.value as RbacRole)}
              className="hidden sm:block px-3.5 py-2 rounded-full bg-[#111111] border border-white/10 text-xs font-mono text-gray-200 focus:outline-none focus:border-[#FF4500]"
            >
              <option value="admin">ROLE: ADMIN</option>
              <option value="analyst">ROLE: ANALYST</option>
              <option value="auditor">ROLE: AUDITOR</option>
            </select>

            <button
              onClick={() => navigateTo('ingestion')}
              className="btn-pill-primary hidden sm:inline-flex px-5 py-2 text-xs whitespace-nowrap shrink-0"
            >
              <span>Ingest Telemetry</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>

            <button
              onClick={() => setMobileMenuOpen(true)}
              className="md:hidden btn-pill-glass p-2.5"
              aria-label="Open menu"
            >
              <Menu className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Full-Screen Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 bg-[#050505] flex flex-col p-6 overflow-y-auto md:hidden">
          <div className="flex items-center justify-between pb-6 border-b border-white/10">
            <span className="font-serif-display text-2xl font-bold tracking-tighter text-white">AegisOne.</span>
            <button
              onClick={() => setMobileMenuOpen(false)}
              className="btn-pill-glass p-2.5"
              aria-label="Close menu"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="py-6 space-y-6 flex-1">
            {NAV_GROUPS.map((grp) => (
              <div key={grp.label} className="space-y-2.5">
                <div className="text-xs font-mono text-gray-500 uppercase tracking-widest">{grp.label}</div>
                <div className="grid grid-cols-1 gap-2">
                  {grp.items.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => navigateTo(item.id)}
                      className={`text-left px-4 py-2.5 text-sm rounded-full border transition-colors ${
                        activeTab === item.id
                          ? 'bg-white text-[#050505] border-white font-medium'
                          : 'bg-[#111111] text-white border-white/10 hover:border-white/25'
                      }`}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div className="pt-4 border-t border-white/10 space-y-3">
            <select
              aria-label="Mobile RBAC role"
              value={role}
              onChange={(e) => handleRoleChange(e.target.value as RbacRole)}
              className="w-full px-4 py-2.5 rounded-full bg-[#111111] border border-white/10 text-xs font-mono text-white"
            >
              <option value="admin">ROLE: ADMIN</option>
              <option value="analyst">ROLE: ANALYST</option>
              <option value="auditor">ROLE: AUDITOR</option>
            </select>
            <button
              onClick={() => navigateTo('ingestion')}
              className="btn-pill-primary w-full py-3 text-sm inline-flex items-center justify-center gap-1.5"
            >
              <span>Ingest Telemetry</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* 14-Module Pill Workspace Dock */}
      <div className="no-print border-b border-white/5 bg-[#050505]/95 px-6 lg:px-12 py-3 overflow-x-auto">
        <div className="max-w-[1440px] mx-auto flex items-center gap-2 min-w-max">
          {NAV_GROUPS.flatMap((g) => g.items).map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => navigateTo(item.id)}
                className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-mono rounded-full border transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-white text-[#050505] border-white font-medium'
                    : 'bg-[#111111] border-white/10 text-gray-400 hover:text-white hover:border-white/25'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 shrink-0 ${active ? 'text-[#FF4500]' : ''}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Content Container */}
      <main className="flex-1 w-full max-w-[1440px] mx-auto px-6 lg:px-12 py-10">
        {activeTab === 'overview' && (
          <CommandCenterView
            data={overview}
            loading={loadingOverview}
            onNavigate={navigateTo}
            onSelectAlert={setSelectedAlert}
            onInvestigateIncident={(inc: IncidentRecord) => {
              setAiIncidentFocus(inc.id);
              navigateTo('ai');
            }}
          />
        )}

        {activeTab === 'discover' && <DiscoverAqlView onSelectAlert={setSelectedAlert} />}

        {activeTab === 'storyline' && <StorylineView onSelectAlert={setSelectedAlert} />}

        {activeTab === 'archives' && <ArchivesView />}

        {activeTab === 'agents' && <AgentsView />}

        {activeTab === 'fim' && <FimView />}

        {activeTab === 'vulnerabilities' && <VulnerabilitiesView role={role} onMutated={loadOverview} />}

        {activeTab === 'incidents' && (
          <IncidentsView
            role={role}
            onSelectAlert={setSelectedAlert}
            onAskAiForIncident={(inc) => {
              setAiIncidentFocus(inc.id);
              navigateTo('ai');
            }}
            onMutated={loadOverview}
          />
        )}

        {activeTab === 'ml' && (
          <MlAnomalyView role={role} onSelectAlert={setSelectedAlert} onMutated={loadOverview} />
        )}

        {activeTab === 'ai' && (
          <AiAnalystView
            initialIncidentId={aiIncidentFocus}
            onSelectAlertById={handleSelectAlertById}
          />
        )}

        {activeTab === 'sandbox' && <SandboxRulesView role={role} />}

        {activeTab === 'ingestion' && (
          <IngestionView role={role} onSelectAlert={setSelectedAlert} onMutated={loadOverview} />
        )}

        {activeTab === 'config' && (
          <ConfigRbacView role={role} onChangeRole={handleRoleChange} onMutated={loadOverview} />
        )}

        {activeTab === 'reports' && <ReportsView overview={overview} />}
      </main>

      {/* Atmospheric Obsidian Footer */}
      <footer className="no-print border-t border-white/10 bg-[#050505] pt-16 pb-10 px-6 lg:px-12 overflow-hidden">
        <div className="max-w-[1440px] mx-auto space-y-12">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-8">
            <div>
              <span className="font-serif-display text-2xl font-bold tracking-tight text-white">AegisOne.</span>
              <p className="mt-2 text-xs font-mono text-gray-500 max-w-md">
                AI-assisted SIEM &amp; XDR platform · Two-Phase XML Decoding · Isolation Forest Behavioral Analytics
              </p>
            </div>
            <div className="text-xs font-mono text-gray-500 md:text-right space-y-1">
              <div>Kushagra Sen, Harsh Verma &amp; Dhara Samtani · Guided by Priyasha Gupta</div>
              <div className="text-gray-400">Medicaps University, Indore (Academic Year 2026–27)</div>
            </div>
          </div>

          <div className="border-t border-white/10 pt-8 flex flex-col items-center">
            <h2 className="font-serif-display text-[10vw] leading-[0.82] tracking-tighter text-white/10 font-bold select-none pointer-events-none">
              AEGISONE.
            </h2>
          </div>
        </div>
      </footer>

      <AlertFlyout
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onAskAi={(alert) => {
          setAiIncidentFocus(alert.incidentId);
          setSelectedAlert(null);
          navigateTo('ai');
        }}
      />
    </div>
  );
}
