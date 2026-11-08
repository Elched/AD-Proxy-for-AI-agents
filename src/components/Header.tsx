import React from 'react';
import { Shield, Play } from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onRunQuickTests: () => void;
  isTesting: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onRunQuickTests,
  isTesting,
}) => {
  return (
    <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-800 bg-slate-950 text-slate-100">
      {/* Zone 1: Single text element wordmark */}
      <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
        <Shield className="w-5 h-5 text-emerald-400 shrink-0" />
        <span className="text-base font-bold tracking-tight text-white">
          Active Directory LDAPS Proxy
        </span>
      </div>

      {/* Zone 2: 5 clean single-line text navigation links */}
      <nav className="hidden md:flex items-center gap-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab('simulator')}
          className={`whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'simulator'
              ? 'text-white border-b-2 border-emerald-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Agent Simulator
        </button>
        <button
          onClick={() => setActiveTab('policies')}
          className={`whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'policies'
              ? 'text-white border-b-2 border-emerald-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          RBAC & Configuration
        </button>
        <button
          onClick={() => setActiveTab('siem')}
          className={`whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'siem'
              ? 'text-white border-b-2 border-emerald-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          SIEM Audit Stream
        </button>
        <button
          onClick={() => setActiveTab('commands')}
          className={`whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'commands'
              ? 'text-white border-b-2 border-emerald-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Command Catalog
        </button>
        <button
          onClick={() => setActiveTab('tests')}
          className={`whitespace-nowrap shrink-0 transition-colors py-1 ${
            activeTab === 'tests'
              ? 'text-white border-b-2 border-emerald-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Verification Suite
        </button>
      </nav>

      {/* Zone 3: 1 primary action */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onRunQuickTests}
          disabled={isTesting}
          className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-emerald-400 rounded-md hover:bg-emerald-300 transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>{isTesting ? 'Validating...' : 'Run Security Tests'}</span>
        </button>
      </div>
    </header>
  );
};
