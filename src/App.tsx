import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { AgentSimulator } from './components/AgentSimulator';
import { PolicyManager } from './components/PolicyManager';
import { SiemAuditStream } from './components/SiemAuditStream';
import { CommandCatalog } from './components/CommandCatalog';
import { TestRunner } from './components/TestRunner';
import { CommandMeta } from './types';
import { Shield, Lock, Database, Key } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('simulator');
  const [commands, setCommands] = useState<CommandMeta[]>([]);
  const [isQuickTesting, setIsQuickTesting] = useState(false);

  const fetchCommands = async () => {
    try {
      const res = await fetch('/api/proxy/commands');
      const data = await res.json();
      if (data.commands) {
        setCommands(data.commands);
      }
    } catch (e) {
      console.error('Failed to load commands catalog', e);
    }
  };

  useEffect(() => {
    fetchCommands();
  }, []);

  const handleRunQuickTests = async () => {
    setIsQuickTesting(true);
    setActiveTab('tests');
    try {
      await fetch('/api/proxy/run-tests', { method: 'POST' });
    } catch (e) {
      console.error(e);
    } finally {
      setIsQuickTesting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* 3-Zone Header Contract */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRunQuickTests={handleRunQuickTests}
        isTesting={isQuickTesting}
      />

      {/* Trust & Environment Status Kicker Strip */}
      <div className="bg-slate-900/60 border-b border-slate-800/80 px-6 py-2.5">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-y-2 text-xs text-slate-400">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
              <Lock className="w-3.5 h-3.5" />
              <span>LDAPS Strictly Enforced (Port 636)</span>
            </span>
            <span aria-hidden="true" className="text-slate-700">·</span>
            <span>Domain: <strong className="text-slate-200 font-mono">corp.acme.internal</strong></span>
            <span aria-hidden="true" className="text-slate-700">·</span>
            <span>Base DN: <strong className="text-slate-200 font-mono">DC=corp,DC=acme,DC=internal</strong></span>
          </div>

          <div className="flex items-center gap-4 text-[11px]">
            <span className="flex items-center gap-1 text-slate-300">
              <Key className="w-3.5 h-3.5 text-blue-400" />
              <span>Secret Manager: <strong className="text-white">gMSA / OpenBao (Vault)</strong></span>
            </span>
            <span aria-hidden="true" className="text-slate-700">·</span>
            <span className="text-slate-300 font-mono">
              SIEM: <strong className="text-emerald-400">ECS & CEF Enabled</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Main Content Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8">
        {activeTab === 'simulator' && (
          <AgentSimulator commands={commands} />
        )}
        {activeTab === 'policies' && (
          <PolicyManager onConfigUpdated={fetchCommands} />
        )}
        {activeTab === 'siem' && (
          <SiemAuditStream />
        )}
        {activeTab === 'commands' && (
          <CommandCatalog commands={commands} />
        )}
        {activeTab === 'tests' && (
          <TestRunner />
        )}
      </main>

      {/* Quiet Corporate Compliance Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 px-6 py-4 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            Active Directory Secure LDAPS Proxy Engine · Zero-Trust Access Gateway for Autonomous Agents
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span>NIST SP 800-53 (AC-6 / AU-2)</span>
            <span>CIS Active Directory Benchmark</span>
            <span>RFC 4515 Injection Guard</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
