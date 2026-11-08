import React, { useState } from 'react';
import {
  Terminal,
  Search,
  Copy,
  Check,
  Shield,
  Layers,
  Code2,
  Lock,
  ChevronDown,
  ChevronRight
} from 'lucide-react';
import { CommandMeta } from '../types';

interface CommandCatalogProps {
  commands: CommandMeta[];
}

export const CommandCatalog: React.FC<CommandCatalogProps> = ({ commands }) => {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [selectedSnippetCmd, setSelectedSnippetCmd] = useState<string>('list_group_members');
  const [snippetLanguage, setSnippetLanguage] = useState<'python' | 'langchain' | 'curl'>('python');
  const [copied, setCopied] = useState(false);

  const filtered = commands.filter((cmd) => {
    if (categoryFilter !== 'ALL' && cmd.category !== categoryFilter) {
      return false;
    }
    if (search) {
      const q = search.toLowerCase();
      return (
        cmd.name.toLowerCase().includes(q) ||
        cmd.description.toLowerCase().includes(q) ||
        cmd.risk_level.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'LOW':
        return 'text-emerald-400 bg-emerald-950/80 border-emerald-800/80';
      case 'MEDIUM':
        return 'text-blue-400 bg-blue-950/80 border-blue-800/80';
      case 'HIGH':
        return 'text-amber-400 bg-amber-950/80 border-amber-800/80';
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-950/80 border-rose-800/80';
      default:
        return 'text-slate-400 bg-slate-800 border-slate-700';
    }
  };

  const getCodeSnippet = (cmdName: string, lang: 'python' | 'langchain' | 'curl') => {
    if (lang === 'python') {
      return `import requests

# AI Agent querying Active Directory via the secure LDAPS Proxy
url = "https://ad-proxy.corp.acme.internal:10636/v1/ldaps/query"
headers = {
    "Content-Type": "application/json",
    "X-IT-Ticket-ID": "INC-2026-8819", # Mandatory for write actions
}
payload = {
    "caller_account": "ai-triage-agent",
    "caller_password": os.environ["AGENT_AD_PASSWORD"],
    "command": "${cmdName}",
    "parameters": {
        # Command parameters escaped automatically via RFC 4515
    }
}
response = requests.post(url, json=payload, headers=headers, verify="/etc/ssl/certs/ad_root_ca.crt")
result = response.json()
print("Success:", result["success"])
print("Data:", result.get("data"))`;
    }

    if (lang === 'langchain') {
      return `from langchain.tools import BaseTool
import requests, os

class ADQueryTool(BaseTool):
    name = "${cmdName}"
    description = "Execute ${cmdName} Active Directory query via Zero-Trust LDAPS Proxy"

    def _run(self, parameters: dict, ticket_id: str = None) -> dict:
        url = "https://ad-proxy.corp.acme.internal:10636/v1/ldaps/query"
        payload = {
            "caller_account": "ai-triage-agent",
            "caller_password": os.environ["AGENT_AD_PASSWORD"],
            "command": "${cmdName}",
            "parameters": parameters,
            "ticket_id": ticket_id
        }
        res = requests.post(url, json=payload, timeout=10)
        return res.json()`;
    }

    return `curl -k -X POST https://127.0.0.1:10636/v1/ldaps/query \\
  -H "Content-Type: application/json" \\
  -d '{
    "caller_account": "ai-triage-agent",
    "caller_password": "AgentSecurePassword2026!",
    "command": "${cmdName}",
    "parameters": {}
  }'`;
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(getCodeSnippet(selectedSnippetCmd, snippetLanguage));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Description and Filters */}
      <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-white">Active Directory LDAPS Command Catalog</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Standard Active Directory commands accessible to permitted service accounts. Extensible via Python decorator.
            </p>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search command name, desc..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        {/* Category filters */}
        <div className="flex items-center gap-1 mt-4 pt-3 border-t border-slate-800 text-xs">
          {['ALL', 'read', 'write', 'admin', 'system'].map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1 rounded transition-colors uppercase font-medium text-[11px] whitespace-nowrap shrink-0 ${
                categoryFilter === cat ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Commands List */}
        <div className="lg:col-span-7 space-y-3">
          {filtered.map((cmd) => (
            <div
              key={cmd.name}
              onClick={() => setSelectedSnippetCmd(cmd.name)}
              className={`p-4 rounded-lg border transition-all cursor-pointer ${
                selectedSnippetCmd === cmd.name
                  ? 'bg-slate-800/90 border-emerald-500/80 shadow-sm'
                  : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-sm text-white">{cmd.name}</span>
                    <span className="text-[11px] text-slate-400 capitalize">· {cmd.category}</span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1">{cmd.description}</p>
                </div>
                <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${getRiskBadge(cmd.risk_level)}`}>
                  {cmd.risk_level}
                </span>
              </div>

              {/* Parameters info */}
              <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-slate-400">
                <div>
                  <span className="text-slate-500">Required: </span>
                  <span className="text-slate-300">
                    {cmd.required_params.length ? cmd.required_params.join(', ') : 'None'}
                  </span>
                </div>
                {cmd.optional_params.length > 0 && (
                  <div>
                    <span className="text-slate-500">Optional: </span>
                    <span className="text-slate-400">{cmd.optional_params.join(', ')}</span>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* AI Agent Integration Snippet Pane */}
        <div className="lg:col-span-5">
          <div className="sticky top-6 p-4 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-semibold text-white">AI Agent Code Snippet</h3>
                <span className="text-[11px] font-mono text-emerald-400">{selectedSnippetCmd}</span>
              </div>
              <button
                onClick={handleCopy}
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* Language tabs */}
            <div className="flex items-center gap-1 p-1 bg-slate-950 rounded border border-slate-800 text-xs">
              {(['python', 'langchain', 'curl'] as const).map((l) => (
                <button
                  key={l}
                  onClick={() => setSnippetLanguage(l)}
                  className={`flex-1 py-1 rounded capitalize font-medium ${
                    snippetLanguage === l ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {l}
                </button>
              ))}
            </div>

            <pre className="p-3 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] text-emerald-300 overflow-x-auto max-h-96 leading-relaxed">
              {getCodeSnippet(selectedSnippetCmd, snippetLanguage)}
            </pre>

            <div className="text-[11px] text-slate-400 p-2.5 bg-slate-950/60 rounded border border-slate-800">
              <span className="font-semibold text-slate-300">Extensibility Notice:</span> To add a new Active Directory command, simply decorate a Python function in <code className="text-emerald-400">ad_proxy/commands.py</code> with <code className="text-emerald-400">@registry.register(...)</code>. It will automatically appear in this catalog.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
