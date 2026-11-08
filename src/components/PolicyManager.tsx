import React, { useState, useEffect } from 'react';
import {
  Shield,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Save,
  Key,
  Users,
  Database,
  Lock
} from 'lucide-react';
import { ServiceAccountPolicy } from '../types';

interface PolicyManagerProps {
  onConfigUpdated?: () => void;
}

export const PolicyManager: React.FC<PolicyManagerProps> = ({ onConfigUpdated }) => {
  const [yamlContent, setYamlContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ text: string; isError?: boolean } | null>(null);
  const [checkOutput, setCheckOutput] = useState('');
  const [activeSubTab, setActiveSubTab] = useState<'matrix' | 'editor'>('matrix');

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/proxy/config');
      const data = await res.json();
      setYamlContent(data.raw_yaml || '');
      setCheckOutput(data.check_output || '');
    } catch (err: any) {
      setStatusMessage({ text: 'Failed to load configuration: ' + err.message, isError: true });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setStatusMessage(null);
    try {
      const res = await fetch('/api/proxy/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml_content: yamlContent }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatusMessage({ text: data.error + (data.details ? `: ${data.details}` : ''), isError: true });
      } else {
        setStatusMessage({ text: data.message, isError: false });
        if (data.output) setCheckOutput(data.output);
        if (onConfigUpdated) onConfigUpdated();
      }
    } catch (err: any) {
      setStatusMessage({ text: 'Error saving: ' + err.message, isError: true });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Controls & Sub-tabs */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
        <div>
          <h2 className="text-base font-semibold text-white">RBAC Policies & Configuration</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure Active Directory domain, upstream secret injection (gMSA / OpenBao), and service account permissions.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Segmented control */}
          <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-md border border-slate-800">
            <button
              onClick={() => setActiveSubTab('matrix')}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                activeSubTab === 'matrix' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Policy Overview
            </button>
            <button
              onClick={() => setActiveSubTab('editor')}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                activeSubTab === 'editor' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              YAML Editor
            </button>
          </div>

          <button
            onClick={fetchConfig}
            className="p-1.5 rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300"
            title="Reload from disk"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {statusMessage && (
        <div
          className={`p-3 rounded border text-xs flex items-center gap-2 ${
            statusMessage.isError
              ? 'bg-rose-950/40 border-rose-800 text-rose-300'
              : 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
          }`}
        >
          {statusMessage.isError ? (
            <AlertTriangle className="w-4 h-4 shrink-0" />
          ) : (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          )}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {activeSubTab === 'matrix' ? (
        <div className="space-y-6">
          {/* Architecture Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-200">
              <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 mb-1">
                <Database className="w-4 h-4" />
                <span>Active Directory Domain</span>
              </div>
              <div className="text-sm font-bold text-white font-mono">corp.acme.internal</div>
              <div className="text-xs text-slate-400 mt-1">Base DN: DC=corp,DC=acme,DC=internal</div>
              <div className="text-xs text-slate-500 mt-0.5">Pool: dc01, dc02 · Port: 636 (LDAPS)</div>
            </div>

            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-200">
              <div className="flex items-center gap-2 text-xs font-semibold text-blue-400 mb-1">
                <Key className="w-4 h-4" />
                <span>Upstream Authentication</span>
              </div>
              <div className="text-sm font-bold text-white">gMSA / OpenBao Secret Vault</div>
              <div className="text-xs text-slate-400 mt-1">Provider: Dynamic Runtime Injection</div>
              <div className="text-xs text-slate-500 mt-0.5">Zero plaintext passwords stored on disk</div>
            </div>

            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-200">
              <div className="flex items-center gap-2 text-xs font-semibold text-amber-400 mb-1">
                <Lock className="w-4 h-4" />
                <span>Zero-Trust Policy Matrix</span>
              </div>
              <div className="text-sm font-bold text-white">Tier-0 Guard Enforced</div>
              <div className="text-xs text-slate-400 mt-1">Domain Admins & Schema Admins Protected</div>
              <div className="text-xs text-slate-500 mt-0.5">Mandatory Change Ticket on Modifications</div>
            </div>
          </div>

          {/* Service Accounts RBAC Matrix */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/90 overflow-hidden">
            <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Configured Service Account Allowlist</h3>
              <span className="text-xs text-slate-400">Granular LDAPS Command Matrix</span>
            </div>

            <div className="divide-y divide-slate-800 text-xs">
              {/* Account 1 */}
              <div className="p-5 space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-emerald-400 text-sm">ai-triage-agent</span>
                      <span className="text-[11px] text-slate-400">· SOC Automated Incident Response</span>
                    </div>
                    <p className="text-slate-400 text-xs mt-0.5">
                      Authorized for security analysis, directory reconnaissance, and host quarantine.
                    </p>
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded">
                    Active Allowlist
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400 block mb-1.5">Permitted Commands (9):</span>
                    <div className="flex flex-wrap gap-1.5">
                      {[
                        'get_domain_info',
                        'search_users',
                        'get_user_attributes',
                        'check_user_membership',
                        'list_group_members',
                        'search_groups',
                        'get_group_details',
                        'search_computers',
                        'disable_account'
                      ].map((cmd) => (
                        <span key={cmd} className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-200">
                          {cmd}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-[11px] font-semibold text-rose-400 block mb-1.5">Explicitly Denied Commands:</span>
                    <div className="flex flex-wrap gap-1.5">
                      {['reset_password', 'add_user_to_group'].map((cmd) => (
                        <span key={cmd} className="text-[11px] font-mono px-2 py-0.5 rounded bg-rose-950/60 border border-rose-900 text-rose-300">
                          {cmd}
                        </span>
                      ))}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-2">
                      Rule: <span className="font-mono text-slate-300">disable_account</span> requires IT change ticket ID.
                    </div>
                  </div>
                </div>
              </div>

              {/* Account 2 */}
              <div className="p-5 space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-emerald-400 text-sm">svc-it-helpdesk-agent</span>
                      <span className="text-[11px] text-slate-400">· IT Helpdesk Virtual Assistant</span>
                    </div>
                    <p className="text-slate-400 text-xs mt-0.5">
                      Authorized to unlock locked accounts and manage VPN access with ticket approval.
                    </p>
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded">
                    Active Allowlist
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400 block mb-1.5">Permitted Commands (9):</span>
                    <div className="flex flex-wrap gap-1.5">
                      {[
                        'get_domain_info',
                        'search_users',
                        'get_user_attributes',
                        'check_user_membership',
                        'list_group_members',
                        'add_user_to_group',
                        'remove_user_from_group',
                        'unlock_account',
                        'enable_account'
                      ].map((cmd) => (
                        <span key={cmd} className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-200">
                          {cmd}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-[11px] font-semibold text-amber-400 block mb-1.5">Boundary Constraints:</span>
                    <p className="text-[11px] text-slate-300">
                      Allowed Groups: <span className="font-mono text-emerald-300">VPN-Users, Developers, Helpdesk-Tier1</span>
                    </p>
                    <p className="text-[11px] text-slate-300 mt-1">
                      Restricted Groups: <span className="font-mono text-rose-300">Domain Admins, Enterprise Admins, Administrators</span>
                    </p>
                  </div>
                </div>
              </div>

              {/* Account 3 */}
              <div className="p-5 space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-emerald-400 text-sm">svc-compliance-scanner</span>
                      <span className="text-[11px] text-slate-400">· Read-Only Auditor</span>
                    </div>
                    <p className="text-slate-400 text-xs mt-0.5">
                      Automated security posture scanner for user attributes and OU structures.
                    </p>
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded">
                    Active Allowlist
                  </span>
                </div>

                <div className="pt-2">
                  <span className="text-[11px] font-semibold text-slate-400 block mb-1.5">Permitted Commands (7):</span>
                  <div className="flex flex-wrap gap-1.5">
                    {[
                      'get_domain_info',
                      'search_users',
                      'get_user_attributes',
                      'get_organizational_units',
                      'search_groups',
                      'list_group_members',
                      'search_computers'
                    ].map((cmd) => (
                      <span key={cmd} className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-200">
                        {cmd}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* YAML Configuration Editor */
        <div className="space-y-4">
          <div className="rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 font-mono text-slate-300">
                <FileCode className="w-4 h-4 text-emerald-400" />
                <span>ad_proxy/config.yaml</span>
              </div>
              <button
                onClick={handleSave}
                disabled={saving}
                className="flex items-center gap-1.5 px-3 py-1 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-semibold rounded transition-colors disabled:opacity-50 text-xs whitespace-nowrap shrink-0"
              >
                <Save className="w-3.5 h-3.5" />
                <span>{saving ? 'Validating...' : 'Validate & Apply'}</span>
              </button>
            </div>

            <textarea
              value={yamlContent}
              onChange={(e) => setYamlContent(e.target.value)}
              rows={22}
              className="w-full bg-slate-950 text-slate-100 font-mono text-xs p-4 focus:outline-none resize-y leading-relaxed"
              spellCheck={false}
            />
          </div>

          {checkOutput && (
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/80">
              <div className="text-xs font-semibold text-slate-300 mb-1.5">Configuration Engine Output:</div>
              <pre className="text-[11px] font-mono text-emerald-400 whitespace-pre-wrap">{checkOutput}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
