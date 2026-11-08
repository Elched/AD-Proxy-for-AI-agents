import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Send,
  Lock,
  User,
  Terminal,
  FileCheck,
  ChevronRight,
  Database,
  RefreshCw,
  Copy,
  Check
} from 'lucide-react';
import { CommandMeta, ProxyExecutionResult } from '../types';

interface AgentSimulatorProps {
  commands: CommandMeta[];
  onExecutionCompleted?: () => void;
}

const PRESET_ACCOUNTS = [
  {
    id: 'ai-triage-agent',
    label: 'ai-triage-agent (SOC Incident Response)',
    defaultPassword: 'AgentSecurePassword2026!',
    description: 'Permitted: read directory, inspect users/groups, quarantine/disable accounts.',
  },
  {
    id: 'svc-it-helpdesk-agent',
    label: 'svc-it-helpdesk-agent (Helpdesk Bot)',
    defaultPassword: 'HelpdeskSecretToken2026#',
    description: 'Permitted: unlock accounts, manage VPN-Users group (requires ticket ID).',
  },
  {
    id: 'svc-compliance-scanner',
    label: 'svc-compliance-scanner (Audit Scanner)',
    defaultPassword: 'StandardUserPass1!',
    description: 'Permitted: read-only directory enumeration.',
  },
  {
    id: 'unauthorized-agent',
    label: 'unauthorized-agent (Unregistered Rogue Account)',
    defaultPassword: 'WrongPassword999!',
    description: 'Not in allowlist: Will be blocked with 403 Forbidden.',
  },
];

export const AgentSimulator: React.FC<AgentSimulatorProps> = ({
  commands,
  onExecutionCompleted,
}) => {
  const [callerAccount, setCallerAccount] = useState('ai-triage-agent');
  const [password, setPassword] = useState('AgentSecurePassword2026!');
  const [selectedCommand, setSelectedCommand] = useState('list_group_members');
  const [ticketId, setTicketId] = useState('INC-2026-8819');
  const [parameters, setParameters] = useState<Record<string, any>>({
    group_name: 'VPN-Users',
    recursive: false,
  });

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ProxyExecutionResult | null>(null);
  const [copied, setCopied] = useState(false);

  // When caller changes, update default password
  const handleAccountChange = (accId: string) => {
    setCallerAccount(accId);
    const found = PRESET_ACCOUNTS.find((a) => a.id === accId);
    if (found) {
      setPassword(found.defaultPassword);
    }
  };

  // When command changes, set default parameters
  const handleCommandChange = (cmdName: string) => {
    setSelectedCommand(cmdName);
    const cmd = commands.find((c) => c.name === cmdName);
    if (!cmd) return;

    if (cmdName === 'list_group_members') {
      setParameters({ group_name: 'VPN-Users', recursive: false });
    } else if (cmdName === 'search_users') {
      setParameters({ query: 'Rivera', department: 'Engineering', enabled_only: false });
    } else if (cmdName === 'get_user_attributes') {
      setParameters({ user_identifier: 'alex.rivera' });
    } else if (cmdName === 'check_user_membership') {
      setParameters({ user_identifier: 'alex.rivera', group_name: 'VPN-Users' });
    } else if (cmdName === 'add_user_to_group') {
      setParameters({ user_identifier: 'sarah.chen', group_name: 'VPN-Users' });
    } else if (cmdName === 'disable_account') {
      setParameters({ user_identifier: 'alex.rivera', reason: 'Security Quarantine' });
    } else if (cmdName === 'reset_password') {
      setParameters({ user_identifier: 'alex.rivera', new_password: 'ComplexSecretPassword2026!' });
    } else if (cmdName === 'get_domain_info') {
      setParameters({});
    } else {
      const initial: Record<string, any> = {};
      cmd.required_params.forEach((p) => {
        initial[p] = p.includes('group') ? 'VPN-Users' : p.includes('user') ? 'alex.rivera' : 'test';
      });
      setParameters(initial);
    }
  };

  const handleExecute = async () => {
    setLoading(true);
    setResult(null);

    try {
      const res = await fetch('/api/proxy/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          caller_account: callerAccount,
          caller_password: password,
          command: selectedCommand,
          parameters,
          ticket_id: ticketId || null,
        }),
      });

      const data = await res.json();
      setResult(data);
      if (onExecutionCompleted) {
        onExecutionCompleted();
      }
    } catch (err: any) {
      setResult({
        success: false,
        status_code: 'CLIENT_ERROR',
        message: err.message || 'Network request failed',
      });
    } finally {
      setLoading(false);
    }
  };

  const copyResultJson = () => {
    if (!result) return;
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const activeCmdMeta = commands.find((c) => c.name === selectedCommand);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Left Column: AI Agent Query Configuration Form */}
      <div className="lg:col-span-6 space-y-5">
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <div>
              <h2 className="text-base font-semibold text-white">AI Agent Query Simulator</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Simulate an autonomous AI agent authenticating and executing Active Directory commands.
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs text-emerald-400 font-mono">
              <Lock className="w-3.5 h-3.5" />
              <span>LDAPS Mutual TLS</span>
            </div>
          </div>

          <div className="space-y-4 text-xs">
            {/* 1. Service Account Selector */}
            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Calling Service Account (AI Agent Identity)
              </label>
              <select
                value={callerAccount}
                onChange={(e) => handleAccountChange(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                {PRESET_ACCOUNTS.map((acc) => (
                  <option key={acc.id} value={acc.id}>
                    {acc.label}
                  </option>
                ))}
              </select>
              <p className="text-[11px] text-slate-400 mt-1">
                {PRESET_ACCOUNTS.find((a) => a.id === callerAccount)?.description}
              </p>
            </div>

            {/* 2. AD Credentials */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  AD Password (Bound to DC)
                </label>
                <div className="relative">
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                    placeholder="Enter AD service account password"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  IT Approval Ticket ID (Mandatory for Writes)
                </label>
                <input
                  type="text"
                  value={ticketId}
                  onChange={(e) => setTicketId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                  placeholder="e.g. INC-2026-8819 or CHG-9901"
                />
              </div>
            </div>

            {/* Quick Test Credential Failures & Rogue Agent Attacks */}
            <div className="space-y-1.5 pt-1 text-[11px] text-slate-400">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-slate-500">Quick tests:</span>
                <button
                  type="button"
                  onClick={() => setPassword('WrongPassword123!')}
                  className="hover:text-amber-400 underline transition-colors"
                >
                  Bad Password
                </button>
                <span aria-hidden="true">·</span>
                <button
                  type="button"
                  onClick={() => setTicketId('')}
                  className="hover:text-amber-400 underline transition-colors"
                >
                  Omit Ticket
                </button>
                <span aria-hidden="true">·</span>
                <button
                  type="button"
                  onClick={() => {
                    const found = PRESET_ACCOUNTS.find((a) => a.id === callerAccount);
                    if (found) setPassword(found.defaultPassword);
                    setTicketId('INC-2026-8819');
                  }}
                  className="hover:text-emerald-400 underline transition-colors"
                >
                  Reset Valid
                </button>
              </div>

              {/* Rogue Agent Attack Simulation Buttons */}
              <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-slate-800/60">
                <span className="text-rose-400 font-semibold">Simulate Rogue Agent:</span>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedCommand('reset_password');
                    setParameters({
                      user_identifier: 'administrator',
                      new_password: 'CompromisedPass123!'
                    });
                  }}
                  className="text-rose-300 hover:text-rose-200 bg-rose-950/80 hover:bg-rose-900 border border-rose-800/80 px-2 py-0.5 rounded text-[10px] font-semibold transition-colors"
                >
                  Reset Admin Password (Sev 10)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedCommand('add_user_to_group');
                    setParameters({
                      group_name: 'Domain Administrators',
                      user_identifier: 'ai-triage-agent'
                    });
                  }}
                  className="text-rose-300 hover:text-rose-200 bg-rose-950/80 hover:bg-rose-900 border border-rose-800/80 px-2 py-0.5 rounded text-[10px] font-semibold transition-colors"
                >
                  Tamper Domain Admins (Sev 10)
                </button>
              </div>
            </div>

            {/* 3. Command Selector */}
            <div className="pt-2 border-t border-slate-800">
              <div className="flex items-center justify-between mb-1">
                <label className="block text-slate-300 font-medium">
                  Active Directory LDAPS Command
                </label>
                {activeCmdMeta && (
                  <span className={`text-[11px] font-mono px-2 py-0.5 rounded ${
                    activeCmdMeta.risk_level === 'LOW'
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : activeCmdMeta.risk_level === 'MEDIUM'
                      ? 'bg-blue-950 text-blue-400 border border-blue-800'
                      : activeCmdMeta.risk_level === 'HIGH'
                      ? 'bg-amber-950 text-amber-400 border border-amber-800'
                      : 'bg-rose-950 text-rose-400 border border-rose-800'
                  }`}>
                    {activeCmdMeta.risk_level} RISK
                  </span>
                )}
              </div>

              <select
                value={selectedCommand}
                onChange={(e) => handleCommandChange(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
              >
                {commands.map((cmd) => (
                  <option key={cmd.name} value={cmd.name}>
                    {cmd.name} ({cmd.category}) - {cmd.description}
                  </option>
                ))}
              </select>
            </div>

            {/* 4. Dynamic Parameter Inputs */}
            <div className="space-y-3 p-3.5 rounded-md bg-slate-950/80 border border-slate-800/80">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-300">
                  Command Parameters (RFC 4515 Escaped)
                </span>
                {/* Privilege Escalation Shortcut Button */}
                {parameters.group_name && (
                  <button
                    type="button"
                    onClick={() =>
                      setParameters({ ...parameters, group_name: 'Domain Admins' })
                    }
                    className="text-[11px] text-rose-400 hover:text-rose-300 underline"
                  >
                    Test Protected Group ("Domain Admins")
                  </button>
                )}
              </div>

              {Object.keys(parameters).length === 0 ? (
                <p className="text-[11px] text-slate-500 italic">No required parameters for this command.</p>
              ) : (
                Object.entries(parameters).map(([key, val]) => (
                  <div key={key} className="space-y-1">
                    <label className="text-[11px] text-slate-400 font-mono flex items-center justify-between">
                      <span>{key}</span>
                      {activeCmdMeta?.required_params.includes(key) && (
                        <span className="text-amber-400 text-[10px]">required</span>
                      )}
                    </label>
                    {typeof val === 'boolean' ? (
                      <select
                        value={val ? 'true' : 'false'}
                        onChange={(e) =>
                          setParameters({ ...parameters, [key]: e.target.value === 'true' })
                        }
                        className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-100 text-xs"
                      >
                        <option value="false">false</option>
                        <option value="true">true</option>
                      </select>
                    ) : (
                      <input
                        type="text"
                        value={String(val)}
                        onChange={(e) =>
                          setParameters({ ...parameters, [key]: e.target.value })
                        }
                        className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                      />
                    )}
                  </div>
                ))
              )}
            </div>

            {/* Execute Button */}
            <div className="pt-2">
              <button
                type="button"
                onClick={handleExecute}
                disabled={loading}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-md font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 transition-colors disabled:opacity-50 text-xs"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Processing Secure LDAPS Pipeline...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>Dispatch LDAPS Request Through AD-Proxy</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Right Column: 5-Stage Zero-Trust Verification Pipeline & Result */}
      <div className="lg:col-span-6 space-y-5">
        {/* Pipeline Stage Visualizer */}
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <h3 className="text-base font-semibold text-white">5-Stage Verification Pipeline</h3>
            <span className="text-xs text-slate-400">Zero-Trust Inspection</span>
          </div>

          <div className="space-y-3">
            {/* Stage 1 */}
            <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="mt-0.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="flex-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">1. LDAPS Mutual TLS Handshake</span>
                  <span className="text-[11px] font-mono text-slate-400">TLS 1.2+ / Port 10636</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Secure socket established. Client payload encrypted; plain-text LDAP strictly prohibited.
                </p>
              </div>
            </div>

            {/* Stage 2 */}
            <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="mt-0.5">
                {result ? (
                  result.status_code === 'AUTHENTICATION_FAILED' ? (
                    <XCircle className="w-4 h-4 text-rose-400" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  )
                ) : (
                  <div className="w-4 h-4 rounded-full border border-slate-600" />
                )}
              </div>
              <div className="flex-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">2. AD Domain Controller Credential Bind</span>
                  {result && (
                    <span className={`text-[11px] font-mono ${result.status_code === 'AUTHENTICATION_FAILED' ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {result.status_code === 'AUTHENTICATION_FAILED' ? 'FAILED' : 'VERIFIED'}
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Proxy verifies agent identity against Domain Controllers via secure LDAPS simple bind.
                </p>
              </div>
            </div>

            {/* Stage 3 */}
            <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="mt-0.5">
                {result ? (
                  result.status_code === 'CRITICAL_SECURITY_ALERT' ? (
                    <ShieldAlert className="w-4 h-4 text-rose-500 animate-pulse" />
                  ) : result.status_code === 'FORBIDDEN' || result.status_code === 'INVALID_INPUT' ? (
                    <XCircle className="w-4 h-4 text-rose-400" />
                  ) : result.success ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-600" />
                  )
                ) : (
                  <div className="w-4 h-4 rounded-full border border-slate-600" />
                )}
              </div>
              <div className="flex-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">3. Granular RBAC & Rogue Agent Interceptor</span>
                  {result && (
                    <span className={`text-[11px] font-mono font-bold ${
                      result.status_code === 'CRITICAL_SECURITY_ALERT'
                        ? 'text-rose-400'
                        : result.status_code === 'FORBIDDEN'
                        ? 'text-rose-400'
                        : result.success
                        ? 'text-emerald-400'
                        : 'text-slate-400'
                    }`}>
                      {result.status_code === 'CRITICAL_SECURITY_ALERT'
                        ? '🚨 ROGUE AGENT DETECTED (SEV 10)'
                        : result.status_code === 'FORBIDDEN'
                        ? 'DENIED'
                        : result.success
                        ? 'PASSED'
                        : 'SKIPPED'}
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Evaluates RBAC and intercepts rogue or hallucinating agents attempting attacks on Tier-0 groups/admins.
                </p>
              </div>
            </div>

            {/* Stage 4 */}
            <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="mt-0.5">
                {result ? (
                  result.success ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-600" />
                  )
                ) : (
                  <div className="w-4 h-4 rounded-full border border-slate-600" />
                )}
              </div>
              <div className="flex-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">4. Upstream Query to Domain Controllers</span>
                  {result?.success && (
                    <span className="text-[11px] font-mono text-emerald-400">
                      {result.duration_ms?.toFixed(2)} ms
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Query dispatched via gMSA / OpenBao injected credentials over LDAPS. Results sanitized.
                </p>
              </div>
            </div>

            {/* Stage 5 */}
            <div className="flex items-start gap-3 p-2.5 rounded bg-slate-950/60 border border-slate-800/80">
              <div className="mt-0.5">
                {result?.siem_event ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : (
                  <div className="w-4 h-4 rounded-full border border-slate-600" />
                )}
              </div>
              <div className="flex-1 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">5. SIEM Audit Logging (CEF / ECS)</span>
                  {result?.siem_event && (
                    <span className="text-[11px] font-mono text-emerald-400">LOGGED</span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Audit event streamed to local file, syslog, or SIEM webhook with complete compliance metadata.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Query Response & Audit Preview */}
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <h3 className="text-base font-semibold text-white">Proxy Execution Response</h3>
            {result && (
              <div className="flex items-center gap-3">
                <span className={`text-xs font-mono font-bold ${result.success ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {result.status_code}
                </span>
                <button
                  onClick={copyResultJson}
                  className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            )}
          </div>

          {!result ? (
            <div className="py-12 text-center text-slate-500 text-xs">
              Configure parameters on the left and dispatch an LDAPS request to observe the verification pipeline.
            </div>
          ) : (
            <div className="space-y-3">
              {/* Status Banner */}
              <div
                className={`p-3 rounded border text-xs flex items-start gap-2.5 ${
                  result.success
                    ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
                    : result.status_code === 'CRITICAL_SECURITY_ALERT'
                    ? 'bg-rose-950/70 border-rose-600 text-rose-100 shadow-lg shadow-rose-950/50'
                    : 'bg-rose-950/40 border-rose-800/80 text-rose-200'
                }`}
              >
                {result.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5 animate-pulse" />
                )}
                <div className="flex-1">
                  <div className="font-semibold flex items-center justify-between">
                    <span>{result.message}</span>
                    {result.status_code === 'CRITICAL_SECURITY_ALERT' && (
                      <span className="font-mono text-[10px] bg-rose-900 border border-rose-500 text-rose-100 px-2 py-0.5 rounded font-bold">
                        SEVERITY 10 / CRITICAL
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Request ID: <span className="font-mono">{result.request_id}</span> · Latency: <span className="font-mono tabular-nums">{result.duration_ms?.toFixed(2)} ms</span>
                  </div>
                  {result.status_code === 'CRITICAL_SECURITY_ALERT' && (
                    <div className="mt-2 p-2 rounded bg-rose-950/80 border border-rose-800 text-[11px] text-rose-200 leading-relaxed">
                      <strong className="text-white">Threat Mitigation:</strong> Rogue/hallucinating AI agent activity intercepted. Connection terminated immediately. Threat indicator <code className="bg-slate-950 px-1 py-0.5 rounded text-rose-300">ROGUE_OR_HALLUCINATING_AGENT_DETECTED</code> dispatched to SIEM and SOC alarms.
                    </div>
                  )}
                </div>
              </div>

              {/* Data payload if success */}
              {result.data && (
                <div>
                  <div className="text-[11px] font-semibold text-slate-400 mb-1">
                    Returned Active Directory Data:
                  </div>
                  <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-48">
                    {JSON.stringify(result.data, null, 2)}
                  </pre>
                </div>
              )}

              {/* Emitted SIEM Event */}
              {result.siem_event && (
                <div>
                  <div className="text-[11px] font-semibold text-slate-400 mb-1 flex items-center justify-between">
                    <span>Generated SIEM Audit Record:</span>
                    <span className="text-slate-500 font-mono">Format: ECS JSON</span>
                  </div>
                  <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-300 overflow-x-auto max-h-40">
                    {JSON.stringify(result.siem_event, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
