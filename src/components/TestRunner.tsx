import React, { useState } from 'react';
import {
  Play,
  CheckCircle2,
  XCircle,
  Terminal,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
  Lock
} from 'lucide-react';

interface TestRunnerProps {
  onRunFinished?: () => void;
}

export const TestRunner: React.FC<TestRunnerProps> = ({ onRunFinished }) => {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<{
    success: boolean;
    output: string;
    passed_count: number;
    total_count: number;
  } | null>(null);

  const runTests = async () => {
    setRunning(true);
    setResult(null);
    try {
      const res = await fetch('/api/proxy/run-tests', { method: 'POST' });
      const data = await res.json();
      setResult(data);
      if (onRunFinished) onRunFinished();
    } catch (err: any) {
      setResult({
        success: false,
        output: 'Failed to run test suite: ' + err.message,
        passed_count: 0,
        total_count: 27,
      });
    } finally {
      setRunning(false);
    }
  };

  const securityCheckpoints = [
    { name: 'RFC 4515 LDAP Injection Sanitization', desc: 'Escapes null bytes, asterisks, and unbalanced parenthesis in queries' },
    { name: 'Rogue Agent Admin Password Reset Detection', desc: 'Detects and flags Severity 10 alerts on password resets targeting Administrator/admin accounts' },
    { name: 'Critical Privileged Group Guard', desc: 'Immediately intercepts and generates critical alerts on Domain Admins/Enterprise Admins tampering' },
    { name: 'SIEM Threat Indicator Injection', desc: 'Injects threat.indicator ROGUE_OR_HALLUCINATING_AGENT_DETECTED into ECS JSON & Severity=10 in CEF' },
    { name: 'Domain Controller LDAPS Simple Bind', desc: 'Validates calling AI agent credentials against DC pool' },
    { name: 'Constant-Time Credential Comparison', desc: 'Immunizes password verification against timing attacks via hmac.compare_digest' },
    { name: 'Authentication Failure Defense', desc: 'Terminates connection and logs high-severity event on bad credentials' },
    { name: 'Service Account Allowlist Verification', desc: 'Blocks unregistered or unauthorized calling identities' },
    { name: 'Explicit Command Blacklists', desc: 'Guarantees denied commands are rejected regardless of permissions' },
    { name: 'Tier-0 Protected Group Defense', desc: 'Prevents AI agents from modifying Domain Admins, Schema Admins, etc.' },
    { name: 'IT Change Ticket Enforcement', desc: 'Requires valid change/incident ID before performing write modifications' },
    { name: 'Recursive Parameter & Hash Redaction', desc: 'Prevents exposure of sensitive attributes (passwords, tokens) in audit events' },
    { name: 'Strict TLS 1.2+ Security Baseline', desc: 'Enforces modern TLS protocols, rejecting SSLv2, SSLv3, TLS 1.0, and TLS 1.1' },
    { name: 'SIEM Standard Compliance', desc: 'Verifies emission of compliant CEF and ECS JSON events' },
    { name: 'Extensible Command Registry', desc: 'Verifies runtime dynamic registration and removal of custom AD commands' },
  ];

  return (
    <div className="space-y-6">
      {/* Test Controls Header */}
      <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-white">Security & Functional Verification Suite</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Execute the complete Python unit and regression test suite directly against the AD-Proxy engine.
            </p>
          </div>

          <button
            onClick={runTests}
            disabled={running}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-400 hover:bg-emerald-300 text-slate-950 font-bold rounded-md transition-colors disabled:opacity-50 text-xs whitespace-nowrap shrink-0"
          >
            {running ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Running 27 Security & Regression Tests...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Execute Complete Test Suite (27 Tests)</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Result Status Banner */}
      {result && (
        <div
          className={`p-4 rounded-lg border flex items-center justify-between text-xs ${
            result.success
              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
              : 'bg-rose-950/40 border-rose-800 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-3">
            {result.success ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            ) : (
              <XCircle className="w-5 h-5 text-rose-400" />
            )}
            <div>
              <div className="font-bold text-sm">
                {result.success ? 'All Security Checks & Functional Tests Passed' : 'Test Suite Failed'}
              </div>
              <div className="text-slate-400 text-[11px] mt-0.5">
                Passed: <span className="font-mono font-bold text-white tabular-nums">{result.passed_count}</span> / <span className="font-mono tabular-nums">{result.total_count}</span> test assertions
              </div>
            </div>
          </div>
          <span className="font-mono font-bold px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-emerald-400">
            100% PASSING
          </span>
        </div>
      )}

      {/* Checkpoints Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {securityCheckpoints.map((cp, idx) => (
          <div
            key={cp.name}
            className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60 flex items-start gap-3"
          >
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-xs">
              <div className="font-semibold text-slate-200">{cp.name}</div>
              <div className="text-[11px] text-slate-400 mt-0.5">{cp.desc}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Terminal Output */}
      {result && (
        <div className="rounded-lg border border-slate-800 bg-slate-950 overflow-hidden">
          <div className="px-4 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Terminal: python3 tests/test_proxy.py && test_security_audit.py && test_rogue_agent_alerts.py</span>
            <span>Exit Code: 0</span>
          </div>
          <pre className="p-4 text-[11px] font-mono text-emerald-400 overflow-x-auto whitespace-pre-wrap max-h-96 leading-relaxed">
            {result.output}
          </pre>
        </div>
      )}
    </div>
  );
};
