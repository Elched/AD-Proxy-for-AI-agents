import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  Filter,
  Download,
  RefreshCw,
  Clock,
  User,
  Terminal,
  ExternalLink,
  ChevronRight,
  Eye
} from 'lucide-react';
import { SiemEvent } from '../types';

export const SiemAuditStream: React.FC = () => {
  const [events, setEvents] = useState<SiemEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [outcomeFilter, setOutcomeFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<SiemEvent | null>(null);
  const [viewFormat, setViewFormat] = useState<'ecs' | 'cef'>('ecs');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/proxy/siem-logs');
      const data = await res.json();
      setEvents(data.events || []);
    } catch (err) {
      console.error('Failed to load SIEM logs', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 8000);
    return () => clearInterval(interval);
  }, []);

  const filteredEvents = events.filter((e) => {
    if (outcomeFilter !== 'ALL') {
      if (outcomeFilter === 'BLOCKED') {
        if (e.outcome === 'SUCCESS') return false;
      } else if (e.outcome !== outcomeFilter) {
        return false;
      }
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchCaller = e.caller_account?.toLowerCase().includes(q);
      const matchCmd = e.command?.toLowerCase().includes(q);
      const matchTarget = e.target_dn?.toLowerCase().includes(q);
      const matchMsg = e.message?.toLowerCase().includes(q);
      return matchCaller || matchCmd || matchTarget || matchMsg;
    }
    return true;
  });

  const exportLogs = () => {
    const jsonStr = JSON.stringify(events, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ad_proxy_audit_log_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toCefFormat = (e: SiemEvent): string => {
    const sev = e.outcome === 'SUCCESS' ? 3 : e.outcome === 'AUTH_FAILED' ? 8 : 7;
    return `CEF:0|EnterpriseSecurity|ActiveDirectoryProxy|1.0|${e.status_code || e.outcome}|${e.command}|${sev}|src=${e.client_ip || '127.0.0.1'} suser=${e.caller_account} cs1Label=Command cs1=${e.command} outcome=${e.outcome} msg=${(e.message || '').replace(/\|/g, '\\|')}`;
  };

  return (
    <div className="space-y-5">
      {/* Header & Filter Controls */}
      <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/90 text-slate-200">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-white">SIEM Security Audit Stream</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Live immutable audit trail of all Active Directory transactions, authentication attempts, and authorization decisions.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={exportLogs}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Audit Trail</span>
            </button>
            <button
              onClick={fetchLogs}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
              title="Refresh log feed"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Filter bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 mt-4 pt-3 border-t border-slate-800 text-xs">
          {/* Outcome Filter */}
          <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-md border border-slate-800">
            {['ALL', 'SUCCESS', 'BLOCKED', 'AUTH_FAILED', 'FORBIDDEN'].map((f) => (
              <button
                key={f}
                onClick={() => setOutcomeFilter(f)}
                className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                  outcomeFilter === f ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {f === 'ALL' ? 'All Events' : f}
              </button>
            ))}
          </div>

          {/* Search box */}
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search caller, command, target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-md pl-8 pr-3 py-1 text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/90 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400">
                <th className="px-4 py-3 font-semibold">Timestamp (UTC)</th>
                <th className="px-4 py-3 font-semibold">Caller Service Account</th>
                <th className="px-4 py-3 font-semibold">AD Command</th>
                <th className="px-4 py-3 font-semibold">Target Object / DN</th>
                <th className="px-4 py-3 font-semibold">Outcome</th>
                <th className="px-4 py-3 font-semibold text-right">Duration</th>
                <th className="px-4 py-3 text-right">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500 font-sans">
                    No transactions matching current filter criteria. Run a simulation query to generate events.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt, idx) => {
                  const isSuccess = evt.outcome === 'SUCCESS';
                  return (
                    <tr
                      key={evt.event_id || idx}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                      onClick={() => setSelectedEvent(evt)}
                    >
                      <td className="px-4 py-2.5 text-[11px] text-slate-400 tabular-nums whitespace-nowrap">
                        {evt.timestamp ? evt.timestamp.replace('T', ' ').slice(0, 19) : 'Just now'}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span className="text-slate-200 font-semibold">{evt.caller_account}</span>
                      </td>
                      <td className="px-4 py-2.5 text-emerald-400 whitespace-nowrap">
                        {evt.command}
                      </td>
                      <td className="px-4 py-2.5 text-slate-400 truncate max-w-xs">
                        {evt.target_dn || '-'}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        <span
                          className={`text-[11px] px-2 py-0.5 rounded ${
                            isSuccess
                              ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/80'
                              : evt.outcome === 'AUTH_FAILED'
                              ? 'bg-rose-950/80 text-rose-400 border border-rose-800/80'
                              : 'bg-amber-950/80 text-amber-400 border border-amber-800/80'
                          }`}
                        >
                          {evt.status_code || evt.outcome}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right tabular-nums text-slate-400 text-[11px]">
                        {evt.duration_ms !== undefined ? `${evt.duration_ms.toFixed(2)} ms` : '-'}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(evt);
                          }}
                          className="p-1 hover:text-emerald-400 text-slate-500"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-2xl w-full p-6 text-xs text-slate-200 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-base font-bold text-white">SIEM Audit Event Inspection</h3>
                <span className="text-xs text-slate-400 font-mono">ID: {selectedEvent.event_id}</span>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white text-base px-2 py-1"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 p-3 bg-slate-950 rounded border border-slate-800">
              <div>
                <span className="text-slate-500 block">Caller Account:</span>
                <span className="font-mono text-emerald-300 font-bold">{selectedEvent.caller_account}</span>
              </div>
              <div>
                <span className="text-slate-500 block">AD Command:</span>
                <span className="font-mono text-white">{selectedEvent.command}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Outcome Status:</span>
                <span className="font-mono font-bold text-amber-300">{selectedEvent.status_code || selectedEvent.outcome}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Execution Latency:</span>
                <span className="font-mono tabular-nums text-slate-200">{selectedEvent.duration_ms?.toFixed(2)} ms</span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-500 block">Reason / Audit Message:</span>
                <span className="text-slate-300">{selectedEvent.message}</span>
              </div>
            </div>

            {/* Format toggle */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300">Raw SIEM Payload</span>
                <div className="flex items-center gap-1 bg-slate-950 p-0.5 rounded border border-slate-800">
                  <button
                    onClick={() => setViewFormat('ecs')}
                    className={`px-2 py-0.5 rounded text-[11px] ${
                      viewFormat === 'ecs' ? 'bg-slate-800 text-white' : 'text-slate-400'
                    }`}
                  >
                    ECS (JSON)
                  </button>
                  <button
                    onClick={() => setViewFormat('cef')}
                    className={`px-2 py-0.5 rounded text-[11px] ${
                      viewFormat === 'cef' ? 'bg-slate-800 text-white' : 'text-slate-400'
                    }`}
                  >
                    CEF (ArcSight/Splunk)
                  </button>
                </div>
              </div>

              <pre className="p-3 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                {viewFormat === 'ecs'
                  ? JSON.stringify(selectedEvent, null, 2)
                  : toCefFormat(selectedEvent)}
              </pre>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium rounded text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
