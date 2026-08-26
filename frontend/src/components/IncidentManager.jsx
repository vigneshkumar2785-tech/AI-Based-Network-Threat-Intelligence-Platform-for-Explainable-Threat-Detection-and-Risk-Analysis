import React, { useState } from 'react';
import { AlertTriangle, ShieldCheck, Clock, CheckCircle2, AlertOctagon, User, ArrowRight, Play } from 'lucide-react';
import { transitionIncidentState } from '../api';

const STATE_COLORS = {
  new: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
  investigating: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  contained: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  resolved: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  closed: 'bg-slate-800 text-slate-400 border-slate-700',
};

export default function IncidentManager({ incidents = [], onIncidentUpdated }) {
  const [activeFilter, setActiveFilter] = useState('all');
  const [selectedIncident, setSelectedIncident] = useState(incidents[0] || null);

  const filtered = incidents.filter(inc => {
    if (activeFilter === 'all') return true;
    return inc.state === activeFilter;
  });

  const handleTransition = async (inc, nextState) => {
    try {
      const updated = await transitionIncidentState(inc.incident_id, nextState, `State changed to ${nextState} via SOC Console`);
      if (onIncidentUpdated) {
        onIncidentUpdated(updated);
      }
      setSelectedIncident(prev => prev ? { ...prev, state: nextState } : null);
    } catch (err) {
      console.error("Transition error:", err);
    }
  };

  return (
    <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-6">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
            SOC Incident Management & Playbooks
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            State machine controls (new → investigating → contained → resolved). All mitigation actions are LOGGED RECOMMENDATIONS.
          </p>
        </div>

        {/* State Filter Tabs */}
        <div className="flex items-center gap-1 font-mono text-xs bg-slate-900/80 p-1 rounded-xl border border-slate-800">
          {['all', 'new', 'investigating', 'contained', 'resolved'].map((st) => (
            <button
              key={st}
              onClick={() => setActiveFilter(st)}
              className={`px-3 py-1 rounded-lg capitalize transition-all ${
                activeFilter === st
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incident List Column */}
        <div className="lg:col-span-1 space-y-3 overflow-y-auto max-h-[500px]">
          {filtered.map((inc) => {
            const isSelected = selectedIncident?.incident_id === inc.incident_id;
            return (
              <div
                key={inc.id || inc.incident_id}
                onClick={() => setSelectedIncident(inc)}
                className={`p-4 rounded-xl border cursor-pointer font-mono text-xs transition-all space-y-2 ${
                  isSelected
                    ? 'bg-slate-900 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                    : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-cyan-300">{inc.incident_id}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${STATE_COLORS[inc.state] || STATE_COLORS.new}`}>
                    {inc.state}
                  </span>
                </div>

                <div className="text-slate-200 font-sans font-medium text-sm">
                  {inc.classification?.replace('_', ' ').toUpperCase()}
                </div>

                <div className="flex items-center justify-between text-[10px] text-slate-400">
                  <span>Risk: <strong className="text-rose-400">{inc.risk_score}</strong>/100</span>
                  <span>{new Date(inc.created_at).toLocaleTimeString()}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Incident Detail & State Controls */}
        <div className="lg:col-span-2 space-y-4">
          {selectedIncident ? (
            <div className="p-5 bg-slate-900/90 rounded-xl border border-slate-800 font-mono space-y-5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-xs text-cyan-400 font-bold block">{selectedIncident.incident_id}</span>
                  <h3 className="text-base font-bold text-slate-100 font-sans">
                    {selectedIncident.classification?.replace('_', ' ').toUpperCase()}
                  </h3>
                </div>
                <div className="text-right">
                  <span className="text-xs text-slate-400 block">SEVERITY</span>
                  <span className="text-sm font-bold text-rose-400 uppercase">{selectedIncident.severity}</span>
                </div>
              </div>

              {/* State Machine Transition Controls */}
              <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 space-y-2">
                <span className="text-slate-400 text-xs block font-bold">STATE MACHINE CONTROLS:</span>
                <div className="flex flex-wrap items-center gap-2">
                  {selectedIncident.state === 'new' && (
                    <button
                      onClick={() => handleTransition(selectedIncident, 'investigating')}
                      className="px-3 py-1.5 bg-amber-500/20 text-amber-300 border border-amber-500/40 rounded-lg text-xs font-bold hover:bg-amber-500/30 flex items-center gap-1"
                    >
                      <Play className="w-3 h-3" /> Start Investigation
                    </button>
                  )}
                  {selectedIncident.state === 'investigating' && (
                    <button
                      onClick={() => handleTransition(selectedIncident, 'contained')}
                      className="px-3 py-1.5 bg-purple-500/20 text-purple-300 border border-purple-500/40 rounded-lg text-xs font-bold hover:bg-purple-500/30 flex items-center gap-1"
                    >
                      <ShieldCheck className="w-3 h-3" /> Contain Incident
                    </button>
                  )}
                  {selectedIncident.state === 'contained' && (
                    <button
                      onClick={() => handleTransition(selectedIncident, 'resolved')}
                      className="px-3 py-1.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-bold hover:bg-emerald-500/30 flex items-center gap-1"
                    >
                      <CheckCircle2 className="w-3 h-3" /> Mark Resolved
                    </button>
                  )}
                  <span className="text-slate-500 text-[10px] ml-auto">Current: {selectedIncident.state.toUpperCase()}</span>
                </div>
              </div>

              {/* Recommended Playbook Actions */}
              <div className="space-y-2">
                <span className="text-slate-400 text-xs block font-bold">RECOMMENDED PLAYBOOK ACTIONS:</span>
                <div className="space-y-2">
                  {(selectedIncident.recommended_actions || []).map((act, idx) => (
                    <div key={idx} className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800 text-xs flex items-center justify-between">
                      <div className="space-y-0.5">
                        <span className="text-cyan-400 font-bold block">{act.action}</span>
                        <span className="text-slate-300 font-sans">{act.description}</span>
                      </div>
                      <span className="px-2 py-0.5 bg-slate-800 text-slate-400 text-[10px] rounded">
                        Priority {act.priority}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">
              Select an incident from the list to view details & playbooks.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
