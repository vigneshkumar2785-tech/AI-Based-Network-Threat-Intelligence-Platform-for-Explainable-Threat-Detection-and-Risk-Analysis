import React, { useState } from 'react';
import { AlertTriangle, ShieldCheck, Clock, CheckCircle2, AlertOctagon, User, ArrowRight, Play } from 'lucide-react';
import { transitionIncidentState } from '../api';

const STATE_COLORS = {
  new: 'bg-rose-50 text-rose-800 border-rose-200',
  investigating: 'bg-amber-50 text-amber-800 border-amber-200',
  contained: 'bg-purple-50 text-purple-800 border-purple-200',
  resolved: 'bg-[#E6F4EA] text-[#00684A] border-[#C1E7D0]',
  closed: 'bg-slate-100 text-slate-600 border-slate-200',
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
    <div className="glass-panel rounded-2xl p-6 border border-[#E1E8E5] bg-white space-y-6 shadow-sm">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#E1E8E5] pb-4">
        <div>
          <h2 className="text-lg font-bold text-[#001E2B] flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-rose-600" />
            SOC Incident Management & Playbooks
          </h2>
          <p className="text-xs text-[#5C6C64] font-mono">
            State machine controls (new → investigating → contained → resolved). All mitigation actions are LOGGED RECOMMENDATIONS.
          </p>
        </div>

        {/* State Filter Tabs */}
        <div className="flex items-center gap-1 font-mono text-xs bg-[#F0F4F2] p-1 rounded-xl border border-[#E1E8E5]">
          {['all', 'new', 'investigating', 'contained', 'resolved'].map((st) => (
            <button
              key={st}
              onClick={() => setActiveFilter(st)}
              className={`px-3 py-1 rounded-lg capitalize transition-all font-semibold ${
                activeFilter === st
                  ? 'bg-[#00684A] text-white font-bold shadow-xs'
                  : 'text-[#5C6C64] hover:text-[#001E2B]'
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
                    ? 'bg-[#E6F4EA] border-[#00684A] shadow-sm font-bold'
                    : 'bg-[#F9FBF9] border-[#E1E8E5] hover:border-[#00684A]/40'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[#00684A]">{inc.incident_id}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${STATE_COLORS[inc.state] || STATE_COLORS.new}`}>
                    {inc.state}
                  </span>
                </div>

                <div className="text-[#001E2B] font-sans font-bold text-sm">
                  {inc.classification?.replace('_', ' ').toUpperCase()}
                </div>

                <div className="flex items-center justify-between text-[10px] text-[#5C6C64] font-semibold">
                  <span>Risk: <strong className="text-rose-700">{inc.risk_score}</strong>/100</span>
                  <span>{new Date(inc.created_at).toLocaleTimeString()}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Incident Detail & State Controls */}
        <div className="lg:col-span-2 space-y-4">
          {selectedIncident ? (
            <div className="p-5 bg-[#F9FBF9] rounded-xl border border-[#E1E8E5] font-mono space-y-5">
              <div className="flex items-center justify-between border-b border-[#E1E8E5] pb-3">
                <div>
                  <span className="text-xs text-[#00684A] font-bold block">{selectedIncident.incident_id}</span>
                  <h3 className="text-base font-bold text-[#001E2B] font-sans">
                    {selectedIncident.classification?.replace('_', ' ').toUpperCase()}
                  </h3>
                </div>
                <div className="text-right">
                  <span className="text-xs text-[#5C6C64] block font-bold">SEVERITY</span>
                  <span className="text-sm font-bold text-rose-700 uppercase">{selectedIncident.severity}</span>
                </div>
              </div>

              {/* State Machine Transition Controls */}
              <div className="p-3 bg-white rounded-xl border border-[#E1E8E5] space-y-2 shadow-xs">
                <span className="text-[#5C6C64] text-xs block font-bold">STATE MACHINE CONTROLS:</span>
                <div className="flex flex-wrap items-center gap-2">
                  {selectedIncident.state === 'new' && (
                    <button
                      onClick={() => handleTransition(selectedIncident, 'investigating')}
                      className="px-3.5 py-1.5 bg-[#00684A] text-white border border-[#00684A] rounded-lg text-xs font-bold hover:bg-[#023430] flex items-center gap-1.5 shadow-xs"
                    >
                      <Play className="w-3.5 h-3.5 text-[#00ED64]" /> Start Investigation
                    </button>
                  )}
                  {selectedIncident.state === 'investigating' && (
                    <button
                      onClick={() => handleTransition(selectedIncident, 'contained')}
                      className="px-3.5 py-1.5 bg-purple-700 text-white border border-purple-700 rounded-lg text-xs font-bold hover:bg-purple-800 flex items-center gap-1.5 shadow-xs"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" /> Contain Incident
                    </button>
                  )}
                  {selectedIncident.state === 'contained' && (
                    <button
                      onClick={() => handleTransition(selectedIncident, 'resolved')}
                      className="px-3.5 py-1.5 bg-[#13AA52] text-white border border-[#13AA52] rounded-lg text-xs font-bold hover:bg-[#00684A] flex items-center gap-1.5 shadow-xs"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" /> Mark Resolved
                    </button>
                  )}
                  <span className="text-[#5C6C64] text-[11px] font-bold ml-auto">Current: {selectedIncident.state.toUpperCase()}</span>
                </div>
              </div>

              {/* Recommended Playbook Actions */}
              <div className="space-y-2">
                <span className="text-[#5C6C64] text-xs block font-bold">RECOMMENDED PLAYBOOK ACTIONS:</span>
                <div className="space-y-2">
                  {(selectedIncident.recommended_actions || []).map((act, idx) => (
                    <div key={idx} className="p-3 bg-white rounded-lg border border-[#E1E8E5] text-xs flex items-center justify-between shadow-xs">
                      <div className="space-y-0.5">
                        <span className="text-[#00684A] font-bold block text-xs">{act.action}</span>
                        <span className="text-[#1C2D27] font-sans font-medium">{act.description}</span>
                      </div>
                      <span className="px-2 py-0.5 bg-[#E6F4EA] text-[#00684A] text-[10px] rounded font-bold border border-[#C1E7D0]">
                        Priority {act.priority}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-[#5C6C64] font-mono text-xs">
              Select an incident from the list to view details & playbooks.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
