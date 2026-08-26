import React, { useState } from 'react';
import { Radio, Play, ShieldAlert, CheckCircle2, Zap, FileCode, RefreshCw } from 'lucide-react';
import { triggerSyntheticEvent } from '../api';

const SCENARIOS = [
  { id: 'port_scan', label: 'Port Scan Recon', icon: Zap, color: 'text-amber-400 border-amber-500/30 bg-amber-500/10', desc: 'Scans 250 ports from external IP. Triggers T1046 recon technique.' },
  { id: 'failed_auth', label: 'Brute-Force SSH', icon: ShieldAlert, color: 'text-rose-400 border-rose-500/30 bg-rose-500/10', desc: '50 failed login attempts on port 22. Triggers T1110 & T1078.' },
  { id: 'dns_anomaly', label: 'DNS Tunneling', icon: Radio, color: 'text-purple-400 border-purple-500/30 bg-purple-500/10', desc: 'High-entropy long subdomains. Triggers T1071.004 & T1048.003.' },
  { id: 'c2_beacon', label: 'C2 Beaconing', icon: Radio, color: 'text-rose-400 border-rose-500/30 bg-rose-500/10', desc: 'Regular low-byte HTTPS heartbeats to C2 server. Triggers T1041.' },
  { id: 'traffic_spike', label: 'Traffic Spike / DoS', icon: Zap, color: 'text-amber-400 border-amber-500/30 bg-amber-500/10', desc: '3GB burst payload over TCP port 8080. Triggers T1498 impact.' },
  { id: 'data_exfil', label: 'Data Exfiltration', icon: ShieldAlert, color: 'text-rose-400 border-rose-500/30 bg-rose-500/10', desc: '135MB egress transfer to external IP. Triggers T1048.003.' },
  { id: 'eicar_test', label: 'EICAR Test Artifact', icon: FileCode, color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10', desc: 'Inert text test string. Demonstrates AV/IDS detection without malware.' },
  { id: 'normal', label: 'Benign Web Traffic', icon: CheckCircle2, color: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10', desc: 'Standard HTTPS request to Google CDN. Verified baseline normal.' },
];

export default function LiveSimulator({ onEventProcessed }) {
  const [loadingType, setLoadingType] = useState(null);

  const handleTrigger = async (type) => {
    setLoadingType(type);
    try {
      const result = await triggerSyntheticEvent(type);
      if (onEventProcessed) {
        onEventProcessed(result);
      }
    } catch (err) {
      console.error("Simulation error:", err);
    } finally {
      setLoadingType(null);
    }
  };

  return (
    <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-6">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
            Live Threat Simulator & Behavioral Engine
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Trigger real-time synthetic events through the ML detection & intelligence correlation pipeline.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/30">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span>SIMULATOR READY</span>
        </div>
      </div>

      {/* Scenario Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {SCENARIOS.map((sc) => {
          const Icon = sc.icon;
          const isLoading = loadingType === sc.id;
          return (
            <button
              key={sc.id}
              onClick={() => handleTrigger(sc.id)}
              disabled={loadingType !== null}
              className={`p-4 rounded-xl border text-left transition-all duration-200 font-mono space-y-3 relative overflow-hidden group ${sc.color} hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50`}
            >
              <div className="flex items-center justify-between">
                <Icon className="w-5 h-5" />
                {isLoading ? (
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                ) : (
                  <Play className="w-4 h-4 opacity-70 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all" />
                )}
              </div>

              <div>
                <h3 className="font-bold text-sm text-slate-100">{sc.label}</h3>
                <p className="text-[11px] text-slate-300 font-sans mt-1 leading-snug">
                  {sc.desc}
                </p>
              </div>

              <div className="text-[10px] text-slate-400 pt-2 border-t border-slate-800/80 flex items-center justify-between">
                <span>Click to Trigger</span>
                <span className="text-cyan-400">POST /events/trigger</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
