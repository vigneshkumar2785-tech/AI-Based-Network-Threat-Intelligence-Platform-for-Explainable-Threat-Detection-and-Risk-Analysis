import React, { useState } from 'react';
import { Radio, Play, ShieldAlert, CheckCircle2, Zap, FileCode, RefreshCw } from 'lucide-react';
import { triggerSyntheticEvent } from '../api';

const SCENARIOS = [
  { id: 'port_scan', label: 'Port Scan Recon', icon: Zap, color: 'text-amber-800 border-amber-200 bg-amber-50 hover:bg-amber-100', desc: 'Scans 250 ports from external IP. Triggers T1046 recon technique.' },
  { id: 'failed_auth', label: 'Brute-Force SSH', icon: ShieldAlert, color: 'text-rose-800 border-rose-200 bg-rose-50 hover:bg-rose-100', desc: '50 failed login attempts on port 22. Triggers T1110 & T1078.' },
  { id: 'dns_anomaly', label: 'DNS Tunneling', icon: Radio, color: 'text-purple-800 border-purple-200 bg-purple-50 hover:bg-purple-100', desc: 'High-entropy long subdomains. Triggers T1071.004 & T1048.003.' },
  { id: 'c2_beacon', label: 'C2 Beaconing', icon: Radio, color: 'text-rose-800 border-rose-200 bg-rose-50 hover:bg-rose-100', desc: 'Regular low-byte HTTPS heartbeats to C2 server. Triggers T1041.' },
  { id: 'traffic_spike', label: 'Traffic Spike / DoS', icon: Zap, color: 'text-amber-800 border-amber-200 bg-amber-50 hover:bg-amber-100', desc: '3GB burst payload over TCP port 8080. Triggers T1498 impact.' },
  { id: 'data_exfil', label: 'Data Exfiltration', icon: ShieldAlert, color: 'text-rose-800 border-rose-200 bg-rose-50 hover:bg-rose-100', desc: '135MB egress transfer to external IP. Triggers T1048.003.' },
  { id: 'eicar_test', label: 'EICAR Test Artifact', icon: FileCode, color: 'text-[#00684A] border-[#C1E7D0] bg-[#E6F4EA] hover:bg-[#D2ECD9]', desc: 'Inert text test string. Demonstrates AV/IDS detection without malware.' },
  { id: 'normal', label: 'Benign Web Traffic', icon: CheckCircle2, color: 'text-[#00684A] border-[#C1E7D0] bg-[#E6F4EA] hover:bg-[#D2ECD9]', desc: 'Standard HTTPS request to Google CDN. Verified baseline normal.' },
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
    <div className="glass-panel rounded-2xl p-6 border border-[#E1E8E5] bg-white space-y-6 shadow-sm">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#E1E8E5] pb-4">
        <div>
          <h2 className="text-lg font-bold text-[#001E2B] flex items-center gap-2">
            <Radio className="w-5 h-5 text-[#00684A] animate-pulse" />
            Live Threat Simulator & Behavioral Engine
          </h2>
          <p className="text-xs text-[#5C6C64] font-mono">
            Trigger real-time synthetic events through the ML detection & intelligence correlation pipeline.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs text-[#00684A] bg-[#E6F4EA] px-3 py-1.5 rounded-lg border border-[#C1E7D0] font-semibold">
          <span className="w-2 h-2 rounded-full bg-[#00ED64] animate-ping" />
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
              className={`p-4 rounded-xl border text-left transition-all duration-200 font-mono space-y-3 relative overflow-hidden group shadow-sm ${sc.color} hover:scale-[1.01] active:scale-[0.99] disabled:opacity-50`}
            >
              <div className="flex items-center justify-between">
                <Icon className="w-5 h-5" />
                {isLoading ? (
                  <RefreshCw className="w-4 h-4 animate-spin text-[#00684A]" />
                ) : (
                  <Play className="w-4 h-4 opacity-70 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all text-[#00684A]" />
                )}
              </div>

              <div>
                <h3 className="font-bold text-sm text-[#001E2B]">{sc.label}</h3>
                <p className="text-[11px] text-[#42524B] font-sans mt-1 leading-snug">
                  {sc.desc}
                </p>
              </div>

              <div className="text-[10px] text-[#5C6C64] pt-2 border-t border-slate-200/80 flex items-center justify-between font-semibold">
                <span>Click to Trigger</span>
                <span className="text-[#00684A]">POST /events/trigger</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
