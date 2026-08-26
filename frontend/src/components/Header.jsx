import React from 'react';
import { Shield, Activity, Radio, Cpu, Network, AlertTriangle, Database, FileCode, Layers } from 'lucide-react';

export default function Header({ activeTab, setActiveTab, liveAlertCount = 0 }) {
  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'simulator', label: 'Live Simulator', icon: Radio },
    { id: 'pipeline', label: 'Detection Pipeline', icon: Layers },
    { id: 'topology', label: 'Network Topology', icon: Network },
    { id: 'incidents', label: 'Incidents & Playbooks', icon: AlertTriangle, badge: liveAlertCount },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Cpu },
    { id: 'eicar', label: 'EICAR Sandbox', icon: FileCode },
    { id: 'iocs', label: 'IOC Feed', icon: Database },
  ];

  return (
    <header className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur-md border-b border-slate-800 text-slate-100 px-4 py-3 shadow-xl">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand & Status */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400 shadow-lg shadow-cyan-500/10">
            <Shield className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-lg tracking-tight bg-gradient-to-r from-cyan-400 via-sky-300 to-emerald-400 bg-clip-text text-transparent">
                Aegis AI Threat Intelligence
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-full">
                PORTFOLIO EDITION
              </span>
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-2 font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block animate-ping" />
              <span>SOC PLATFORM OPERATIONAL</span>
              <span className="text-slate-600">|</span>
              <span className="text-cyan-400">ML INFERENCE ENGINE ACTIVE</span>
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 overflow-x-auto max-w-full pb-1 md:pb-0 scrollbar-none">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`relative px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-200 flex items-center gap-1.5 whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                {tab.badge > 0 && (
                  <span className="ml-1 px-1.5 py-0.2 text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 rounded-full">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
