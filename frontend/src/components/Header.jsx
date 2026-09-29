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
    <header className="sticky top-0 z-50 bg-[#001E2B] text-slate-100 px-4 py-3 shadow-md border-b border-[#003847]">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand & Status (MongoDB LeafyGreen style) */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-[#00684A]/60 border border-[#00ED64]/40 rounded-xl text-[#00ED64] shadow-sm shadow-[#00ED64]/20">
            <Shield className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap">
              <h1 className="font-bold text-base sm:text-lg tracking-tight text-white whitespace-nowrap flex items-center gap-1.5">
                Aegis <span className="text-[#00ED64]">Threat Intelligence</span>
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-[#00ED64]/20 text-[#00ED64] border border-[#00ED64]/40 rounded-full whitespace-nowrap">
                MONGODB THEME
              </span>
            </div>
            <p className="text-xs text-slate-300 flex items-center gap-2 font-mono">
              <span className="w-2 h-2 rounded-full bg-[#00ED64] inline-block animate-ping" />
              <span>SOC PLATFORM OPERATIONAL</span>
              <span className="text-slate-500">|</span>
              <span className="text-[#00ED64]">ML INFERENCE ACTIVE</span>
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
                className={`relative px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-150 flex items-center gap-1.5 whitespace-nowrap ${
                  isActive
                    ? 'bg-[#00ED64] text-[#001E2B] shadow-sm shadow-[#00ED64]/30 font-bold'
                    : 'text-slate-300 hover:text-white hover:bg-[#003847]/70 border border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-[#001E2B]' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
                {tab.badge > 0 && (
                  <span className={`ml-1 px-1.5 py-0.2 text-[10px] font-mono font-bold rounded-full ${
                    isActive ? 'bg-[#001E2B] text-[#00ED64]' : 'bg-rose-500 text-white'
                  }`}>
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
