import React from 'react';
import { Activity, ShieldAlert, AlertTriangle, Database, Zap, Cpu, ArrowUpRight } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

const THREAT_COLORS = ['#00684A', '#13AA52', '#00ED64', '#D97706', '#E11D48', '#023430'];

export default function DashboardSummary({ summaryData }) {
  const metrics = summaryData?.metrics || {
    total_events: 12480,
    total_anomalies: 842,
    total_incidents: 14,
    active_incidents: 5,
    avg_risk_score: 42.8,
    total_iocs: 128,
  };

  const chartData = [
    { name: 'Normal', value: 11638 },
    { name: 'Port Scan', value: 210 },
    { name: 'Brute Force', value: 180 },
    { name: 'DNS Tunnel', value: 140 },
    { name: 'C2 Beacon', value: 95 },
    { name: 'Data Exfil', value: 75 },
  ];

  return (
    <div className="space-y-6">
      {/* 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-panel p-5 rounded-2xl border border-[#E1E8E5] bg-white space-y-2 shadow-sm">
          <div className="flex items-center justify-between text-[#5C6C64] font-mono text-xs">
            <span>TOTAL EVENTS</span>
            <Activity className="w-4 h-4 text-[#00684A]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#001E2B]">{metrics.total_events.toLocaleString()}</div>
          <div className="text-[11px] text-[#00684A] font-mono font-medium flex items-center gap-1">
            <ArrowUpRight className="w-3.5 h-3.5 text-[#00684A]" />
            <span>Real-time Netflow Monitoring</span>
          </div>
        </div>

        <div className="glass-panel p-5 rounded-2xl border border-[#E1E8E5] bg-white space-y-2 shadow-sm">
          <div className="flex items-center justify-between text-[#5C6C64] font-mono text-xs">
            <span>ANOMALIES DETECTED</span>
            <Zap className="w-4 h-4 text-amber-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-700">{metrics.total_anomalies.toLocaleString()}</div>
          <div className="text-[11px] text-amber-700 font-mono font-medium">
            Isolation Forest Anomaly Rate: 6.7%
          </div>
        </div>

        <div className="glass-panel p-5 rounded-2xl border border-[#E1E8E5] bg-white space-y-2 shadow-sm">
          <div className="flex items-center justify-between text-[#5C6C64] font-mono text-xs">
            <span>ACTIVE INCIDENTS</span>
            <AlertTriangle className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-700">{metrics.active_incidents}</div>
          <div className="text-[11px] text-rose-700 font-mono font-medium">
            3 Critical, 2 High Priority
          </div>
        </div>

        <div className="glass-panel p-5 rounded-2xl border border-[#E1E8E5] bg-white space-y-2 shadow-sm">
          <div className="flex items-center justify-between text-[#5C6C64] font-mono text-xs">
            <span>AVG RISK SCORE</span>
            <ShieldAlert className="w-4 h-4 text-[#00684A]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#001E2B]">{metrics.avg_risk_score}/100</div>
          <div className="text-[11px] text-[#00684A] font-mono font-medium">
            Weighted Risk Scoring Engine
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Distribution Bar Chart */}
        <div className="glass-panel p-6 rounded-2xl border border-[#E1E8E5] bg-white space-y-4 shadow-sm">
          <h3 className="text-sm font-bold font-mono text-[#001E2B]">Threat Distribution Breakdown</h3>
          <div className="h-[220px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <XAxis dataKey="name" stroke="#5C6C64" fontSize={10} tickLine={false} />
                <YAxis stroke="#5C6C64" fontSize={10} tickLine={false} />
                <Tooltip contentStyle={{ background: '#FFFFFF', borderColor: '#E1E8E5', color: '#001E2B', borderRadius: '8px', fontSize: '12px', boxShadow: '0 4px 12px rgba(0,30,43,0.08)' }} />
                <Bar dataKey="value" fill="#00684A" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Categories Pie */}
        <div className="glass-panel p-6 rounded-2xl border border-[#E1E8E5] bg-white space-y-4 shadow-sm">
          <h3 className="text-sm font-bold font-mono text-[#001E2B]">Threat Event Mix</h3>
          <div className="h-[220px] w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={chartData.slice(1)} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={75} innerRadius={40}>
                  {chartData.slice(1).map((_, index) => (
                    <Cell key={`cell-${index}`} fill={THREAT_COLORS[index % THREAT_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#FFFFFF', borderColor: '#E1E8E5', color: '#001E2B', borderRadius: '8px', fontSize: '12px', boxShadow: '0 4px 12px rgba(0,30,43,0.08)' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
