import React, { useState } from 'react';
import { Database, Search, ShieldAlert, CheckCircle2, FileCode, Filter } from 'lucide-react';

const SAMPLE_IOCS = [
  { id: '1', ioc_type: 'ip', value: '185.220.101.45', reputation: 'malicious', score: 0.95, context: 'Source IP in Port Scan & Credential attack events', last_seen: 'Just now' },
  { id: '2', ioc_type: 'ip', value: '91.108.4.0', reputation: 'malicious', score: 0.92, context: 'Destination IP in C2 Beaconing session', last_seen: '2 mins ago' },
  { id: '3', ioc_type: 'domain', value: '9cwpvhwp.4luzuq.otuznb0v.xyz', reputation: 'suspicious', score: 0.88, context: 'High-entropy DGA domain query', last_seen: '5 mins ago' },
  { id: '4', ioc_type: 'eicar_string', value: '275a021bbfb6489e54d471899f7db9d1', reputation: 'test_artifact', score: 1.00, context: 'EICAR standard anti-virus test string (inert text)', last_seen: '10 mins ago' },
  { id: '5', ioc_type: 'hash_md5', value: '44d88612fea8a8f36de82e1278abb02f', reputation: 'test_artifact', score: 1.00, context: 'EICAR MD5 checksum', last_seen: '10 mins ago' },
  { id: '6', ioc_type: 'ip', value: '8.8.8.8', reputation: 'benign', score: 0.05, context: 'Google Public DNS resolver', last_seen: '15 mins ago' },
];

export default function IocFeed() {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');

  const filtered = SAMPLE_IOCS.filter(ioc => {
    const matchesSearch = ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          ioc.context.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === 'all' || ioc.ioc_type === typeFilter;
    return matchesSearch && matchesType;
  });

  return (
    <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-6">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            Threat Indicators of Compromise (IOC Feed)
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Extracted IP addresses, DGA domains, payload hashes & test artifacts with reputation scores.
          </p>
        </div>

        {/* Search & Filter Bar */}
        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, domain, hash..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500/50"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800/80">
        <table className="w-full text-left font-mono text-xs">
          <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] border-b border-slate-800">
            <tr>
              <th className="p-3">Type</th>
              <th className="p-3">Indicator Value</th>
              <th className="p-3">Reputation</th>
              <th className="p-3">Score</th>
              <th className="p-3">Context</th>
              <th className="p-3">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-950/60">
            {filtered.map((ioc) => (
              <tr key={ioc.id} className="hover:bg-slate-900/40 transition-colors">
                <td className="p-3 font-bold text-cyan-400 uppercase">{ioc.ioc_type}</td>
                <td className="p-3 font-semibold text-slate-100">{ioc.value}</td>
                <td className="p-3">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    ioc.reputation === 'malicious' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                    ioc.reputation === 'test_artifact' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                    ioc.reputation === 'suspicious' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                    'bg-slate-800 text-slate-400'
                  }`}>
                    {ioc.reputation}
                  </span>
                </td>
                <td className="p-3 font-bold text-rose-400">{(ioc.score * 100).toFixed(0)}%</td>
                <td className="p-3 text-slate-400 font-sans text-[11px]">{ioc.context}</td>
                <td className="p-3 text-slate-500 text-[10px]">{ioc.last_seen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
