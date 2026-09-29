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

  const filtered = SAMPLE_IOCS.filter(ioc => {
    const matchesSearch = ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          ioc.context.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSearch;
  });

  return (
    <div className="glass-panel rounded-2xl p-6 border border-[#E1E8E5] bg-white space-y-6 shadow-sm">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#E1E8E5] pb-4">
        <div>
          <h2 className="text-lg font-bold text-[#001E2B] flex items-center gap-2">
            <Database className="w-5 h-5 text-[#00684A]" />
            Threat Indicators of Compromise (IOC Feed)
          </h2>
          <p className="text-xs text-[#5C6C64] font-mono">
            Extracted IP addresses, DGA domains, payload hashes & test artifacts with reputation scores.
          </p>
        </div>

        {/* Search Bar */}
        <div className="flex items-center gap-3 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-[#5C6C64]" />
            <input
              type="text"
              placeholder="Search IP, domain, hash..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#F9FBF9] border border-[#E1E8E5] rounded-xl pl-9 pr-3 py-1.5 text-xs text-[#001E2B] font-mono focus:outline-none focus:border-[#00684A]"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-[#E1E8E5]">
        <table className="w-full text-left font-mono text-xs">
          <thead className="bg-[#F0F4F2] text-[#001E2B] uppercase text-[10px] border-b border-[#E1E8E5] font-bold">
            <tr>
              <th className="p-3">Type</th>
              <th className="p-3">Indicator Value</th>
              <th className="p-3">Reputation</th>
              <th className="p-3">Score</th>
              <th className="p-3">Context</th>
              <th className="p-3">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E1E8E5] bg-white">
            {filtered.map((ioc) => (
              <tr key={ioc.id} className="hover:bg-[#F9FBF9] transition-colors">
                <td className="p-3 font-bold text-[#00684A] uppercase">{ioc.ioc_type}</td>
                <td className="p-3 font-bold text-[#001E2B]">{ioc.value}</td>
                <td className="p-3">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                    ioc.reputation === 'malicious' ? 'bg-rose-50 text-rose-800 border-rose-200' :
                    ioc.reputation === 'test_artifact' ? 'bg-[#E6F4EA] text-[#00684A] border-[#C1E7D0]' :
                    ioc.reputation === 'suspicious' ? 'bg-amber-50 text-amber-800 border-amber-200' :
                    'bg-slate-100 text-slate-700 border-slate-200'
                  }`}>
                    {ioc.reputation}
                  </span>
                </td>
                <td className="p-3 font-bold text-rose-700">{(ioc.score * 100).toFixed(0)}%</td>
                <td className="p-3 text-[#1C2D27] font-sans text-[11px] font-medium">{ioc.context}</td>
                <td className="p-3 text-[#5C6C64] text-[10px] font-semibold">{ioc.last_seen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
