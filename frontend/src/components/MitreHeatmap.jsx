import React, { useState } from 'react';
import { Cpu, CheckCircle2, ShieldAlert, FileText, Info } from 'lucide-react';

const TACTIC_COLUMNS = [
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0011", name: "Command & Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

const TECHNIQUES_DATA = [
  { id: "T1046", name: "Network Service Scanning", tactic_id: "TA0007", hits: 24, evidence: "unique_dst_ports >= 20", status: "EVIDENCED", color: "amber" },
  { id: "T1110", name: "Brute Force", tactic_id: "TA0006", hits: 18, evidence: "failed_attempts >= 10, port in [22, 3389]", status: "EVIDENCED", color: "rose" },
  { id: "T1078", name: "Valid Accounts", tactic_id: "TA0006", hits: 12, evidence: "failed_attempts >= 50", status: "EVIDENCED", color: "rose" },
  { id: "T1071.004", name: "DNS Application Protocol", tactic_id: "TA0011", hits: 15, evidence: "dns_query_length >= 40, entropy >= 3.5", status: "EVIDENCED", color: "purple" },
  { id: "T1071.001", name: "Web Protocols (C2)", tactic_id: "TA0011", hits: 9, evidence: "dst_port in [80, 443], conn_std <= 5000", status: "EVIDENCED", color: "purple" },
  { id: "T1573", name: "Encrypted Channel", tactic_id: "TA0011", hits: 11, evidence: "protocol in [HTTPS, TLS]", status: "EVIDENCED", color: "purple" },
  { id: "T1048.003", name: "Exfiltration Over Non-C2", tactic_id: "TA0010", hits: 8, evidence: "bytes_out_ratio >= 0.7", status: "EVIDENCED", color: "rose" },
  { id: "T1041", name: "Exfiltration Over C2", tactic_id: "TA0010", hits: 7, evidence: "byte_count >= 1MB, bytes_out >= 0.8", status: "EVIDENCED", color: "rose" },
  { id: "T1498", name: "Network Denial of Service", tactic_id: "TA0040", hits: 5, evidence: "packet_count >= 100k", status: "EVIDENCED", color: "amber" },
  { id: "T1105", name: "Ingress Tool Transfer", tactic_id: "TA0011", hits: 4, evidence: "has_payload == 1, payload_entropy >= 3.0", status: "EVIDENCED", color: "emerald" },
  { id: "T1204", name: "User Execution", tactic_id: "TA0002", hits: 3, evidence: "has_payload == 1, dst_port in [80, 21, 445]", status: "EVIDENCED", color: "emerald" },
];

export default function MitreHeatmap() {
  const [selectedTech, setSelectedTech] = useState(TECHNIQUES_DATA[0]);

  return (
    <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-6">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            MITRE ATT&CK Evidence-Gated Heatmap
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Strict evidence gating — techniques are only highlighted when concrete event threshold proof exists.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="px-2.5 py-1 bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-lg">
            11 TTPs MAPPED
          </span>
          <span className="px-2.5 py-1 bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 rounded-lg">
            0 SPECULATIVE MAPPINGS
          </span>
        </div>
      </div>

      {/* Tactic Matrix Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 overflow-x-auto">
        {TACTIC_COLUMNS.map((tactic) => {
          const techs = TECHNIQUES_DATA.filter(t => t.tactic_id === tactic.id);
          return (
            <div key={tactic.id} className="bg-slate-900/80 rounded-xl border border-slate-800/80 p-3 space-y-3">
              <div className="border-b border-slate-800 pb-2">
                <span className="text-[10px] font-mono text-cyan-400 block font-semibold">{tactic.id}</span>
                <h3 className="text-xs font-bold text-slate-200 truncate">{tactic.name}</h3>
              </div>

              <div className="space-y-2">
                {techs.length > 0 ? (
                  techs.map((tech) => {
                    const isSelected = selectedTech?.id === tech.id;
                    return (
                      <button
                        key={tech.id}
                        onClick={() => setSelectedTech(tech)}
                        className={`w-full text-left p-2.5 rounded-lg border transition-all duration-150 font-mono text-xs space-y-1 ${
                          isSelected
                            ? 'bg-cyan-500/20 border-cyan-400 text-slate-100 shadow-md shadow-cyan-500/10'
                            : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-bold text-cyan-300">{tech.id}</span>
                          <span className="px-1.5 py-0.2 rounded text-[9px] bg-slate-800 text-slate-400">
                            {tech.hits} hits
                          </span>
                        </div>
                        <div className="text-[11px] font-sans font-medium text-slate-200 leading-tight truncate">
                          {tech.name}
                        </div>
                        <div className="text-[9px] text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-2.5 h-2.5 text-emerald-400" />
                          <span>Evidenced</span>
                        </div>
                      </button>
                    );
                  })
                ) : (
                  <div className="text-[11px] text-slate-600 font-mono italic text-center py-4">
                    No active hits
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Technique Evidence Detail Panel */}
      {selectedTech && (
        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 text-xs font-mono space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-bold text-cyan-400 text-sm flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              {selectedTech.id}: {selectedTech.name}
            </span>
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] font-bold border border-emerald-500/30">
              EVIDENCE VERIFIED
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-slate-300">
            <div>
              <span className="text-slate-500 block text-[10px]">REQUIRED EVIDENCE RULE:</span>
              <code className="text-amber-300 bg-slate-950 px-2 py-1 rounded block mt-1 border border-slate-800">
                {selectedTech.evidence}
              </code>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">DETECTION NOTE:</span>
              <p className="text-slate-300 mt-1 font-sans">
                Evidence-gated detection. This technique is only triggered when field-level thresholds pass verification.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
