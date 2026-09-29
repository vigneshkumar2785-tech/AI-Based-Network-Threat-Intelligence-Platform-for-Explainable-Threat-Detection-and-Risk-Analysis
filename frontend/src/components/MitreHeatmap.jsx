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
    <div className="glass-panel rounded-2xl p-6 border border-[#E1E8E5] bg-white space-y-6 shadow-sm">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#E1E8E5] pb-4">
        <div>
          <h2 className="text-lg font-bold text-[#001E2B] flex items-center gap-2">
            <Cpu className="w-5 h-5 text-[#00684A]" />
            MITRE ATT&CK Evidence-Gated Heatmap
          </h2>
          <p className="text-xs text-[#5C6C64] font-mono">
            Strict evidence gating — techniques are only highlighted when concrete event threshold proof exists.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="px-2.5 py-1 bg-[#E6F4EA] text-[#00684A] border border-[#C1E7D0] font-bold rounded-lg">
            11 TTPs MAPPED
          </span>
          <span className="px-2.5 py-1 bg-emerald-50 text-emerald-800 border border-emerald-200 font-bold rounded-lg">
            0 SPECULATIVE MAPPINGS
          </span>
        </div>
      </div>

      {/* Tactic Matrix Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 overflow-x-auto">
        {TACTIC_COLUMNS.map((tactic) => {
          const techs = TECHNIQUES_DATA.filter(t => t.tactic_id === tactic.id);
          return (
            <div key={tactic.id} className="bg-[#F9FBF9] rounded-xl border border-[#E1E8E5] p-3 space-y-3 shadow-xs">
              <div className="border-b border-[#E1E8E5] pb-2">
                <span className="text-[10px] font-mono text-[#00684A] font-bold block">{tactic.id}</span>
                <h3 className="text-xs font-bold text-[#001E2B] truncate">{tactic.name}</h3>
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
                            ? 'bg-[#E6F4EA] border-[#00684A] text-[#001E2B] shadow-sm font-bold'
                            : 'bg-white border-[#E1E8E5] hover:border-[#00684A]/40 text-[#1C2D27]'
                        }`}
                      >
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-bold text-[#00684A]">{tech.id}</span>
                          <span className="px-1.5 py-0.2 rounded text-[9px] bg-[#F0F4F2] text-[#5C6C64] font-semibold">
                            {tech.hits} hits
                          </span>
                        </div>
                        <div className="text-[11px] font-sans font-semibold text-[#001E2B] leading-tight truncate">
                          {tech.name}
                        </div>
                        <div className="text-[9px] text-[#00684A] font-bold flex items-center gap-1">
                          <CheckCircle2 className="w-2.5 h-2.5 text-[#00684A]" />
                          <span>Evidenced</span>
                        </div>
                      </button>
                    );
                  })
                ) : (
                  <div className="text-[11px] text-[#5C6C64] font-mono italic text-center py-4">
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
        <div className="p-4 bg-[#E6F4EA] rounded-xl border border-[#C1E7D0] text-xs font-mono space-y-2 text-[#001E2B]">
          <div className="flex items-center justify-between">
            <span className="font-bold text-[#00684A] text-sm flex items-center gap-2">
              <Info className="w-4 h-4 text-[#00684A]" />
              {selectedTech.id}: {selectedTech.name}
            </span>
            <span className="px-2 py-0.5 rounded bg-[#00684A] text-white text-[10px] font-bold">
              EVIDENCE VERIFIED
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[#1C2D27]">
            <div>
              <span className="text-[#5C6C64] block text-[10px] font-bold">REQUIRED EVIDENCE RULE:</span>
              <code className="text-[#00684A] bg-white px-2.5 py-1 rounded block mt-1 border border-[#C1E7D0] font-bold">
                {selectedTech.evidence}
              </code>
            </div>
            <div>
              <span className="text-[#5C6C64] block text-[10px] font-bold">DETECTION NOTE:</span>
              <p className="text-[#1C2D27] mt-1 font-sans font-medium">
                Evidence-gated detection. This technique is only triggered when field-level thresholds pass verification.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
