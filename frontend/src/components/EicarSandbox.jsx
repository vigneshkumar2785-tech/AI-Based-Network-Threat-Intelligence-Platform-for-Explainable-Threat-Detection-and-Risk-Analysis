import React, { useState } from 'react';
import { FileCode, ShieldCheck, AlertTriangle, Copy, Check, Terminal } from 'lucide-react';
import { triggerSyntheticEvent } from '../api';

const EICAR_TEXT = `X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`;

export default function EicarSandbox({ onEventProcessed }) {
  const [copied, setCopied] = useState(false);
  const [running, setRunning] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const handleCopy = () => {
    navigator.clipboard.writeText(EICAR_TEXT);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRunSandboxTest = async () => {
    setRunning(true);
    try {
      const res = await triggerSyntheticEvent('eicar_test');
      setTestResult(res);
      if (onEventProcessed) {
        onEventProcessed(res);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="glass-panel rounded-2xl p-6 border border-[#E1E8E5] bg-white space-y-6 shadow-sm">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#E1E8E5] pb-4">
        <div>
          <h2 className="text-lg font-bold text-[#001E2B] flex items-center gap-2">
            <FileCode className="w-5 h-5 text-[#00684A]" />
            EICAR Anti-Virus Security Sandbox
          </h2>
          <p className="text-xs text-[#5C6C64] font-mono">
            Standard AV test artifact verification. Treated exclusively as INERT TEXT DATA — never executed as binary code.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs text-[#00684A] bg-[#E6F4EA] px-3 py-1.5 rounded-lg border border-[#C1E7D0] font-semibold">
          <ShieldCheck className="w-4 h-4 text-[#00684A]" />
          <span>ZERO HOST RISK — INERT DATA</span>
        </div>
      </div>

      {/* Explanation Banner */}
      <div className="p-4 bg-[#E6F4EA] border border-[#C1E7D0] rounded-xl space-y-2 text-xs font-mono text-[#001E2B]">
        <div className="flex items-center gap-2 font-bold text-[#00684A] text-sm">
          <ShieldCheck className="w-4 h-4" />
          Why EICAR Test Data?
        </div>
        <p className="font-sans leading-relaxed text-[#1C2D27] font-medium">
          The EICAR standard test string is universally accepted by anti-virus & intrusion detection systems to verify detection pipelines without sourcing or handling actual malicious code. In this platform, payload analysis is performed exclusively via string entropy and hash matching.
        </p>
      </div>

      {/* String Inspection Box */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono text-[#5C6C64]">
          <span className="font-bold">EICAR Standard String Content (68 bytes ASCII):</span>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-[#00684A] hover:text-[#023430] font-bold transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy String'}</span>
          </button>
        </div>
        <div className="p-4 bg-[#001E2B] rounded-xl border border-[#003847] font-mono text-xs text-[#00ED64] break-all select-all font-bold">
          {EICAR_TEXT}
        </div>
      </div>

      {/* Hashes & Metadata */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
        <div className="p-3 bg-[#F9FBF9] rounded-xl border border-[#E1E8E5] space-y-1">
          <span className="text-[#5C6C64] text-[10px] block font-bold">MD5 HASH:</span>
          <code className="text-[#00684A] font-bold">44d88612fea8a8f36de82e1278abb02f</code>
        </div>
        <div className="p-3 bg-[#F9FBF9] rounded-xl border border-[#E1E8E5] space-y-1">
          <span className="text-[#5C6C64] text-[10px] block font-bold">SHA-256 HASH:</span>
          <code className="text-[#00684A] font-bold">275a021bbfb6489e54d471899f7db9d1663fc695...</code>
        </div>
      </div>

      {/* Trigger Sandbox Test Action */}
      <div className="flex items-center justify-between pt-2">
        <button
          onClick={handleRunSandboxTest}
          disabled={running}
          className="px-5 py-2.5 bg-[#00684A] text-white rounded-xl font-mono text-xs font-bold hover:bg-[#023430] transition-all flex items-center gap-2 shadow-md shadow-[#00684A]/20"
        >
          <Terminal className="w-4 h-4 text-[#00ED64]" />
          <span>{running ? 'Ingesting Payload...' : 'Run EICAR Detection Sandbox Test'}</span>
        </button>

        {testResult && (
          <div className="text-xs font-mono text-[#00684A] font-bold flex items-center gap-2">
            <Check className="w-4 h-4 text-[#00684A]" />
            <span>Classification: {testResult.classification.toUpperCase()} (100% confidence)</span>
          </div>
        )}
      </div>
    </div>
  );
}
