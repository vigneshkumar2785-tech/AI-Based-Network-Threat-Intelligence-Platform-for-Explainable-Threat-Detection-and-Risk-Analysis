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
    <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-6">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <FileCode className="w-5 h-5 text-emerald-400" />
            EICAR Anti-Virus Security Sandbox
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Standard AV test artifact verification. Treated exclusively as INERT TEXT DATA — never executed as binary code.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/30">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>ZERO HOST RISK — INERT DATA</span>
        </div>
      </div>

      {/* Explanation Banner */}
      <div className="p-4 bg-emerald-950/40 border border-emerald-500/30 rounded-xl space-y-2 text-xs font-mono text-emerald-200">
        <div className="flex items-center gap-2 font-bold text-emerald-400 text-sm">
          <ShieldCheck className="w-4 h-4" />
          Why EICAR Test Data?
        </div>
        <p className="font-sans leading-relaxed text-emerald-300">
          The EICAR standard test string is universally accepted by anti-virus & intrusion detection systems to verify detection pipelines without sourcing or handling actual malicious code. In this platform, payload analysis is performed exclusively via string entropy and hash matching.
        </p>
      </div>

      {/* String Inspection Box */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400">
          <span>EICAR Standard String Content (68 bytes ASCII):</span>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy String'}</span>
          </button>
        </div>
        <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-amber-300 break-all select-all">
          {EICAR_TEXT}
        </div>
      </div>

      {/* Hashes & Metadata */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
        <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800 space-y-1">
          <span className="text-slate-500 text-[10px] block">MD5 HASH:</span>
          <code className="text-cyan-400">44d88612fea8a8f36de82e1278abb02f</code>
        </div>
        <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800 space-y-1">
          <span className="text-slate-500 text-[10px] block">SHA-256 HASH:</span>
          <code className="text-cyan-400">275a021bbfb6489e54d471899f7db9d1663fc695...</code>
        </div>
      </div>

      {/* Trigger Sandbox Test Action */}
      <div className="flex items-center justify-between pt-2">
        <button
          onClick={handleRunSandboxTest}
          disabled={running}
          className="px-5 py-2.5 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-xl font-mono text-xs font-bold hover:bg-emerald-500/30 transition-all flex items-center gap-2 shadow-lg shadow-emerald-500/10"
        >
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span>{running ? 'Ingesting Payload...' : 'Run EICAR Detection Sandbox Test'}</span>
        </button>

        {testResult && (
          <div className="text-xs font-mono text-emerald-400 flex items-center gap-2">
            <Check className="w-4 h-4 text-emerald-400" />
            <span>Classification: {testResult.classification.toUpperCase()} (100% confidence)</span>
          </div>
        )}
      </div>
    </div>
  );
}
