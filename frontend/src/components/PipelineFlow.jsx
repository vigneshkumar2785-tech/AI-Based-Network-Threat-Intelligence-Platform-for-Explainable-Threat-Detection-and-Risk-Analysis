import React, { useState } from 'react';
import { ReactFlow, Background, Controls } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Layers, Info, CheckCircle2, ShieldAlert, Cpu, Lock, Database } from 'lucide-react';

const initialNodes = [
  {
    id: '1',
    position: { x: 50, y: 150 },
    data: { label: 'Raw Event Ingestion', detail: 'Parses netflow, DNS, and HTTP packets into standardized JSON payloads' },
    style: { background: '#0F172A', color: '#38BDF8', border: '1px solid #0EA5E9', borderRadius: '12px', padding: '12px', width: 180 },
  },
  {
    id: '2',
    position: { x: 270, y: 150 },
    data: { label: 'Feature Preprocessing', detail: '31 canonical features: log counts, ratios, one-hot protocols & Shannon entropy' },
    style: { background: '#0F172A', color: '#A855F7', border: '1px solid #9333EA', borderRadius: '12px', padding: '12px', width: 180 },
  },
  {
    id: '3',
    position: { x: 490, y: 70 },
    data: { label: 'Isolation Forest', detail: 'Unsupervised anomaly detection (200 trees). Flags outlier behavior' },
    style: { background: '#0F172A', color: '#F59E0B', border: '1px solid #D97706', borderRadius: '12px', padding: '12px', width: 180 },
  },
  {
    id: '4',
    position: { x: 490, y: 230 },
    data: { label: 'XGBoost Classifier', detail: 'Multi-class threat classifier (300 trees, depth=6). 8 threat categories' },
    style: { background: '#0F172A', color: '#EF4444', border: '1px solid #DC2626', borderRadius: '12px', padding: '12px', width: 180 },
  },
  {
    id: '5',
    position: { x: 710, y: 150 },
    data: { label: 'IOC Extractor', detail: 'Extracts IP, domain, hash & EICAR string indicators with reputation scoring' },
    style: { background: '#0F172A', color: '#10B981', border: '1px solid #059669', borderRadius: '12px', padding: '12px', width: 180 },
  },
  {
    id: '6',
    position: { x: 930, y: 70 },
    data: { label: 'MITRE ATT&CK Mapper', detail: 'Evidence-gated mapping to 11 TTPs. Requires concrete threshold proof' },
    style: { background: '#0F172A', color: '#6366F1', border: '1px solid #4F46E5', borderRadius: '12px', padding: '12px', width: 180 },
  },
  {
    id: '7',
    position: { x: 930, y: 230 },
    data: { label: 'Risk Scorer & XAI', detail: 'Weighted 0-100 risk score + SHAP feature attributions & LIME rules' },
    style: { background: '#0F172A', color: '#EC4899', border: '1px solid #DB2777', borderRadius: '12px', padding: '12px', width: 180 },
  },
  {
    id: '8',
    position: { x: 1150, y: 150 },
    data: { label: 'Incident Engine', detail: 'State machine management (new->investigating->contained->resolved) + playbooks' },
    style: { background: '#0F172A', color: '#14B8A6', border: '1px solid #0D9488', borderRadius: '12px', padding: '12px', width: 190 },
  },
];

const initialEdges = [
  { id: 'e1-2', source: '1', target: '2', animated: true, style: { stroke: '#38BDF8', strokeWidth: 2 } },
  { id: 'e2-3', source: '2', target: '3', animated: true, style: { stroke: '#A855F7', strokeWidth: 2 } },
  { id: 'e2-4', source: '2', target: '4', animated: true, style: { stroke: '#A855F7', strokeWidth: 2 } },
  { id: 'e3-5', source: '3', target: '5', animated: true, style: { stroke: '#F59E0B', strokeWidth: 2 } },
  { id: 'e4-5', source: '4', target: '5', animated: true, style: { stroke: '#EF4444', strokeWidth: 2 } },
  { id: 'e5-6', source: '5', target: '6', animated: true, style: { stroke: '#10B981', strokeWidth: 2 } },
  { id: 'e5-7', source: '5', target: '7', animated: true, style: { stroke: '#10B981', strokeWidth: 2 } },
  { id: 'e6-8', source: '6', target: '8', animated: true, style: { stroke: '#6366F1', strokeWidth: 2 } },
  { id: 'e7-8', source: '7', target: '8', animated: true, style: { stroke: '#EC4899', strokeWidth: 2 } },
];

export default function PipelineFlow() {
  const [selectedNode, setSelectedNode] = useState(initialNodes[0]);

  const onNodeClick = (_, node) => {
    setSelectedNode(node);
  };

  return (
    <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-4">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            Detection & Intelligence Pipeline Architecture
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Interactive multi-stage processing graph (@xyflow/react). Click any node to inspect details.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs text-slate-400 bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>8 STAGES ACTIVE</span>
        </div>
      </div>

      {/* Flow Canvas */}
      <div className="h-[380px] w-full bg-slate-950/80 rounded-xl overflow-hidden border border-slate-800/80 relative">
        <ReactFlow
          nodes={initialNodes}
          edges={initialEdges}
          onNodeClick={onNodeClick}
          fitView
        >
          <Background color="#1E293B" gap={20} size={1} />
          <Controls className="bg-slate-900 border-slate-800 text-slate-200" />
        </ReactFlow>
      </div>

      {/* Selected Node Details Card */}
      {selectedNode && (
        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 text-xs space-y-2 font-mono">
          <div className="flex items-center justify-between">
            <span className="font-bold text-cyan-400 flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              Stage {selectedNode.id}: {selectedNode.data.label}
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
              Pipeline Component
            </span>
          </div>
          <p className="text-slate-300 leading-relaxed">
            {selectedNode.data.detail}
          </p>
        </div>
      )}
    </div>
  );
}
