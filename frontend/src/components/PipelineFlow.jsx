import React, { useState } from 'react';
import { ReactFlow, Background, Controls } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Layers, Info, CheckCircle2, ShieldAlert, Cpu, Lock, Database } from 'lucide-react';

const initialNodes = [
  {
    id: '1',
    position: { x: 50, y: 150 },
    data: { label: 'Raw Event Ingestion', detail: 'Parses netflow, DNS, and HTTP packets into standardized JSON payloads' },
    style: { background: '#FFFFFF', color: '#001E2B', border: '2px solid #00684A', borderRadius: '12px', padding: '12px', width: 180, boxShadow: '0 4px 12px rgba(0,30,43,0.06)' },
  },
  {
    id: '2',
    position: { x: 270, y: 150 },
    data: { label: 'Feature Preprocessing', detail: '31 canonical features: log counts, ratios, one-hot protocols & Shannon entropy' },
    style: { background: '#FFFFFF', color: '#001E2B', border: '2px solid #13AA52', borderRadius: '12px', padding: '12px', width: 180, boxShadow: '0 4px 12px rgba(0,30,43,0.06)' },
  },
  {
    id: '3',
    position: { x: 490, y: 70 },
    data: { label: 'Isolation Forest', detail: 'Unsupervised anomaly detection (200 trees). Flags outlier behavior' },
    style: { background: '#FFFFFF', color: '#001E2B', border: '2px solid #D97706', borderRadius: '12px', padding: '12px', width: 180, boxShadow: '0 4px 12px rgba(0,30,43,0.06)' },
  },
  {
    id: '4',
    position: { x: 490, y: 230 },
    data: { label: 'XGBoost Classifier', detail: 'Multi-class threat classifier (300 trees, depth=6). 8 threat categories' },
    style: { background: '#FFFFFF', color: '#001E2B', border: '2px solid #E11D48', borderRadius: '12px', padding: '12px', width: 180, boxShadow: '0 4px 12px rgba(0,30,43,0.06)' },
  },
  {
    id: '5',
    position: { x: 710, y: 150 },
    data: { label: 'IOC Extractor', detail: 'Extracts IP, domain, hash & EICAR string indicators with reputation scoring' },
    style: { background: '#FFFFFF', color: '#001E2B', border: '2px solid #00ED64', borderRadius: '12px', padding: '12px', width: 180, boxShadow: '0 4px 12px rgba(0,30,43,0.06)' },
  },
  {
    id: '6',
    position: { x: 930, y: 70 },
    data: { label: 'MITRE ATT&CK Mapper', detail: 'Evidence-gated mapping to 11 TTPs. Requires concrete threshold proof' },
    style: { background: '#FFFFFF', color: '#001E2B', border: '2px solid #6366F1', borderRadius: '12px', padding: '12px', width: 180, boxShadow: '0 4px 12px rgba(0,30,43,0.06)' },
  },
  {
    id: '7',
    position: { x: 930, y: 230 },
    data: { label: 'Risk Scorer & XAI', detail: 'Weighted 0-100 risk score + SHAP feature attributions & LIME rules' },
    style: { background: '#FFFFFF', color: '#001E2B', border: '2px solid #EC4899', borderRadius: '12px', padding: '12px', width: 180, boxShadow: '0 4px 12px rgba(0,30,43,0.06)' },
  },
  {
    id: '8',
    position: { x: 1150, y: 150 },
    data: { label: 'Incident Engine', detail: 'State machine management (new->investigating->contained->resolved) + playbooks' },
    style: { background: '#FFFFFF', color: '#001E2B', border: '2px solid #00684A', borderRadius: '12px', padding: '12px', width: 190, boxShadow: '0 4px 12px rgba(0,30,43,0.06)' },
  },
];

const initialEdges = [
  { id: 'e1-2', source: '1', target: '2', animated: true, style: { stroke: '#00684A', strokeWidth: 2.5 } },
  { id: 'e2-3', source: '2', target: '3', animated: true, style: { stroke: '#13AA52', strokeWidth: 2.5 } },
  { id: 'e2-4', source: '2', target: '4', animated: true, style: { stroke: '#13AA52', strokeWidth: 2.5 } },
  { id: 'e3-5', source: '3', target: '5', animated: true, style: { stroke: '#D97706', strokeWidth: 2.5 } },
  { id: 'e4-5', source: '4', target: '5', animated: true, style: { stroke: '#E11D48', strokeWidth: 2.5 } },
  { id: 'e5-6', source: '5', target: '6', animated: true, style: { stroke: '#00684A', strokeWidth: 2.5 } },
  { id: 'e5-7', source: '5', target: '7', animated: true, style: { stroke: '#00684A', strokeWidth: 2.5 } },
  { id: 'e6-8', source: '6', target: '8', animated: true, style: { stroke: '#6366F1', strokeWidth: 2.5 } },
  { id: 'e7-8', source: '7', target: '8', animated: true, style: { stroke: '#EC4899', strokeWidth: 2.5 } },
];

export default function PipelineFlow() {
  const [selectedNode, setSelectedNode] = useState(initialNodes[0]);

  const onNodeClick = (_, node) => {
    setSelectedNode(node);
  };

  return (
    <div className="glass-panel rounded-2xl p-6 border border-[#E1E8E5] bg-white space-y-4 shadow-sm">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#E1E8E5] pb-4">
        <div>
          <h2 className="text-lg font-bold text-[#001E2B] flex items-center gap-2">
            <Layers className="w-5 h-5 text-[#00684A]" />
            Detection & Intelligence Pipeline Architecture
          </h2>
          <p className="text-xs text-[#5C6C64] font-mono">
            Interactive multi-stage processing graph (@xyflow/react). Click any node to inspect details.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs text-[#00684A] bg-[#E6F4EA] px-3 py-1.5 rounded-lg border border-[#C1E7D0] font-semibold">
          <span className="w-2 h-2 rounded-full bg-[#00ED64] animate-ping" />
          <span>8 STAGES ACTIVE</span>
        </div>
      </div>

      {/* Flow Canvas */}
      <div className="h-[380px] w-full bg-[#F9FBF9] rounded-xl overflow-hidden border border-[#E1E8E5] relative">
        <ReactFlow
          nodes={initialNodes}
          edges={initialEdges}
          onNodeClick={onNodeClick}
          fitView
        >
          <Background color="#D2ECD9" gap={20} size={1} />
          <Controls className="bg-white border-[#E1E8E5] text-[#001E2B]" />
        </ReactFlow>
      </div>

      {/* Selected Node Details Card */}
      {selectedNode && (
        <div className="p-4 bg-[#E6F4EA] rounded-xl border border-[#C1E7D0] text-xs space-y-2 font-mono text-[#001E2B]">
          <div className="flex items-center justify-between">
            <span className="font-bold text-[#00684A] flex items-center gap-2">
              <Info className="w-4 h-4 text-[#00684A]" />
              Stage {selectedNode.id}: {selectedNode.data.label}
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] bg-[#00684A] text-white font-bold">
              MongoDB Pipeline Node
            </span>
          </div>
          <p className="text-[#1C2D27] leading-relaxed font-sans font-medium">
            {selectedNode.data.detail}
          </p>
        </div>
      )}
    </div>
  );
}
