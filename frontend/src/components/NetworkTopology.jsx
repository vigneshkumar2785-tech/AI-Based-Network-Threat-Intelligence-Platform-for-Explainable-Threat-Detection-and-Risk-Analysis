import React, { useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Network, ShieldAlert, Server, Globe } from 'lucide-react';

export default function NetworkTopology({ currentEvent = null }) {
  const graphData = useMemo(() => {
    const nodes = [
      { id: 'gw-1', name: 'Perimeter Gateway (10.0.0.1)', group: 'gateway', val: 12 },
      { id: 'srv-http', name: 'Web Server (10.0.0.10)', group: 'internal', val: 8 },
      { id: 'srv-db', name: 'Database Core (10.0.0.25)', group: 'internal', val: 10 },
      { id: 'srv-dns', name: 'Internal DNS (10.0.1.53)', group: 'internal', val: 7 },
      { id: 'work-1', name: 'Workstation 101 (192.168.1.45)', group: 'workstation', val: 5 },
      { id: 'work-2', name: 'Workstation 102 (192.168.1.66)', group: 'workstation', val: 5 },
      { id: 'ext-mal1', name: 'C2 Endpoint (91.108.4.0)', group: 'threat', val: 9 },
      { id: 'ext-mal2', name: 'Brute IP (45.142.212.100)', group: 'threat', val: 9 },
      { id: 'ext-clean', name: 'Google DNS (8.8.8.8)', group: 'benign', val: 6 },
    ];

    const links = [
      { source: 'gw-1', target: 'srv-http', value: 3 },
      { source: 'gw-1', target: 'srv-dns', value: 2 },
      { source: 'srv-http', target: 'srv-db', value: 4 },
      { source: 'work-1', target: 'srv-http', value: 2 },
      { source: 'work-2', target: 'srv-http', value: 2 },
      { source: 'work-1', target: 'ext-clean', value: 1 },
      { source: 'ext-mal1', target: 'gw-1', value: 5, color: '#E11D48' },
      { source: 'ext-mal2', target: 'gw-1', value: 5, color: '#D97706' },
      { source: 'work-2', target: 'ext-mal1', value: 4, color: '#DC2626' },
    ];

    if (currentEvent && currentEvent.src_ip && currentEvent.dst_ip) {
      const srcId = 'active-src';
      const dstId = 'active-dst';
      nodes.push({ id: srcId, name: `Event Source (${currentEvent.src_ip})`, group: currentEvent.is_anomaly ? 'threat' : 'internal', val: 11 });
      nodes.push({ id: dstId, name: `Target (${currentEvent.dst_ip}:${currentEvent.dst_port})`, group: 'internal', val: 10 });
      links.push({ source: srcId, target: dstId, value: 6, color: currentEvent.risk_score >= 80 ? '#E11D48' : '#00684A' });
    }

    return { nodes, links };
  }, [currentEvent]);

  const getNodeColor = (node) => {
    switch (node.group) {
      case 'gateway': return '#00684A';
      case 'internal': return '#13AA52';
      case 'workstation': return '#00ED64';
      case 'threat': return '#E11D48';
      case 'benign': return '#64748B';
      default: return '#5C6C64';
    }
  };

  return (
    <div className="glass-panel rounded-2xl p-6 border border-[#E1E8E5] bg-white space-y-4 shadow-sm">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-[#E1E8E5] pb-4">
        <div>
          <h2 className="text-lg font-bold text-[#001E2B] flex items-center gap-2">
            <Network className="w-5 h-5 text-[#00684A]" />
            Live Network Topology & Threat Map
          </h2>
          <p className="text-xs text-[#5C6C64] font-mono">
            Interactive force-directed graph (react-force-graph-2d). Drag nodes to reposition.
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono font-semibold text-[#001E2B]">
          <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#00684A] inline-block" /> Gateway</div>
          <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#13AA52] inline-block" /> Internal Core</div>
          <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-[#E11D48] inline-block" /> Threat Source</div>
        </div>
      </div>

      {/* Canvas Wrapper */}
      <div className="h-[400px] w-full bg-[#F9FBF9] rounded-xl overflow-hidden border border-[#E1E8E5] relative">
        <ForceGraph2D
          graphData={graphData}
          nodeAutoColorBy="group"
          nodeColor={getNodeColor}
          nodeRelSize={6}
          linkDirectionalParticles={3}
          linkDirectionalParticleSpeed={0.005}
          linkDirectionalParticleWidth={2}
          nodeCanvasObject={(node, ctx, globalScale) => {
            const label = node.name;
            const fontSize = 11 / globalScale;
            ctx.font = `600 ${fontSize}px Inter, sans-serif`;
            const color = getNodeColor(node);

            // Draw Node Circle
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
            ctx.fillStyle = color;
            ctx.shadowColor = 'rgba(0, 30, 43, 0.15)';
            ctx.shadowBlur = 6;
            ctx.fill();

            // Draw Label text
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = '#001E2B';
            ctx.fillText(label, node.x, node.y + node.val + 8);
          }}
        />
      </div>
    </div>
  );
}
