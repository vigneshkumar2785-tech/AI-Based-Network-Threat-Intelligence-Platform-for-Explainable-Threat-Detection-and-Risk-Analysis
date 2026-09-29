import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import DashboardSummary from './components/DashboardSummary';
import LiveSimulator from './components/LiveSimulator';
import PipelineFlow from './components/PipelineFlow';
import NetworkTopology from './components/NetworkTopology';
import MitreHeatmap from './components/MitreHeatmap';
import EicarSandbox from './components/EicarSandbox';
import XaiInspector from './components/XaiInspector';
import IncidentManager from './components/IncidentManager';
import IocFeed from './components/IocFeed';

import { fetchDashboardSummary, fetchIncidents } from './api';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [summaryData, setSummaryData] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [lastTriggeredResult, setLastTriggeredResult] = useState(null);

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    const sum = await fetchDashboardSummary();
    setSummaryData(sum);
    const incs = await fetchIncidents();
    setIncidents(incs);
  };

  const handleEventProcessed = (result) => {
    setLastTriggeredResult(result);
    if (result.incident) {
      setIncidents(prev => [result.incident, ...prev]);
    }
  };

  return (
    <div className="min-h-screen bg-[#F9FBF9] text-[#1C2D27] flex flex-col font-sans selection:bg-[#00ED64] selection:text-[#001E2B]">
      {/* Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        liveAlertCount={incidents.filter(i => i.state === 'new').length}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {/* TAB 1: OVERVIEW */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <DashboardSummary summaryData={summaryData} />
            <LiveSimulator onEventProcessed={handleEventProcessed} />
            {lastTriggeredResult && (
              <XaiInspector
                xaiData={lastTriggeredResult.xai}
                classification={lastTriggeredResult.classification}
                confidence={lastTriggeredResult.confidence}
              />
            )}
          </div>
        )}

        {/* TAB 2: LIVE SIMULATOR */}
        {activeTab === 'simulator' && (
          <div className="space-y-6">
            <LiveSimulator onEventProcessed={handleEventProcessed} />
            {lastTriggeredResult && (
              <div className="space-y-6">
                <div className="p-5 bg-[#E6F4EA] rounded-2xl border border-[#C1E7D0] font-mono text-xs space-y-3 shadow-xs">
                  <div className="flex items-center justify-between text-[#00684A] font-bold">
                    <span>LIVE EVENT RESULT: {lastTriggeredResult.event_type.toUpperCase()}</span>
                    <span>RISK SCORE: {lastTriggeredResult.risk_score}/100 ({lastTriggeredResult.risk_level.toUpperCase()})</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[#1C2D27] font-semibold">
                    <div>Src: {lastTriggeredResult.src_ip}</div>
                    <div>Dst: {lastTriggeredResult.dst_ip}:{lastTriggeredResult.dst_port}</div>
                    <div>Proto: {lastTriggeredResult.protocol}</div>
                    <div>Confidence: {(lastTriggeredResult.confidence * 100).toFixed(1)}%</div>
                  </div>
                </div>

                <XaiInspector
                  xaiData={lastTriggeredResult.xai}
                  classification={lastTriggeredResult.classification}
                  confidence={lastTriggeredResult.confidence}
                />
              </div>
            )}
          </div>
        )}

        {/* TAB 3: PIPELINE FLOW (@xyflow/react) */}
        {activeTab === 'pipeline' && (
          <PipelineFlow />
        )}

        {/* TAB 4: NETWORK TOPOLOGY (react-force-graph-2d) */}
        {activeTab === 'topology' && (
          <NetworkTopology currentEvent={lastTriggeredResult} />
        )}

        {/* TAB 5: INCIDENTS & PLAYBOOKS */}
        {activeTab === 'incidents' && (
          <IncidentManager
            incidents={incidents}
            onIncidentUpdated={loadInitialData}
          />
        )}

        {/* TAB 6: MITRE ATT&CK HEATMAP */}
        {activeTab === 'mitre' && (
          <MitreHeatmap />
        )}

        {/* TAB 7: EICAR SANDBOX */}
        {activeTab === 'eicar' && (
          <div className="space-y-6">
            <EicarSandbox onEventProcessed={handleEventProcessed} />
            {lastTriggeredResult && lastTriggeredResult.eicar_detected && (
              <XaiInspector
                xaiData={lastTriggeredResult.xai}
                classification={lastTriggeredResult.classification}
                confidence={lastTriggeredResult.confidence}
              />
            )}
          </div>
        )}

        {/* TAB 8: IOC FEED */}
        {activeTab === 'iocs' && (
          <IocFeed />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#E1E8E5] bg-white py-4 px-6 text-center text-xs text-[#5C6C64] font-mono font-medium">
        Aegis Threat Intelligence Platform — MongoDB LeafyGreen Theme Edition &copy; 2026. Built with React 18, FastAPI & XGBoost.
      </footer>
    </div>
  );
}
