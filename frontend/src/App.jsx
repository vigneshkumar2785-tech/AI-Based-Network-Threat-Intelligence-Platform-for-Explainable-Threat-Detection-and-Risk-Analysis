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
    // Refresh incidents if created
    if (result.incident) {
      setIncidents(prev => [result.incident, ...prev]);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
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
                <div className="p-5 bg-slate-900/90 rounded-2xl border border-cyan-500/40 font-mono text-xs space-y-3">
                  <div className="flex items-center justify-between text-cyan-400 font-bold">
                    <span>LIVE EVENT RESULT: {lastTriggeredResult.event_type.toUpperCase()}</span>
                    <span>RISK SCORE: {lastTriggeredResult.risk_score}/100 ({lastTriggeredResult.risk_level.toUpperCase()})</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-slate-300">
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
      <footer className="border-t border-slate-900 bg-slate-950 py-4 px-6 text-center text-xs text-slate-500 font-mono">
        AI Network Threat Intelligence Platform — Interactive Portfolio Edition &copy; 2026. Built with React 18, FastAPI & XGBoost.
      </footer>
    </div>
  );
}
