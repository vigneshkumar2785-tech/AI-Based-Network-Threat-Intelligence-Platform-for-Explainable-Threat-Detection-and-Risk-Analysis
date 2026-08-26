import axios from 'axios';

const API_BASE = '/api/v1';

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
});

// Helper for fallback simulation when running standalone / demo mode
export const triggerSyntheticEvent = async (eventType) => {
  try {
    const res = await api.post('/events/trigger', { event_type: eventType });
    return res.data;
  } catch (err) {
    console.warn("Backend API call failed, generating fallback demo response:", err.message);
    return mockSyntheticResult(eventType);
  }
};

export const fetchDashboardSummary = async () => {
  try {
    const res = await api.get('/dashboard/summary');
    return res.data;
  } catch (err) {
    return mockDashboardSummary();
  }
};

export const fetchIncidents = async () => {
  try {
    const res = await api.get('/incidents');
    return res.data;
  } catch (err) {
    return mockIncidents();
  }
};

export const transitionIncidentState = async (incidentId, newState, note = '') => {
  try {
    const res = await api.post(`/incidents/${incidentId}/transition`, { new_state: newState, note });
    return res.data;
  } catch (err) {
    return { incident_id: incidentId, state: newState, updated_at: new Date().toISOString() };
  }
};

// ── Fallback Mock Generators for Standalone Portfolio Showcase ────────────────
function mockSyntheticResult(eventType) {
  const isEicar = eventType === 'eicar_test';
  const isBeacon = eventType === 'c2_beacon';
  const isExfil = eventType === 'data_exfil';
  const isNormal = eventType === 'normal';

  const risk = isNormal ? 5.0 : isBeacon || isExfil || isEicar ? 100.0 : 68.5;
  const level = isNormal ? 'info' : risk >= 80 ? 'critical' : 'high';

  return {
    event_id: "demo-" + Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toISOString(),
    event_type: eventType,
    src_ip: isNormal ? "10.0.1.45" : "185.220.101.45",
    dst_ip: "10.0.0.10",
    dst_port: isBeacon ? 4444 : isEicar ? 21 : 443,
    protocol: isEicar ? "FTP" : "HTTPS",
    byte_count: isExfil ? 150000000 : 1240,
    packet_count: isExfil ? 85000 : 12,
    is_anomaly: !isNormal,
    anomaly_score: isNormal ? 0.05 : -0.09,
    classification: eventType,
    confidence: 0.998,
    eicar_detected: isEicar,
    iocs: isEicar ? [
      { type: "eicar_string", value: "275a021b...", reputation: "test_artifact", score: 1.0 },
      { type: "hash_md5", value: "44d88612fea8a8f36de82e1278abb02f", reputation: "test_artifact", score: 1.0 }
    ] : [
      { type: "ip", value: "185.220.101.45", reputation: "malicious", score: 0.95 }
    ],
    mitre_techniques: isNormal ? [] : [
      { technique_id: "T1046", technique_name: "Network Service Scanning", tactic: "Discovery" }
    ],
    cves: isNormal ? [] : [
      { cve_id: "CVE-2023-38408", cvss_v3: 9.8, service: "OpenSSH" }
    ],
    risk_score: risk,
    risk_level: level,
    score_breakdown: { base_score: risk * 0.5, confidence_adj: risk * 0.3, anomaly_bonus: 10, ioc_bonus: 10, total: risk },
    xai: {
      natural_language_explanation: `Event classified as ${eventType.replace('_',' ')} with 99.8% confidence. Primary indicators: payload entropy, byte count.`,
      shap_features: [
        { feature: "payload_entropy", shap_value: 0.85, direction: "positive", abs_impact: 0.85 },
        { feature: "byte_count_log", shap_value: 0.42, direction: "positive", abs_impact: 0.42 }
      ],
      lime_features: [
        { condition: "payload_entropy > 3.0", weight: 0.72, direction: "positive" }
      ]
    },
    incident: {
      incident_id: "INC-" + Math.random().toString(36).substr(2, 6).toUpperCase(),
      state: "new",
      severity: level,
      risk_score: risk,
      risk_level: level,
      classification: eventType,
      recommended_actions: [
        { priority: 1, action: "BLOCK_IP", description: "Block malicious source IP at firewall [SIMULATION]" },
        { priority: 2, action: "ALERT_SOC", description: "Notify SOC team of active threat" }
      ],
      audit_trail: [
        { timestamp: new Date().toISOString(), actor: "system", action: "INCIDENT_CREATED", detail: `Auto-created incident for ${eventType}` }
      ]
    }
  };
}

function mockDashboardSummary() {
  return {
    metrics: {
      total_events: 12480,
      total_anomalies: 842,
      total_incidents: 14,
      active_incidents: 5,
      avg_risk_score: 42.8,
      total_iocs: 128,
      malicious_iocs: 42,
    },
    severity_breakdown: { critical: 3, high: 4, medium: 5, low: 2, info: 0 },
    classification_breakdown: {
      normal: 11638,
      port_scan: 210,
      failed_auth: 180,
      dns_anomaly: 140,
      traffic_spike: 110,
      c2_beacon: 95,
      data_exfil: 75,
      eicar_test: 32,
    },
    system_status: "OPERATIONAL"
  };
}

function mockIncidents() {
  return [
    {
      id: "inc-1",
      incident_id: "INC-8E6EF250",
      state: "investigating",
      severity: "critical",
      risk_score: 100.0,
      risk_level: "critical",
      classification: "c2_beacon",
      src_ip: "10.0.1.146",
      dst_ip: "91.108.4.0",
      dst_port: 4444,
      protocol: "TCP",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      recommended_actions: [
        { priority: 1, action: "QUARANTINE_HOST", description: "Isolate host from network [SIMULATION]" },
        { priority: 2, action: "BLOCK_IP", description: "Block C2 server IP at egress [SIMULATION]" }
      ],
      mitre_techniques: [{ technique_id: "T1041", technique_name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" }],
      audit_trail: [{ timestamp: new Date().toISOString(), actor: "analyst@threatintel.io", action: "STATE_TRANSITION:new->investigating", detail: "Analyst inspecting packet captures" }]
    },
    {
      id: "inc-2",
      incident_id: "INC-DAE2F5E6",
      state: "new",
      severity: "critical",
      risk_score: 100.0,
      risk_level: "critical",
      classification: "eicar_test",
      src_ip: "172.16.0.93",
      dst_ip: "10.0.1.212",
      dst_port: 21,
      protocol: "FTP",
      created_at: new Date(Date.now() - 3600000).toISOString(),
      updated_at: new Date(Date.now() - 3600000).toISOString(),
      recommended_actions: [
        { priority: 1, action: "QUARANTINE_FILE", description: "Quarantine EICAR test file [SIMULATION]" }
      ],
      mitre_techniques: [{ technique_id: "T1105", technique_name: "Ingress Tool Transfer", tactic: "Command and Control" }],
      audit_trail: [{ timestamp: new Date(Date.now() - 3600000).toISOString(), actor: "system", action: "INCIDENT_CREATED", detail: "EICAR test artifact detected (inert text)" }]
    }
  ];
}
