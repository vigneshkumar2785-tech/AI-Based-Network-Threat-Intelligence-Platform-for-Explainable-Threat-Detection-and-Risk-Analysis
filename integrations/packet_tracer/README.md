# Cisco Packet Tracer Integration Guide
## Aegis AI Network Threat Intelligence Platform

This guide explains how to use **Cisco Packet Tracer** to simulate external network activity and pipe the captured data into the AI Threat Intelligence Platform.

---

## 1. Cisco Packet Tracer Setup

### Step 1: Create a Basic Topology
Open Cisco Packet Tracer and place the following components on your canvas:

```text
[ PC1 (192.168.1.100) ]
          │
          │ (Ethernet Cable)
          ▼
[ Switch (2960) ]
          │
          │ (Ethernet Cable)
          ▼
[ Router (1941) ]
          │
          │ (Ethernet Cable)
          ▼
[ Server (10.0.0.1) ]
```

### Step 2: Configure IP Addresses
1. **PC1**:
   - IP: `192.168.1.100`
   - Subnet Mask: `255.255.255.0`
   - Default Gateway: `192.168.1.1`

2. **Server**:
   - IP: `10.0.0.1`
   - Subnet Mask: `255.255.255.0`
   - Services: Enable **HTTP**, **FTP**, and **DNS** services.

---

## 2. Generate Network Activity

### Scenario A: Benign Ping / Web Traffic
1. Open **PC1** -> **Desktop** -> **Command Prompt**.
2. Run ping command:
   ```cmd
   ping 10.0.0.1
   ```
3. Open **PC1** -> **Desktop** -> **Web Browser**.
4. Navigate to `http://10.0.0.1`.

### Scenario B: Simulated Port Scan / Reconnaissance
1. Switch Packet Tracer to **Simulation Mode** (bottom-right corner clock icon).
2. Create complex PDUs targeting multiple ports (`80`, `22`, `443`, `3389`).
3. Click **Auto Capture / Play** to observe packet transmission across the switch and router.

---

## 3. Passing Data to Wireshark & Aegis Platform

Since Packet Tracer is a desktop simulator, network events captured in Packet Tracer can be ingested into Aegis in **two easy ways**:

### Option 1: Direct Ingest via Wireshark Adapter
Save your captured packet summary or export CSV from Wireshark, then run:
```bash
python integrations/wireshark/wireshark_adapter.py
```

### Option 2: Direct Ingest via Postman
Copy the packet parameters (`src_ip: 192.168.1.100`, `dst_ip: 10.0.0.1`, `protocol: TCP`, `dst_port: 80`) and send a POST request to:
`http://localhost:8000/api/v1/events/ingest`
