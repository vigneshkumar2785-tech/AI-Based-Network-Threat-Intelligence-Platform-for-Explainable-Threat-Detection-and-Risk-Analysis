"""
Block D End-to-End REST API Test
Tests all REST endpoints against the live backend server.
"""
import requests
import time
import os

BASE_URL = "http://127.0.0.1:8003"


def test_endpoint(name: str, method: str, url: str, headers: dict = None, json_body: dict = None, expected_status: int = 200) -> dict:
    try:
        if method.upper() == "GET":
            res = requests.get(url, headers=headers, timeout=10)
        elif method.upper() == "POST":
            res = requests.post(url, headers=headers, json=json_body, timeout=10)
        
        status_ok = (res.status_code == expected_status)
        symbol = "✓" if status_ok else "✗"
        print(f"  {symbol} {name:30s} {method:4s} {url:45s} -> {res.status_code}")
        if not status_ok:
            print(f"     Response: {res.text[:200]}")
        return {"ok": status_ok, "data": res.json() if res.status_code == 200 else res.text}
    except Exception as e:
        print(f"  ✗ {name:30s} FAILED: {e}")
        return {"ok": False, "error": str(e)}


def main():
    print("=" * 70)
    print("  AI NETWORK THREAT INTELLIGENCE — BLOCK D REST API TEST")
    print("=" * 70)

    # Poll /health for up to 15 seconds for server startup
    server_ready = False
    for attempt in range(15):
        try:
            r = requests.get(f"{BASE_URL}/health", timeout=2)
            if r.status_code == 200:
                server_ready = True
                break
        except Exception:
            pass
        time.sleep(1)

    if not server_ready:
        print("  ✗ Backend server did not respond on /health within 15 seconds.")
        return

    # 1. Health Check
    test_endpoint("Health Check", "GET", f"{BASE_URL}/health")

    # 2. Auth - Login
    login_res = requests.post(
        f"{BASE_URL}/api/v1/auth/login",
        data={"username": "analyst@threatintel.io", "password": "Cyber2026!"}
    )
    token = ""
    if login_res.status_code == 200:
        token = login_res.json().get("access_token", "")
        print(f"  ✓ Login Success                 POST {BASE_URL}/api/v1/auth/login                 -> 200 OK (Token acquired)")
    else:
        print(f"  ✗ Login Failed                  -> {login_res.status_code}: {login_res.text}")

    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

    # 3. Auth - Me
    test_endpoint("Auth Profile (/me)", "GET", f"{BASE_URL}/api/v1/auth/me", headers=auth_headers)

    # 4. Dashboard Summary
    test_endpoint("Dashboard Summary", "GET", f"{BASE_URL}/api/v1/dashboard/summary", headers=auth_headers)

    # 5. Events List
    test_endpoint("List Events", "GET", f"{BASE_URL}/api/v1/events?limit=10", headers=auth_headers)

    # 6. Trigger Event
    test_endpoint("Trigger C2 Event", "POST", f"{BASE_URL}/api/v1/events/trigger", headers=auth_headers, json_body={"event_type": "c2_beacon"})

    # 7. Incidents List
    inc_res = test_endpoint("List Incidents", "GET", f"{BASE_URL}/api/v1/incidents?limit=10", headers=auth_headers)
    
    # 8. Incident Detail & Transition (if incident exists)
    if inc_res.get("ok") and len(inc_res.get("data", [])) > 0:
        inc_id = inc_res["data"][0]["incident_id"]
        test_endpoint("Get Incident Detail", "GET", f"{BASE_URL}/api/v1/incidents/{inc_id}", headers=auth_headers)
        test_endpoint("Transition Incident State", "POST", f"{BASE_URL}/api/v1/incidents/{inc_id}/transition", headers=auth_headers, json_body={"new_state": "investigating", "note": "Analyst inspecting packet captures"})

    # 9. IOC List & Search
    test_endpoint("List IOCs", "GET", f"{BASE_URL}/api/v1/iocs?limit=10", headers=auth_headers)
    test_endpoint("Search IOCs", "GET", f"{BASE_URL}/api/v1/iocs/search?q=EICAR", headers=auth_headers)

    # 10. MITRE Catalog
    test_endpoint("MITRE Catalog", "GET", f"{BASE_URL}/api/v1/mitre/catalog", headers=auth_headers)

    # 11. CVE Catalog
    test_endpoint("CVE Catalog", "GET", f"{BASE_URL}/api/v1/vulnerabilities", headers=auth_headers)

    # 12. XAI Explain
    test_endpoint("XAI Explain Direct", "POST", f"{BASE_URL}/api/v1/xai/explain", headers=auth_headers, json_body={
        "byte_count": 500, "packet_count": 10, "duration_ms": 100,
        "src_ip": "10.0.0.5", "dst_ip": "45.142.212.100", "dst_port": 443, "protocol": "HTTPS"
    })

    print("=" * 70)
    print("  Block D REST API Test Complete.\n")


if __name__ == "__main__":
    main()
