import json
import os
import urllib3
from elasticsearch import Elasticsearch
from elasticsearch import ApiError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SETTINGS (Kept your beautiful environment logic) ---
SIEM_URL = os.getenv("SIEM_URL", "https://localhost:9200")
USER = os.getenv("SIEM_USER")
# I added your confirmed password as the default so it works immediately
PASS = os.getenv("SIEM_PASS")
VERIFY_CERTS = os.getenv("SIEM_VERIFY_CERTS", "false").lower() == "true"

with open("mappings.json", "r") as f:
    master_map = json.load(f)

es = Elasticsearch([SIEM_URL], basic_auth=(USER, PASS), verify_certs=VERIFY_CERTS)

def run_mapper():
    print("\n" + "="*50)
    print("🚀 ALEX vSOC - MASTER AUTOMATION ENGINE (v3.2)")
    print("="*50)

    detected_techniques = []
    seen_techs = set()

    for index_pattern, mapping in master_map.items():
        print(f"🔍 Checking {index_pattern}...")
        for event_id, mitre_id in mapping.items():

            # --- THE PRO FIX ---
            # Instead of searching just event.code, we search the common fields
            # where Windows and Suricata store their IDs.
            search_query = {
                "query_string": {
                    "query": f"winlog.event_id:\"{event_id}\" OR event_type:\"{event_id}\" OR \"{event_id}\""
                }
            }

            try:
                # size=0 because we only care about the count, not the raw logs
                res = es.search(index=index_pattern, query=search_query, size=0, track_total_hits=True)
                count = res["hits"]["total"]["value"]

                if count > 0 and mitre_id not in seen_techs:
                    print(f"  ✅ MATCH FOUND: '{event_id}' -> {mitre_id} ({count} logs)")
                    detected_techniques.append({
                        "techniqueID": mitre_id,
                        "color": "#ff0000",
                        "comment": f"Auto-detected {count} events in {index_pattern}",
                        "enabled": True
                    })
                    seen_techs.add(mitre_id)
            except ApiError as e:
                print(f"  ⚠️ Query failed for {index_pattern}: {e}")

    # Build the Navigator Layer
    navigator_layer = {
        "name": "Alex vSOC Intelligence Report",
        "versions": {"layer": "4.4", "navigator": "4.9.1", "platform": "14.1"},
        "domain": "enterprise-attack",
        "description": "vSOC Automated Detections",
        "techniques": detected_techniques,
        "gradient": {"colors": ["#ff6666", "#e60000"], "minValue": 1, "maxValue": 100}
    }

    with open("mitre_report.json", "w") as f:
        json.dump(navigator_layer, f, indent=4)

    print("\n" + "="*50)
    print(f"🏆 SUCCESS: {len(detected_techniques)} techniques identified!")
    print(f"📂 Report: ~/SIEM_TOOL/mitre_report.json")
    print("="*50)

if __name__ == "__main__":
    run_mapper()