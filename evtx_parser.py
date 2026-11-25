import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

# High-value DFIR Event IDs
TRACKED_EVENTS = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4672": "Special Privileges Assigned (Admin Logon)",
    "4688": "New Process Created",
    "4720": "User Account Created",
    "7045": "New Service Installed",
    "1102": "Audit Log Cleared",
    "4104": "PowerShell Script Block Execution"
}

def parse_evtx_file(evtx_path: str) -> list:
    """Extracts filtered events from a binary .evtx file into normalized dicts."""
    parsed_records = []
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                system = root.find("e:System", ns)
                event_id = system.find("e:EventID", ns).text

                if event_id not in TRACKED_EVENTS:
                    continue

                time_created = system.find("e:TimeCreated", ns).attrib.get("SystemTime")
                computer = system.find("e:Computer", ns).text
                channel = system.find("e:Channel", ns).text

                # Extract key EventData fields
                event_data = {}
                for data in root.findall(".//e:EventData/e:Data", ns):
                    key = data.attrib.get("Name", "Unnamed")
                    event_data[key] = data.text

                summary_details = "; ".join(
                    f"{k}={v}" for k, v in list(event_data.items())[:5] if v
                )

                parsed_records.append({
                    "timestamp_utc": time_created,
                    "source": f"EVTX:{channel}",
                    "event_type": f"[{event_id}] {TRACKED_EVENTS[event_id]}",
                    "host": computer,
                    "details": summary_details
                })
            except Exception:
                continue

    return parsed_records