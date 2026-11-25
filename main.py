import os
from datetime import datetime, timezone
from collector import collect_artifacts
from evtx_parser import parse_evtx_file
from timeline import extract_file_timestamps, build_timeline

def run_toolkit():
    case_id = datetime.now(timezone.utc).strftime("CASE_%Y%m%d_%H%M%S")
    evidence_dir = os.path.join(os.getcwd(), "evidence_output", case_id)

    print(f"[*] Starting Windows Triage -> {evidence_dir}")
    manifest = collect_artifacts(evidence_dir)

    all_events = []

    # 1. Parse all collected .evtx files
    for item in manifest:
        if item["collected_path"].endswith(".evtx"):
            print(f"[*] Parsing {item['artifact_name']}...")
            all_events.extend(parse_evtx_file(item["collected_path"]))

    # 2. Add filesystem/Prefetch timestamps
    all_events.extend(extract_file_timestamps(evidence_dir))

    # 3. Export unified timeline
    timeline_csv = os.path.join(evidence_dir, f"{case_id}_timeline.csv")
    build_timeline(all_events, timeline_csv)

if __name__ == "__main__":
    run_toolkit()