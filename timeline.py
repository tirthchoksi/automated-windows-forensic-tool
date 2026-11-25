import os
import csv
from datetime import datetime, timezone

def extract_file_timestamps(collected_dir: str) -> list:
    """Extracts filesystem timestamps from collected artifacts (e.g., Prefetch)."""
    file_events = []
    for root_dir, _, files in os.walk(collected_dir):
        for fname in files:
            if fname == "chain_of_custody.json":
                continue
            fpath = os.path.join(root_dir, fname)
            stat = os.stat(fpath)

            # Modification time (correlates with last run time for .pf files)
            mtime_iso = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
            file_events.append({
                "timestamp_utc": mtime_iso,
                "source": "Filesystem:MTime",
                "event_type": "Artifact Modified / Executed",
                "host": os.environ.get("COMPUTERNAME", "LOCALHOST"),
                "details": f"File={fname}; Size={stat.st_size}B"
            })
    return file_events

def build_timeline(events: list, output_csv: str):
    """Sorts all normalized events chronologically and writes to CSV."""
    # Standardize timestamps for reliable sorting
    sorted_events = sorted(events, key=lambda x: x["timestamp_utc"])

    fieldnames = ["timestamp_utc", "source", "event_type", "host", "details"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sorted_events)

    print(f"[+] Timeline generated with {len(sorted_events)} events -> {output_csv}")