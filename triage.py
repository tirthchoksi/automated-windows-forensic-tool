import ctypes
import csv
import hashlib
import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import Evtx.Evtx as evtx

ARTIFACTS = {
    "Security_Log": r"C:\Windows\System32\winevt\Logs\Security.evtx",
    "System_Log": r"C:\Windows\System32\winevt\Logs\System.evtx",
    "PowerShell_Log": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
    "Hosts_File": r"C:\Windows\System32\drivers\etc\hosts",
    "Prefetch_Dir": r"C:\Windows\Prefetch",
}

# Maps artifact key -> Windows Event Log channel name for wevtutil fallback
EVTX_CHANNELS = {
    "Security_Log": "Security",
    "System_Log": "System",
    "PowerShell_Log": "Microsoft-Windows-PowerShell/Operational",
}

TRACKED_EVENTS = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4672": "Special Privileges Assigned (Admin Logon)",
    "4688": "New Process Created",
    "4720": "User Account Created",
    "7045": "New Service Installed",
    "1102": "Audit Log Cleared",
    "4104": "PowerShell Script Block Execution",
}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def export_evtx_via_wevtutil(channel: str, dst_path: str) -> bool:
    """Exports an active/locked Windows event log channel to a .evtx file."""
    if os.path.exists(dst_path):
        os.remove(dst_path)
    cmd = ["wevtutil", "epl", channel, dst_path]
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.returncode == 0 and os.path.exists(dst_path)


def collect_and_hash(out_dir: str) -> list:
    os.makedirs(out_dir, exist_ok=True)
    manifest = []

    for label, src in ARTIFACTS.items():
        if not os.path.exists(src):
            print(f"[!] Skipped (not found): {label} -> {src}")
            continue

        if os.path.isfile(src):
            dst = os.path.join(out_dir, os.path.basename(src))
            copied = False

            try:
                shutil.copy2(src, dst)
                copied = True
                print(f"[+] Collected {label}")
            except (PermissionError, OSError):
                channel = EVTX_CHANNELS.get(label)
                if channel and export_evtx_via_wevtutil(channel, dst):
                    copied = True
                    print(f"[+] Exported {label} via wevtutil ({channel})")
                else:
                    print(f"[-] Permission denied / locked: {label} ({src})")

            if copied and os.path.exists(dst):
                manifest.append({
                    "artifact": label,
                    "source": src,
                    "collected_copy": dst,
                    "sha256": sha256_file(dst),
                    "collected_utc": datetime.now(timezone.utc).isoformat(),
                })

        elif os.path.isdir(src):
            sub = os.path.join(out_dir, label)
            os.makedirs(sub, exist_ok=True)
            try:
                entries = os.listdir(src)
            except (PermissionError, OSError):
                print(f"[-] Permission denied listing directory: {src}")
                continue

            count = 0
            for fname in entries:
                f_src = os.path.join(src, fname)
                if os.path.isfile(f_src):
                    f_dst = os.path.join(sub, fname)
                    try:
                        shutil.copy2(f_src, f_dst)
                        manifest.append({
                            "artifact": f"{label}:{fname}",
                            "source": f_src,
                            "collected_copy": f_dst,
                            "sha256": sha256_file(f_dst),
                            "collected_utc": datetime.now(timezone.utc).isoformat(),
                        })
                        count += 1
                    except (PermissionError, OSError):
                        continue
            print(f"[+] Collected {count} files from {label}")

    manifest_file = os.path.join(out_dir, "chain_of_custody.json")
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


def parse_evtx(evtx_path: str) -> list:
    rows = []
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    try:
        with evtx.Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                    sys_node = root.find("e:System", ns)
                    eid_node = sys_node.find("e:EventID", ns) if sys_node is not None else None
                    if eid_node is None or eid_node.text not in TRACKED_EVENTS:
                        continue

                    eid = eid_node.text
                    time_node = sys_node.find("e:TimeCreated", ns)
                    comp_node = sys_node.find("e:Computer", ns)
                    chan_node = sys_node.find("e:Channel", ns)

                    ts = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
                    host = comp_node.text if (comp_node is not None and comp_node.text) else ""
                    channel = chan_node.text if (chan_node is not None and chan_node.text) else ""

                    kv = []
                    for d in root.findall(".//e:EventData/e:Data", ns):
                        name = d.attrib.get("Name", "Field")
                        if d.text:
                            kv.append(f"{name}={d.text}")
                        if len(kv) >= 5:
                            break

                    rows.append({
                        "timestamp_utc": ts,
                        "source": f"EVTX:{channel}",
                        "event": f"[{eid}] {TRACKED_EVENTS[eid]}",
                        "host": host,
                        "details": "; ".join(kv),
                    })
                except Exception:
                    continue
    except Exception as exc:
        print(f"[!] Could not parse {evtx_path}: {exc}")

    return rows


def collect_file_times(out_dir: str) -> list:
    rows = []
    host = os.environ.get("COMPUTERNAME", "WINDOWS_HOST")
    for root_dir, _, files in os.walk(out_dir):
        for fname in files:
            if fname == "chain_of_custody.json":
                continue
            fpath = os.path.join(root_dir, fname)
            st = os.stat(fpath)
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
            rows.append({
                "timestamp_utc": mtime,
                "source": "File:MTime",
                "event": "Artifact Timestamp",
                "host": host,
                "details": f"File={fname}; Size={st.st_size}B",
            })
    return rows


def main():
    if not is_admin():
        print("[!] Warning: Not running as Administrator. Protected logs/Prefetch may fail.")

    case_id = datetime.now(timezone.utc).strftime("CASE_%Y%m%d_%H%M%S")
    out_dir = os.path.join(os.getcwd(), "evidence_output", case_id)

    print(f"[*] Running triage -> {out_dir}")
    manifest = collect_and_hash(out_dir)

    events = []
    for item in manifest:
        path = item["collected_copy"]
        if path.lower().endswith(".evtx"):
            print(f"[*] Parsing {os.path.basename(path)}...")
            events.extend(parse_evtx(path))

    events.extend(collect_file_times(out_dir))
    events.sort(key=lambda r: r["timestamp_utc"])

    csv_path = os.path.join(out_dir, f"{case_id}_timeline.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["timestamp_utc", "source", "event", "host", "details"]
        )
        writer.writeheader()
        writer.writerows(events)

    print(f"[+] Done! {len(events)} timeline entries saved to:\n    {csv_path}")
    print(f"[+] SHA-256 manifest saved to:\n    {os.path.join(out_dir, 'chain_of_custody.json')}")


if __name__ == "__main__":
    main()