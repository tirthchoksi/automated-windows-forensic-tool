import os
import shutil
import hashlib
import json
from datetime import datetime, timezone

DEFAULT_ARTIFACTS = {
    "Security_Log": r"C:\Windows\System32\winevt\Logs\Security.evtx",
    "System_Log": r"C:\Windows\System32\winevt\Logs\System.evtx",
    "PowerShell_Log": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
    "Hosts_File": r"C:\Windows\System32\drivers\etc\hosts",
    "Prefetch_Dir": r"C:\Windows\Prefetch"
}

def calculate_sha256(file_path: str) -> str:
    """Computes SHA-256 hash in 64KB chunks to handle large files safely."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def collect_artifacts(output_dir: str, targets: dict = DEFAULT_ARTIFACTS) -> list:
    """Copies selected artifacts and logs chain-of-custody metadata."""
    os.makedirs(output_dir, exist_ok=True)
    manifest = []

    for name, src_path in targets.items():
        if not os.path.exists(src_path):
            print(f"[!] Missing or inaccessible: {src_path}")
            continue

        if os.path.isfile(src_path):
            dest_path = os.path.join(output_dir, os.path.basename(src_path))
            try:
                shutil.copy2(src_path, dest_path)  # Preserves MACB timestamps
                manifest.append({
                    "artifact_name": name,
                    "source_path": src_path,
                    "collected_path": dest_path,
                    "sha256": calculate_sha256(dest_path),
                    "collected_utc": datetime.now(timezone.utc).isoformat()
                })
                print(f"[+] Collected {name}")
            except PermissionError:
                print(f"[-] Permission denied (Admin required or file locked): {src_path}")

        elif os.path.isdir(src_path):
            sub_dir = os.path.join(output_dir, name)
            os.makedirs(sub_dir, exist_ok=True)
            for fname in os.listdir(src_path):
                full_src = os.path.join(src_path, fname)
                if os.path.isfile(full_src):
                    full_dest = os.path.join(sub_dir, fname)
                    try:
                        shutil.copy2(full_src, full_dest)
                        manifest.append({
                            "artifact_name": f"{name}:{fname}",
                            "source_path": full_src,
                            "collected_path": full_dest,
                            "sha256": calculate_sha256(full_dest),
                            "collected_utc": datetime.now(timezone.utc).isoformat()
                        })
                    except PermissionError:
                        continue
            print(f"[+] Collected directory {name}")

    manifest_path = os.path.join(output_dir, "chain_of_custody.json")
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=4)

    return manifest