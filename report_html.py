"""Known-asset context: label hosts as recognized/unrecognized in reports."""

import csv


def load_assets(path):
    """CSV with columns: ip,role,name (name optional). Returns {ip: {role, name}}."""
    assets = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ip", "").strip()
            if not ip:
                continue
            assets[ip] = {
                "role": row.get("role", "").strip() or "unspecified role",
                "name": row.get("name", "").strip(),
            }
    return assets


def annotate_host(ip, assets):
    if assets is None:
        return ip
    if ip in assets:
        info = assets[ip]
        label = info["name"] or info["role"]
        return f"{ip} (recognized: {label}, {info['role']})"
    return f"{ip} (UNRECOGNIZED -- not in provided asset list)"
