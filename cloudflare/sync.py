#!/usr/bin/env python3
"""Synchronize standalone Cloudflare One Split Tunnel and AI route files."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


API_BASE = "https://api.cloudflare.com/client/v4"
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_path(base: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (base / path).resolve()


def normalize_hostname(value: str) -> str:
    hostname = value.strip().lower().strip(".")
    if hostname.startswith("*."):
        hostname = hostname[2:]
    if not HOST_RE.fullmatch(hostname):
        raise ValueError(f"invalid hostname: {value}")
    return hostname


def load_hostnames(path: Path) -> list[str]:
    hostnames: list[str] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        hostname = normalize_hostname(value)
        if hostname in seen:
            raise ValueError(f"duplicate hostname in {path.name}:{line_number}: {hostname}")
        seen.add(hostname)
        hostnames.append(hostname)
    if not hostnames:
        raise ValueError(f"hostname list is empty: {path}")
    return sorted(hostnames)


def validate_split_entries(entries: Any) -> list[dict[str, str]]:
    if not isinstance(entries, list):
        raise ValueError("Split Tunnel configuration must be a JSON array")
    if len(entries) > 1000:
        raise ValueError(f"Split Tunnel has {len(entries)} entries; Cloudflare limit is 1000")

    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            raise ValueError(f"Split Tunnel entry {index} must be an object")
        has_address = "address" in item
        has_host = "host" in item
        if has_address == has_host:
            raise ValueError(f"Split Tunnel entry {index} must contain exactly one of address or host")
        if has_address:
            value = str(ipaddress.ip_network(str(item["address"]), strict=False))
            key = ("address", value)
            output = {"address": value}
        else:
            value = normalize_hostname(str(item["host"]))
            key = ("host", value)
            output = {"host": value}
        if key in seen:
            raise ValueError(f"duplicate Split Tunnel entry: {value}")
        seen.add(key)
        if item.get("description"):
            output["description"] = str(item["description"])[:100]
        normalized.append(output)
    return normalized


class CloudflareAPI:
    def __init__(self, account_id: str, token: str) -> None:
        self.account_id = account_id
        self.token = token

    def request(self, method: str, path: str, payload: Any | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{API_BASE}/accounts/{self.account_id}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "tailscaleconf-cloudflare-sync/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Cloudflare API {method} {path} failed: HTTP {error.code}: {detail}"
            ) from error
        if not body.get("success", False):
            raise RuntimeError(f"Cloudflare API {method} {path} failed: {body.get('errors', body)}")
        return body.get("result")


def active_hostname_routes(result: Any) -> list[dict[str, Any]]:
    routes = result if isinstance(result, list) else []
    return [route for route in routes if not route.get("deleted_at")]


def sync_hostname_routes(
    api: CloudflareAPI,
    desired_hostnames: list[str],
    tunnel_id: str,
    tunnel_name: str,
    comment_prefix: str,
) -> None:
    existing = active_hostname_routes(api.request("GET", "/zerotrust/routes/hostname?per_page=1000"))
    by_hostname = {str(route.get("hostname", "")).lower(): route for route in existing}
    desired = set(desired_hostnames)

    conflicts = [
        route
        for hostname, route in by_hostname.items()
        if hostname in desired
        and str(route.get("tunnel_id")) != tunnel_id
        and not str(route.get("comment", "")).startswith(comment_prefix)
    ]
    if conflicts:
        details = ", ".join(
            f"{route.get('hostname')} -> {route.get('tunnel_name') or route.get('tunnel_id')}"
            for route in conflicts
        )
        raise RuntimeError(f"unmanaged hostname route conflicts detected: {details}")

    stale = [
        route
        for route in existing
        if str(route.get("comment", "")).startswith(comment_prefix)
        and (
            str(route.get("hostname", "")).lower() not in desired
            or str(route.get("tunnel_id")) != tunnel_id
        )
    ]
    for route in stale:
        api.request("DELETE", f"/zerotrust/routes/hostname/{route['id']}")
        print(f"deleted stale AI route: {route['hostname']}")

    for hostname in desired_hostnames:
        current = by_hostname.get(hostname)
        if current and str(current.get("tunnel_id")) == tunnel_id:
            print(f"kept AI route: {hostname} -> {tunnel_name}")
            continue
        api.request(
            "POST",
            "/zerotrust/routes/hostname",
            {"hostname": hostname, "tunnel_id": tunnel_id, "comment": comment_prefix},
        )
        print(f"created AI route: {hostname} -> {tunnel_name}")


def load_configuration(config_path: Path) -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
    config = read_json(config_path)
    base = config_path.parent
    split_path = resolve_path(base, config["split_tunnel_entries"])
    route_path = resolve_path(base, config["hostname_routes"]["entries_file"])
    split_entries = validate_split_entries(read_json(split_path))
    hostnames = load_hostnames(route_path)
    return config, split_entries, hostnames


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write the desired state to Cloudflare")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("config.json"),
    )
    args = parser.parse_args()

    try:
        config, split_entries, hostnames = load_configuration(args.config.resolve())
        print(f"validated Split Tunnel exclusions: {len(split_entries)}")
        print(f"validated AI hostname routes: {len(hostnames)}")

        if not args.apply:
            print("dry run only; pass --apply to update Cloudflare")
            return 0

        token = os.environ.get("CF_API_TOKEN") or os.environ.get("CLOUDFLARE_API_TOKEN")
        if not token:
            raise RuntimeError("CF_API_TOKEN is required with --apply")
        api = CloudflareAPI(config["account_id"], token)
        profile = config["mobile_profile"]
        mode = profile.get("split_tunnel_mode", "exclude")
        if mode not in {"include", "exclude"}:
            raise ValueError(f"unsupported split_tunnel_mode: {mode}")

        api.request("PUT", f"/devices/policy/{profile['id']}/{mode}", split_entries)
        print(f"replaced {profile['name']} Split Tunnel {mode} list: {len(split_entries)} entries")

        route_config = config["hostname_routes"]
        sync_hostname_routes(
            api,
            hostnames,
            route_config["tunnel_id"],
            route_config.get("tunnel_name", route_config["tunnel_id"]),
            route_config["comment_prefix"],
        )
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
