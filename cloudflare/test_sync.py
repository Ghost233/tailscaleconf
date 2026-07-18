import tempfile
import unittest
from pathlib import Path

import sync


class FakeAPI:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, path: str, payload: object | None = None) -> object:
        self.calls.append((method, path))
        return self.result


class SyncTests(unittest.TestCase):
    def test_load_standalone_hostnames(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ai-hostnames.list"
            path.write_text("# AI\nClaude.AI\nopenai.com # comment\n", encoding="utf-8")
            self.assertEqual(sync.load_hostnames(path), ["claude.ai", "openai.com"])

    def test_duplicate_hostname_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ai-hostnames.list"
            path.write_text("claude.ai\nCLAUDE.AI\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate hostname"):
                sync.load_hostnames(path)

    def test_split_tunnel_keeps_cloudflare_token_range_inside_warp(self) -> None:
        config_path = Path(__file__).with_name("split-tunnel-exclude.json")
        entries = sync.validate_split_entries(sync.read_json(config_path))
        networks = [
            sync.ipaddress.ip_network(entry["address"])
            for entry in entries
            if "address" in entry and ":" not in entry["address"]
        ]
        token_ip = sync.ipaddress.ip_address("100.80.0.1")
        self.assertFalse(any(token_ip in network for network in networks))

    def test_hostname_routes_target_jp_tunnel_by_name(self) -> None:
        config_path = Path(__file__).with_name("config.json")
        route_config = sync.read_json(config_path)["hostname_routes"]
        self.assertEqual(route_config["tunnel_name"], "jp")
        self.assertNotIn("tunnel_id", route_config)

    def test_resolve_tunnel_id_by_name(self) -> None:
        api = FakeAPI(
            [
                {"id": "jp-tunnel-id", "name": "jp", "deleted_at": None},
                {"id": "deleted-id", "name": "jp", "deleted_at": "2026-01-01T00:00:00Z"},
            ]
        )

        self.assertEqual(sync.resolve_tunnel_id(api, "jp"), "jp-tunnel-id")
        self.assertEqual(
            api.calls,
            [("GET", "/tunnels?name=jp&is_deleted=false&per_page=1000")],
        )

    def test_missing_tunnel_name_is_rejected(self) -> None:
        api = FakeAPI([])
        with self.assertRaisesRegex(RuntimeError, "Cloudflare Tunnel not found: jp"):
            sync.resolve_tunnel_id(api, "jp")


if __name__ == "__main__":
    unittest.main()
