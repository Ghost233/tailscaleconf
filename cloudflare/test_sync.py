import tempfile
import unittest
from pathlib import Path

import sync


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


if __name__ == "__main__":
    unittest.main()
