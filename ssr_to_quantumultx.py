#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSR分流规则转Quantumult X规则脚本
将ACL4SSR.ini配置文件转换为Quantumult X可用的分流规则格式
"""

import hashlib
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 配置常量
PROJECT_ROOT = Path(__file__).resolve().parent
ACL4SSR_INI_PATH = str(PROJECT_ROOT / "ACL4SSR.ini")
OUTPUT_DIR = str(PROJECT_ROOT / "QuantumultX")
CACHE_DIR = str(PROJECT_ROOT / "cache")

# 策略组名映射（用于生成独立规则列表）
POLICY_MAP = {
    "🎯 全球直连": "DIRECT",
    "🛑 广告拦截": "REJECT",
    "🍃 应用净化": "REJECT",
    "🆎 AdBlock": "REJECT",
    "🛡️ 隐私防护": "REJECT",
    "🚀 节点选择": "proxy",
    "🌍 国外媒体": "proxy",
    "🌏 国内媒体": "DIRECT",
    "🍎 苹果服务": "DIRECT",
    "🎥 奈飞视频": "proxy",
    "🎮 游戏平台": "proxy",
    "🎶 网易音乐": "DIRECT",
    "🐟 漏网之鱼": "proxy",
    "💬 OpenAi": "proxy",
    "📢 谷歌FCM": "proxy",
    "📲 电报消息": "proxy",
    "📹 油管视频": "proxy",
    "📺 巴哈姆特": "proxy",
    "📺 哔哩哔哩": "DIRECT",
    "🤖 AI": "proxy",
    "🎇 Anthropic": "proxy",
    "🎯 Github Copilot": "proxy",
    "🎯 Google": "proxy",
    "🎯 Other": "proxy",
    "🎯 Parsec": "proxy",
}

# 生成模式
GENERATE_MODE = "list"  # "list" 或 "full"
# list: 生成独立规则列表文件(.list)，不包含策略组
# full: 生成完整配置文件(.conf)，包含所有段和策略组

# Clash规则类型到Quantumult X的映射
RULE_TYPE_MAP = {
    "DOMAIN": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP-CIDR6",
    "GEOIP": "GEOIP",
    "MATCH": "FINAL",
}


class QuantumultXConverter:
    """SSR规则转Quantumult X转换器"""

    def __init__(
        self,
        ini_path: str,
        output_dir: str,
        cache_dir: str,
        mode: str = "list",
        max_workers: int = 10,
    ):
        self.ini_path = ini_path
        self.output_dir = Path(output_dir)
        self.cache_dir = Path(cache_dir)
        self.mode = mode  # "list" 或 "full"
        self.max_workers = max_workers  # 最大并发数
        self.rulesets: List[Tuple[str, str]] = []  # (策略组, 规则URL或特殊规则)
        self.converted_rules: Dict[str, List[str]] = {}  # 策略组 -> 规则列表

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def parse_acl4ssr_ini(self) -> None:
        """解析ACL4SSR.ini文件，提取所有ruleset"""
        print(f"正在解析配置文件: {self.ini_path}")

        with open(self.ini_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("ruleset="):
                    match = re.match(r"ruleset=([^,]+),(.+)", line)
                    if match:
                        policy_group = match.group(1).strip()
                        rule_url = match.group(2).strip()
                        self.rulesets.append((policy_group, rule_url))
                        print(f"  找到规则集: {policy_group} -> {rule_url}")

        print(f"共解析出 {len(self.rulesets)} 个规则集\n")

    def get_cache_path(self, url: str) -> Path:
        """根据URL生成缓存文件路径"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.txt"

    def download_rule_file(self, url: str, use_cache: bool = True) -> Optional[str]:
        """下载规则文件，支持缓存"""
        cache_path = self.get_cache_path(url)

        if use_cache and cache_path.exists():
            print(f"  使用缓存: {cache_path.name}")
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as exc:  # pragma: no cover - 防止缓存损坏
                print(f"  读取缓存失败: {exc}")

        print(f"  下载规则: {url}")
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read().decode("utf-8")
                try:
                    with open(cache_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    print(f"  已缓存到: {cache_path.name}")
                except Exception as exc:  # pragma: no cover
                    print(f"  保存缓存失败: {exc}")
                return content
        except urllib.error.URLError as exc:
            print(f"  下载失败: {exc}")
            if cache_path.exists():
                print(f"  回退使用缓存: {cache_path.name}")
                try:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception:
                    pass
            return None
        except Exception as exc:  # pragma: no cover
            print(f"  下载异常: {exc}")
            return None

    def convert_clash_rule_to_quantumult(
        self, rule: str, policy_group: str
    ) -> Optional[str]:
        """将Clash规则转换为Quantumult X格式"""
        rule = rule.strip()
        if not rule or rule.startswith("#"):
            return None

        parts = [p.strip() for p in rule.split(",") if p.strip()]
        if len(parts) < 2:
            return None

        rule_type_raw = parts[0]
        rule_value = parts[1]
        mapped_type = RULE_TYPE_MAP.get(rule_type_raw)

        if mapped_type is None:
            return None

        if self.mode == "list":
            final_policy = POLICY_MAP.get(policy_group, "proxy")
        else:
            final_policy = policy_group

        extras = parts[2:]

        if mapped_type in {"HOST", "HOST-SUFFIX", "HOST-KEYWORD"}:
            return f"{mapped_type},{rule_value},{final_policy}"

        if mapped_type in {"IP-CIDR", "IP-CIDR6"}:
            flags = [flag for flag in extras if flag]
            if not any(flag.lower() == "no-resolve" for flag in flags):
                flags.append("no-resolve")
            flag_part = f",{','.join(flags)}" if flags else ""
            return f"{mapped_type},{rule_value},{final_policy}{flag_part}"

        if mapped_type == "GEOIP":
            return f"GEOIP,{rule_value},{final_policy}"

        if mapped_type == "FINAL":
            return f"FINAL,{final_policy}"

        return None

    def process_ruleset(self, policy_group: str, rule_def: str) -> None:
        """处理单个规则集"""
        print(f"\n处理规则集: {policy_group}")

        if policy_group not in self.converted_rules:
            self.converted_rules[policy_group] = []

        if rule_def.startswith("["):
            special_rule = rule_def[2:]

            if special_rule == "FINAL":
                final_policy = POLICY_MAP.get(policy_group, policy_group)
                self.converted_rules[policy_group].append(f"FINAL,{final_policy}")
                print("  添加FINAL规则")
            elif special_rule.startswith("GEOIP,"):
                geoip_type = special_rule.split(",")[1]
                self.converted_rules[policy_group].append(
                    f"GEOIP,{geoip_type},{POLICY_MAP.get(policy_group, policy_group)}"
                )
                print(f"  添加GEOIP规则: {geoip_type}")
            elif special_rule.startswith("IP-CIDR,"):
                cidr = special_rule.split(",", 1)[1]
                final_policy = POLICY_MAP.get(policy_group, policy_group)
                self.converted_rules[policy_group].append(
                    f"IP-CIDR,{cidr},{final_policy},no-resolve"
                )
                print(f"  添加IP-CIDR规则: {cidr}")
            return

        content = self.download_rule_file(rule_def)
        if not content:
            print("  跳过规则集（无法下载）")
            return

        converted_count = 0
        for line in content.splitlines():
            converted = self.convert_clash_rule_to_quantumult(line, policy_group)
            if converted:
                self.converted_rules[policy_group].append(converted)
                converted_count += 1

        print(f"  转换了 {converted_count} 条规则")

    def generate_output_files(self) -> None:
        """生成输出文件"""
        print("\n正在生成输出文件...")

        all_rules: List[str] = []
        file_extension = ".list" if self.mode == "list" else ".conf"

        for policy_group, rules in self.converted_rules.items():
            if not rules:
                continue

            filename = f"{policy_group}{file_extension}"
            filepath = self.output_dir / filename

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"# Quantumult X Rules for {policy_group}\n")
                f.write("# Generated from ACL4SSR.ini\n")
                f.write(f"# Mode: {self.mode}\n")
                f.write(f"# Total rules: {len(rules)}\n\n")
                for rule in rules:
                    f.write(f"{rule}\n")

            print(f"  生成文件: {filename} ({len(rules)} 条规则)")
            all_rules.extend(rules)

        if all_rules:
            all_filename = f"ALL{file_extension}"
            all_filepath = self.output_dir / all_filename
            with open(all_filepath, "w", encoding="utf-8") as f:
                f.write("# Quantumult X Rules - ALL\n")
                f.write("# Generated from ACL4SSR.ini\n")
                f.write(f"# Mode: {self.mode}\n")
                f.write(f"# Total rules: {len(all_rules)}\n\n")
                for rule in all_rules:
                    f.write(f"{rule}\n")
            print(f"  生成合并文件: {all_filename} ({len(all_rules)} 条规则)")

        if self.mode == "full":
            self.generate_full_config()

    def generate_full_config(self) -> None:
        """生成完整的Quantumult X配置文件"""
        print("\n正在生成完整配置文件...")
        full_config_path = self.output_dir / "quantumultx_full.conf"

        with open(full_config_path, "w", encoding="utf-8") as f:
            f.write("[general]\n")
            f.write("bypass-system=true\n")
            f.write("server_check_url=http://www.gstatic.com/generate_204\n")
            f.write("dns_exclusion_list=*.local,localhost\n")
            f.write("ipv6=true\n")
            f.write("\n")

            f.write("[dns]\n")
            f.write("prefer-doh=false\n")
            f.write("server=system\n")
            f.write("ipv6=true\n")
            f.write("\n")

            f.write("[policy]\n")
            seen: set[str] = set()
            for policy_group in self.converted_rules.keys():
                if policy_group in seen:
                    continue
                seen.add(policy_group)
                f.write(f"static={policy_group}, proxy, direct, reject\n")
            f.write("static=PROXY, proxy\n")
            f.write("static=DIRECT, direct\n")
            f.write("static=REJECT, reject\n")
            f.write("\n")

            f.write("[filter_local]\n")
            f.write("# Generated from ACL4SSR.ini\n\n")
            for policy_group, rules in self.converted_rules.items():
                if rules:
                    f.write(f"# {policy_group}\n")
                    for rule in rules:
                        f.write(f"{rule}\n")
                    f.write("\n")

            f.write("[rewrite_local]\n\n")
            f.write("[http_backend]\n\n")
            f.write("[task_local]\n\n")
            f.write("[mitm]\n")

        print("  生成完整配置: quantumultx_full.conf")

    def convert(self) -> None:
        """执行完整的转换流程"""
        print("=" * 60)
        print("SSR分流规则转Quantumult X规则")
        print(
            f"模式: {self.mode} ({'独立规则列表' if self.mode == 'list' else '完整配置文件'})"
        )
        print(f"并发数: {self.max_workers}")
        print("=" * 60)

        self.parse_acl4ssr_ini()

        print(f"\n开始并发处理 {len(self.rulesets)} 个规则集...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ruleset = {
                executor.submit(self.process_ruleset, policy_group, rule_def): (
                    policy_group,
                    rule_def,
                )
                for policy_group, rule_def in self.rulesets
            }

            completed = 0
            for future in as_completed(future_to_ruleset):
                policy_group, _ = future_to_ruleset[future]
                try:
                    future.result()
                    completed += 1
                    print(f"  [{completed}/{len(self.rulesets)}] 完成: {policy_group}")
                except Exception as exc:  # pragma: no cover
                    print(f"  处理失败: {policy_group} - {exc}")

        self.generate_output_files()

        print("\n" + "=" * 60)
        print("转换完成！")
        print(f"输出目录: {self.output_dir}")
        print(f"模式: {self.mode}")
        print("=" * 60)


def main() -> None:
    """主函数"""
    import sys

    mode = GENERATE_MODE
    max_workers = 10

    if len(sys.argv) > 1 and sys.argv[1] in ["list", "full"]:
        mode = sys.argv[1]

    if len(sys.argv) > 2:
        try:
            max_workers = int(sys.argv[2])
        except ValueError:
            pass

    print(f"启动模式: {mode}")
    print(f"并发数: {max_workers}\n")

    converter = QuantumultXConverter(
        ACL4SSR_INI_PATH, OUTPUT_DIR, CACHE_DIR, mode=mode, max_workers=max_workers
    )
    converter.convert()


if __name__ == "__main__":
    main()
