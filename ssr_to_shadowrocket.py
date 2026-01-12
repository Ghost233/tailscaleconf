#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSR分流规则转Shadowrocket规则脚本
将ACL4SSR.ini配置文件转换为Shadowrocket可用的分流规则格式
"""

import os
import re
import urllib.request
import urllib.error
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置常量
ACL4SSR_INI_PATH = "/Users/ghost233/code/tailscaleconf/ACL4SSR.ini"
OUTPUT_DIR = "/Users/ghost233/code/tailscaleconf/shadowrocket"
CACHE_DIR = "/Users/ghost233/code/tailscaleconf/cache"

# 策略组名映射（用于生成独立规则列表）
POLICY_MAP = {
    "🎯 全球直连": "DIRECT",
    "🛑 广告拦截": "REJECT",
    "🍃 应用净化": "REJECT",
    "🆎 AdBlock": "REJECT",
    "🛡️ 隐私防护": "REJECT",
    "🚀 节点选择": "PROXY",
    "🌍 国外媒体": "PROXY",
    "🌏 国内媒体": "DIRECT",
    "🍎 苹果服务": "DIRECT",
    "🎥 奈飞视频": "PROXY",
    "🎮 游戏平台": "PROXY",
    "🎶 网易音乐": "DIRECT",
    "🐟 漏网之鱼": "PROXY",
    "💬 OpenAi": "PROXY",
    "📢 谷歌FCM": "PROXY",
    "📲 电报消息": "PROXY",
    "📹 油管视频": "PROXY",
    "📺 巴哈姆特": "PROXY",
    "📺 哔哩哔哩": "DIRECT",
    "🤖 AI": "PROXY",
    "🎇 Anthropic": "PROXY",
    "🎯 Github Copilot": "PROXY",
    "🎯 Google": "PROXY",
    "🎯 Other": "PROXY",
    "🎯 Parsec": "PROXY",
}

# 生成模式
GENERATE_MODE = "list"  # "list" 或 "full"
# list: 生成独立规则列表文件(.list)，不包含策略组
# full: 生成完整配置文件(.conf)，包含所有段和策略组

# Clash规则类型到Shadowrocket的映射
RULE_TYPE_MAP = {
    "DOMAIN": "DOMAIN",
    "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
    "IP-CIDR": "IP-CIDR",
    "GEOIP": "GEOIP",
    "MATCH": "FINAL",
}


class SSRConverter:
    """SSR规则转Shadowrocket转换器"""

    def __init__(self, ini_path: str, output_dir: str, cache_dir: str, mode: str = "list", max_workers: int = 10):
        self.ini_path = ini_path
        self.output_dir = Path(output_dir)
        self.cache_dir = Path(cache_dir)
        self.mode = mode  # "list" 或 "full"
        self.max_workers = max_workers  # 最大并发数
        self.rulesets: List[Tuple[str, str]] = []  # (策略组, 规则URL或特殊规则)
        self.converted_rules: Dict[str, List[str]] = {}  # 策略组 -> 规则列表

        # 创建输出和缓存目录
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def parse_acl4ssr_ini(self) -> None:
        """解析ACL4SSR.ini文件，提取所有ruleset"""
        print(f"正在解析配置文件: {self.ini_path}")

        with open(self.ini_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("ruleset="):
                    # 解析 ruleset=策略组,规则
                    match = re.match(r"ruleset=([^,]+),(.+)", line)
                    if match:
                        policy_group = match.group(1).strip()
                        rule_url = match.group(2).strip()
                        self.rulesets.append((policy_group, rule_url))
                        print(f"  找到规则集: {policy_group} -> {rule_url}")

        print(f"共解析出 {len(self.rulesets)} 个规则集\n")

    def get_cache_path(self, url: str) -> Path:
        """根据URL生成缓存文件路径"""
        # 使用URL的MD5哈希作为文件名
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.txt"

    def download_rule_file(self, url: str, use_cache: bool = True) -> Optional[str]:
        """下载规则文件，支持缓存"""
        cache_path = self.get_cache_path(url)

        # 检查缓存
        if use_cache and cache_path.exists():
            print(f"  使用缓存: {cache_path.name}")
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception as e:
                print(f"  读取缓存失败: {e}")

        # 下载文件
        print(f"  下载规则: {url}")
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read().decode("utf-8")

                # 保存到缓存
                try:
                    with open(cache_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    print(f"  已缓存到: {cache_path.name}")
                except Exception as e:
                    print(f"  保存缓存失败: {e}")

                return content

        except urllib.error.URLError as e:
            print(f"  下载失败: {e}")
            # 如果有缓存，尝试使用缓存
            if cache_path.exists():
                print(f"  回退使用缓存: {cache_path.name}")
                try:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception:
                    pass
            return None
        except Exception as e:
            print(f"  下载异常: {e}")
            return None

    def convert_clash_rule_to_shadowrocket(
        self, rule: str, policy_group: str
    ) -> Optional[str]:
        """将Clash规则转换为Shadowrocket格式"""
        rule = rule.strip()
        if not rule or rule.startswith("#"):
            return None

        # 解析Clash规则格式
        parts = rule.split(",")
        if len(parts) < 2:
            return None

        rule_type = parts[0].strip()
        rule_value = parts[1].strip()

        # 根据模式选择策略
        if self.mode == "list":
            # 独立规则列表模式：映射到基本策略
            final_policy = POLICY_MAP.get(policy_group, "PROXY")
        else:
            # 完整配置模式：保留策略组名
            final_policy = policy_group

        # 处理特殊规则类型
        if rule_type in ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"]:
            return f"{rule_type},{rule_value},{final_policy}"

        elif rule_type == "IP-CIDR":
            # IP-CIDR规则添加no-resolve
            return f"{rule_type},{rule_value},{final_policy},no-resolve"

        elif rule_type == "GEOIP":
            return f"{rule_type},{rule_value},{final_policy}"

        elif rule_type == "MATCH":
            return f"FINAL,{final_policy}"

        # 不支持的规则类型
        return None

    def process_ruleset(self, policy_group: str, rule_def: str) -> None:
        """处理单个规则集"""
        print(f"\n处理规则集: {policy_group}")

        # 初始化策略组的规则列表
        if policy_group not in self.converted_rules:
            self.converted_rules[policy_group] = []

        # 处理特殊规则
        if rule_def.startswith("["):
            # 特殊规则如: []GEOIP,CN 或 []FINAL
            special_rule = rule_def[2:]  # 去掉[]

            if special_rule == "FINAL":
                final_policy = POLICY_MAP.get(policy_group, policy_group)
                self.converted_rules[policy_group].append(f"FINAL,{final_policy}")
                print(f"  添加FINAL规则")

            elif special_rule.startswith("GEOIP,"):
                # GEOIP规则
                geoip_type = special_rule.split(",")[1]
                self.converted_rules[policy_group].append(
                    f"GEOIP,{geoip_type},{POLICY_MAP.get(policy_group, policy_group)}"
                )
                print(f"  添加GEOIP规则: {geoip_type}")

            return

        # 下载规则文件
        content = self.download_rule_file(rule_def)
        if not content:
            print(f"  跳过规则集（无法下载）")
            return

        # 转换每条规则
        converted_count = 0
        for line in content.splitlines():
            converted = self.convert_clash_rule_to_shadowrocket(line, policy_group)
            if converted:
                self.converted_rules[policy_group].append(converted)
                converted_count += 1

        print(f"  转换了 {converted_count} 条规则")

    def generate_output_files(self) -> None:
        """生成输出文件"""
        print("\n正在生成输出文件...")

        all_rules = []
        file_extension = ".list" if self.mode == "list" else ".conf"

        for policy_group, rules in self.converted_rules.items():
            if not rules:
                continue

            # 生成文件名（保留表情符号）
            filename = f"{policy_group}{file_extension}"
            filepath = self.output_dir / filename

            # 写入分组文件
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"# Shadowrocket Rules for {policy_group}\n")
                f.write(f"# Generated from ACL4SSR.ini\n")
                f.write(f"# Mode: {self.mode}\n")
                f.write(f"# Total rules: {len(rules)}\n\n")
                for rule in rules:
                    f.write(f"{rule}\n")

            print(f"  生成文件: {filename} ({len(rules)} 条规则)")

            # 添加到合并列表
            all_rules.extend(rules)

        # 生成合并文件
        if all_rules:
            all_filename = f"ALL{file_extension}"
            all_filepath = self.output_dir / all_filename
            with open(all_filepath, "w", encoding="utf-8") as f:
                f.write(f"# Shadowrocket Rules - ALL\n")
                f.write(f"# Generated from ACL4SSR.ini\n")
                f.write(f"# Mode: {self.mode}\n")
                f.write(f"# Total rules: {len(all_rules)}\n\n")
                for rule in all_rules:
                    f.write(f"{rule}\n")

            print(f"  生成合并文件: {all_filename} ({len(all_rules)} 条规则)")

        # 如果是full模式，生成完整配置文件
        if self.mode == "full":
            self.generate_full_config()

    def convert(self) -> None:
        """执行完整的转换流程"""
        print("=" * 60)
        print("SSR分流规则转Shadowrocket规则")
        print(f"模式: {self.mode} ({'独立规则列表' if self.mode == 'list' else '完整配置文件'})")
        print(f"并发数: {self.max_workers}")
        print("=" * 60)

        # 1. 解析配置文件
        self.parse_acl4ssr_ini()

        # 2. 并发处理所有规则集
        print(f"\n开始并发处理 {len(self.rulesets)} 个规则集...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_ruleset = {
                executor.submit(self.process_ruleset, policy_group, rule_def): (policy_group, rule_def)
                for policy_group, rule_def in self.rulesets
            }

            # 收集结果
            completed = 0
            for future in as_completed(future_to_ruleset):
                policy_group, rule_def = future_to_ruleset[future]
                try:
                    future.result()
                    completed += 1
                    print(f"  [{completed}/{len(self.rulesets)}] 完成: {policy_group}")
                except Exception as e:
                    print(f"  处理失败: {policy_group} - {e}")

        # 3. 生成输出文件
        self.generate_output_files()

        print("\n" + "=" * 60)
        print("转换完成！")
        print(f"输出目录: {self.output_dir}")
        print(f"模式: {self.mode}")
        print("=" * 60)


    def generate_full_config(self) -> None:
        """生成完整的Shadowrocket配置文件"""
        print("\n正在生成完整配置文件...")
        
        full_config_path = self.output_dir / "shadowrocket_full.conf"
        
        with open(full_config_path, "w", encoding="utf-8") as f:
            # [General] 段
            f.write("[General]\n")
            f.write("bypass-system = true\n")
            f.write("skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local\n")
            f.write("dns-server = system\n")
            f.write("ipv6 = true\n")
            f.write("prefer-ipv6 = false\n")
            f.write("\n")
            
            # [Rule] 段
            f.write("[Rule]\n")
            f.write("# Generated from ACL4SSR.ini\n\n")
            
            # 按策略组顺序写入规则
            for policy_group, rules in self.converted_rules.items():
                if rules:
                    f.write(f"# {policy_group}\n")
                    for rule in rules:
                        f.write(f"{rule}\n")
                    f.write("\n")
            
            # [Host] 段
            f.write("[Host]\n")
            f.write("localhost = 127.0.0.1\n")
            f.write("\n")
            
            # [URL Rewrite] 段
            f.write("[URL Rewrite]\n")
            f.write("^https?://(www.)?g.cn https://www.google.com 302\n")
            f.write("^https?://(www.)?google.cn https://www.google.com 302\n")
        
        print(f"  生成完整配置: shadowrocket_full.conf")


def main():
    """主函数"""
    import sys
    
    # 从命令行参数获取模式
    mode = GENERATE_MODE
    max_workers = 10
    
    if len(sys.argv) > 1:
        if sys.argv[1] in ["list", "full"]:
            mode = sys.argv[1]
    
    if len(sys.argv) > 2:
        try:
            max_workers = int(sys.argv[2])
        except ValueError:
            pass
    
    print(f"启动模式: {mode}")
    print(f"并发数: {max_workers}\n")
    
    converter = SSRConverter(ACL4SSR_INI_PATH, OUTPUT_DIR, CACHE_DIR, mode=mode, max_workers=max_workers)
    converter.convert()


if __name__ == "__main__":
    main()
