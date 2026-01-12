# SSR to Shadowrocket 转换工具使用说明

## 功能简介

这个脚本可以将 ACL4SSR 的 Clash 规则转换为 Shadowrocket 可用的规则格式。

## 修复内容

### 主要问题
1. ✅ **规则格式问题**：原脚本生成的 `.conf` 文件只包含规则列表，而不是完整的配置文件
2. ✅ **策略组映射**：添加了完整的策略组映射，支持所有常见策略组
3. ✅ **并发处理**：使用多线程并发下载和处理规则，大幅提升速度
4. ✅ **生成模式**：支持两种生成模式

### 两种生成模式

#### 1. List 模式（独立规则列表）
生成 `.list` 文件，适合作为 RULE-SET 导入到其他配置中：

```bash
python3 ssr_to_shadowrocket.py list [并发数]
```

特点：
- 生成 `.list` 文件
- 规则使用基本策略（PROXY/DIRECT/REJECT）
- 可在 Shadowrocket 中通过 RULE-SET 导入
- **推荐使用**：适合大多数场景

#### 2. Full 模式（完整配置文件）
生成完整的 `.conf` 配置文件，包含 [General]、[Rule]、[Host]、[URL Rewrite] 等段：

```bash
python3 ssr_to_shadowrocket.py full [并发数]
```

特点：
- 生成完整的 Shadowrocket 配置文件
- 包含所有必要的配置段
- 保留策略组名称（需要在 Shadowrocket 中配置对应的策略组）
- 生成 `shadowrocket_full.conf` 文件

## 使用示例

### 快速开始
```bash
# 使用默认设置（list 模式，10 并发）
python3 ssr_to_shadowrocket.py

# 使用 list 模式，20 并发（推荐）
python3 ssr_to_shadowrocket.py list 20

# 使用 full 模式，15 并发
python3 ssr_to_shadowrocket.py full 15
```

### 输出文件说明

#### List 模式输出
```
shadowrocket/
├── 🎇 Anthropic.list          # Anthropic AI 规则
├── 🎯 Google.list              # Google 服务规则
├── 🎯 Github Copilot.list      # GitHub Copilot 规则
├── 🎯 全球直连.list             # 国内直连规则
├── 🛑 广告拦截.list             # 广告拦截规则
├── 🚀 节点选择.list             # 代理规则
├── ALL.list                     # 所有规则合并
└── ...
```

#### Full 模式额外输出
```
shadowrocket/
├── shadowrocket_full.conf       # 完整配置文件
└── ...
```

## 规则格式对比

### List 模式规则示例
```
DOMAIN-SUFFIX,google.com,PROXY
DOMAIN,api.openai.com,PROXY
IP-CIDR,1.2.3.0/24,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,PROXY
```

### Full 模式规则示例
```
[General]
bypass-system = true
dns-server = system
ipv6 = true

[Rule]
# 🚀 节点选择
DOMAIN-SUFFIX,google.com,🚀 节点选择
DOMAIN,api.openai.com,🚀 节点选择

# 🎯 全球直连
GEOIP,CN,🎯 全球直连
FINAL,🐟 漏网之鱼

[Host]
localhost = 127.0.0.1

[URL Rewrite]
^https?://(www.)?google.cn https://www.google.com 302
```

## 策略组映射

脚本自动将以下策略组映射为基本策略（List 模式）：

| 策略组名称 | 映射策略 | 说明 |
|-----------|---------|------|
| 🎯 全球直连 | DIRECT | 国内直连 |
| 🛑 广告拦截 | REJECT | 拦截广告 |
| 🍃 应用净化 | REJECT | 应用内广告 |
| 🛡️ 隐私防护 | REJECT | 隐私跟踪 |
| 🚀 节点选择 | PROXY | 国际代理 |
| 🌍 国外媒体 | PROXY | 国际流媒体 |
| 📹 油管视频 | PROXY | YouTube |
| 🎥 奈飞视频 | PROXY | Netflix |
| 💬 OpenAi | PROXY | ChatGPT/OpenAI |
| 🎇 Anthropic | PROXY | Claude |
| 🎯 Google | PROXY | Google 服务 |
| 🌏 国内媒体 | DIRECT | 国内流媒体 |
| 📺 哔哩哔哩 | DIRECT | Bilibili |
| 🍎 苹果服务 | DIRECT | Apple 服务 |

## 性能优化

### 并发数设置建议
- **网络较好**：使用 20-30 并发
- **网络一般**：使用 10-15 并发
- **网络较差**：使用 5-10 并发

```bash
# 高速网络
python3 ssr_to_shadowrocket.py list 30

# 一般网络
python3 ssr_to_shadowrocket.py list 15

# 较慢网络
python3 ssr_to_shadowrocket.py list 5
```

### 缓存机制
- 脚本会自动缓存下载的规则文件到 `cache/` 目录
- 再次运行时会优先使用缓存，大幅提升速度
- 如需强制更新，删除 `cache/` 目录即可

## 在 Shadowrocket 中使用

### 使用 List 文件（推荐）

1. **上传规则文件**：
   - 将生成的 `.list` 文件上传到 GitHub/Gitee 等托管服务
   - 获取文件的 Raw URL

2. **在配置中引用**：
```
[Rule]
# 广告拦截
RULE-SET,https://raw.githubusercontent.com/your-repo/shadowrocket/🛑 广告拦截.list,REJECT

# Google 服务
RULE-SET,https://raw.githubusercontent.com/your-repo/shadowrocket/🎯 Google.list,PROXY

# 国内直连
RULE-SET,https://raw.githubusercontent.com/your-repo/shadowrocket/🎯 全球直连.list,DIRECT

# 其他流量
FINAL,PROXY
```

### 使用 Full 配置文件

1. 将 `shadowrocket_full.conf` 导入 Shadowrocket
2. 根据需要调整 [Proxy Group] 设置
3. 启用配置即可使用

## 常见问题

### Q: List 模式和 Full 模式如何选择？
**A**: 
- **推荐 List 模式**：更灵活，可以在 Shadowrocket 中自由组合规则
- **Full 模式**：适合需要完整配置文件的场景

### Q: 为什么有些规则没有转换？
**A**: 
- 检查网络连接，确保可以访问 GitHub
- 查看 `cache/` 目录，确认文件已下载
- 某些特殊规则类型可能不被支持

### Q: 如何更新规则？
**A**: 
```bash
# 删除缓存
rm -rf cache/

# 重新运行脚本
python3 ssr_to_shadowrocket.py list 20
```

### Q: 并发数设置多少合适？
**A**: 
- 推荐 10-20
- 太高可能导致网络请求失败
- 太低会影响转换速度

## 文件结构

```
tailscaleconf/
├── ssr_to_shadowrocket.py      # 转换脚本
├── ACL4SSR.ini                 # 源配置文件
├── USAGE.md                    # 使用说明（本文件）
├── cache/                      # 规则缓存目录
│   └── *.txt                   # 缓存的规则文件
└── shadowrocket/               # 输出目录
    ├── *.list                  # List 模式输出
    ├── *.conf                  # Full 模式输出（如果生成）
    └── ALL.list                # 所有规则合并
```

## 更新日志

### v2.0 (2026-01-13)
- ✅ 修复规则格式问题
- ✅ 添加完整策略组映射
- ✅ 实现多线程并发处理
- ✅ 支持两种生成模式（list/full）
- ✅ 优化输出文件结构
- ✅ 改进错误处理和日志输出

### v1.0 (初始版本)
- 基础规则转换功能
- 缓存机制

## 贡献

欢迎提交 Issue 和 Pull Request！
