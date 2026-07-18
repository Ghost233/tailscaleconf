# Cloudflare Zero Trust 自动同步

本目录管理两类配置：

1. `手机专用` 设备配置文件的 Split Tunnel Exclude 列表。
2. `ai-hostnames.list` 中 AI 域名的 Hostname Routes，全部指向 `hk` Tunnel。

Split Tunnel 只决定流量是否进入 Cloudflare One Client，不能选择出口。AI 域名使用
Hostname Route 才能经 `hk` 上的 `cloudflared` 访问公网，并使用服务器公网 IP 出口。

## 文件

- `config.json`：Cloudflare Account、手机配置文件、`hk` Tunnel 以及专用列表路径。
- `split-tunnel-exclude.json`：每次同步都会完整覆盖到 `手机专用` 的 Exclude 列表。
- `ai-hostnames.list`：经 `hk` 出口的独立 AI 域名列表。
- `sync.py`：校验配置、解析 AI 规则并调用 Cloudflare API。
- `test_sync.py`：离线单元测试。

`100.80.0.0/16` 未加入 Exclude。这是 Hostname Route 使用的 Cloudflare token IP
范围，必须继续经过 WARP，AI 域名才能被送到 `hk` Tunnel。

## AI 规则来源

Cloudflare 配置不引用本目录之外的任何规则文件，也不会在运行时下载远程列表。
当前 Anthropic、OpenAI、通用 AI 和 GitHub Copilot 域名均已复制到
`ai-hostnames.list`。继续增加配置时，每行写一个明确域名即可。

脚本只删除注释以 `tailscaleconf:ai` 开头、但已不再出现在配置中的 Hostname Route。
手工创建的测试路由和其他路由不会被删除。如果同名路由已指向其他 Tunnel，脚本会
报错退出，不会擅自覆盖。

## 本地校验

```bash
cd /Users/admin/code/tailscaleconf
python3 -m unittest discover -s cloudflare -p 'test_*.py'
python3 cloudflare/sync.py
```

第二条命令默认只构建和校验，不访问 Cloudflare。实际同步：

```bash
export CF_API_TOKEN='你的 API Token'
python3 cloudflare/sync.py --apply
```

API Token 至少需要：

- 编辑设备策略/Split Tunnel 的 Zero Trust 写权限。
- `Cloudflare One Networks Write` 或 `Cloudflare Tunnel Write`，用于 Hostname Routes。

## GitHub Secret 与 Action

在 GitHub 仓库的 `Settings → Secrets and variables → Actions` 中创建：

- `CF_API_TOKEN`

Account ID、设备配置 ID 和 Tunnel ID 不是密钥，已经声明在 `config.json`。Action
会在任意提交推送到 `main` 后运行测试，然后执行一次全量同步。GitHub Actions 的
触发单位是 `push`；一次推送包含多个本地提交时，只会同步一次。
