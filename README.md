# gate

自动检测 [VPN Gate](https://www.vpngate.net/) 的 **SSTP(TCP)** 节点可用性，并用 Cloudflare Worker 实测出口 IP，最后把结果发布到 GitHub Pages，供 edgetunnel 之类的项目当作「自定义优选 IP / 订阅」使用。

> 这是一个模板仓库：**你只需要 Fork、添加一个 Secret、手动跑一次**，不需要改代码。

---

## 特性

- 只用 VPN Gate 的 TCP 节点（VPN Gate 的 TCP 端口即 SSTP 端口），并发检测
- Cloudflare Worker 检测真实出口 IP、ASN、机房/住宅属性、延迟
- 检测结果自动按国家/地区归类，住宅出口优先
- 同时产出仪表盘（`index.html`）、结构化数据（`data.json`）、订阅文件（`nodes.txt`）
- 源站失败自动回退镜像；检测整体失败时**拒绝发布**，不会用空结果覆盖你上一份订阅
- 所有配置走环境变量 / GitHub Secret，不写死域名

## 架构

```
GitHub Actions (手动或 cron)
        │
        ├─ 抓取 VPN Gate API（失败回退 GitHub 镜像）
        ├─ 解析 OpenVPN 配置 → 只保留 proto tcp → 得到 SSTP 候选
        ├─ 去重 + 按 Ping 预排序 +（可选）截断
        ├─ 并发请求 Cloudflare Worker: /check?sstp=vpn:vpn@host:port
        ├─ 合并静态优选域名 + 优选 API 端点
        └─ 生成 public/{data.json,index.html,nodes.txt}
                    │
                    └─ GitHub Pages → nodes.txt 作为 edgetunnel 的「自定义优选 IP」
```

## 快速开始

1. **Fork** 本仓库。
2. 打开 `Settings → Secrets and variables → Actions`，新增 Secret：
   - Name：`DOMAIN`
   - Secret：你的检测 Worker 主机名，**只填 host**，例如 `abc.workers.dev` 或 `check.example.com`
   - 不需要写 `https://`、不需要写 `/check`，工作流会自动拼成 `https://<DOMAIN>/check?sstp=vpn:vpn@`
3. 打开 `Settings → Pages`，把 **Source** 选成 **GitHub Actions**（工作流通常也会自动开启，失败时按此手动配置）。
4. 打开 `Actions → VPN Gate Node Check → Run workflow`，跑完即可访问：
   - 订阅：`https://<你的用户名>.github.io/<仓库名>/nodes.txt`
   - 仪表盘：`https://<你的用户名>.github.io/<仓库名>/`
5. 把订阅地址填入 edgetunnel 后台的「自定义优选 IP / 订阅」中。

## 自动更新（可选）

模板默认**不配置定时任务**，避免给你的仓库带来意外消耗。需要自动更新时，在 `.github/workflows/check.yml` 里取消注释：

```yaml
on:
  schedule:
    - cron: '*/30 * * * *'
```

注意事项：

- GitHub 的定时任务最小间隔约 5 分钟，但实际通常会延迟几分钟，不保证准点。
- 仓库连续 60 天没有提交，定时任务会被 GitHub 自动停用。
- 需要固定时间就写 UTC 时间，例如北京时间 08:00 = `0 0 * * *`。

## 配置项

全部通过环境变量传入，工作流里已经处理好常用的几个。

| 变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `CHECK_WORKER` | 无（必需） | 检测地址前缀，必须以 `sstp=vpn:vpn@` 结尾。工作流由 Secret `DOMAIN` 拼出 |
| `DOMAIN` | 无 | 仅工作流使用；Secret 形式，值为 Worker 的 host |
| `CHECK_CONCURRENCY` | `32` | 并发检测数，建议 16–32 |
| `CHECK_TIMEOUT` | `25` | 单节点检测超时（秒）。检测 Worker 通常十余秒内返回，不建议设太大 |
| `CHECK_DEADLINE` | `1200` | 整轮检测的总截止时间（秒），超时未完成的节点按失败处理 |
| `MAX_CHECK_NODES` | `0` | 最多检测多少个节点，`0` 表示全部；按 Ping 从低到高取 |
| `MIN_SUCCESS_RATIO` | `0` | 成功率低于该比例时拒绝发布（0–1），`0` 表示不启用 |
| `MAX_RESIDENTIAL_PER_COUNTRY` | `20` | 每个国家/地区写入 nodes.txt 的住宅节点上限 |
| `MAX_DATACENTER_PER_COUNTRY` | `10` | 每个国家/地区写入 nodes.txt 的机房节点上限 |
| `EDGE_HOSTS` / `HOSTS_ENTRY` | 内置池 | 自定义优选域名池，逗号分隔，可带端口，如 `a.com:443,b.com:8443` |
| `OPTIMAL_API` | `https://cf.090227.xyz/ct?ips=6&port=443` | 优选 API；返回每行一个 `IP:端口` 或 IPv6，支持逗号分隔多个 |
| `PUBLIC_DIR` | `./public` | 产物目录 |
| `VPNGATE_API` / `VPNGATE_MIRROR` | 官方 API / 内置镜像 | 数据源，一般不用改 |
| `NODES_URL` | 自动推导 | 仅用于日志展示；默认按 `GITHUB_REPOSITORY` 推导 |

## 产物说明

### `nodes.txt`

每行一个 edgetunnel 可识别的条目：

```
入口域名:端口#国家-住宅-01$sstp://vpn:vpn@节点域名:端口
```

- 备注中的 `#`、`$` 会被剔除，避免破坏行格式
- 每个国家/地区有数量上限（见上表），避免订阅过大
- 同一链接不会重复出现

### `data.json`（schema_version = 1）

下面只截取 1 个国家/1 个节点做示例，真实文件包含全部检测结果。

```json
{
  "schema_version": 1,
  "generated_at": "2026-01-01 00:00:00 UTC",
  "source": "vpngate.net/api/iphone",
  "worker_host": "abc.workers.dev",
  "duration_s": 68.2,
  "stats": {
    "raw_nodes": 95, "sstp_nodes": 87, "checked": 87,
    "success": 31, "failed": 56, "worker_errors": 0,
    "timed_out": 0, "countries": 12,
    "residential_est": 18, "datacenter_est": 13, "unknown_est": 0
  },
  "countries": {
    "JP": {
      "code": "JP", "name": "Japan", "count": 1,
      "residential": 1, "datacenter": 0, "unknown": 0,
      "nodes": [
        {
          "host": "public-vpn-153.opengw.net", "port": 443,
          "ip": "219.100.37.153", "country": "Japan", "country_code": "JP",
          "ping": 45, "score": 123456,
          "protocol": "sstp", "link": "sstp://vpn:vpn@public-vpn-153.opengw.net:443",
          "status": "success", "success": true,
          "latency_ms": 120, "colo": "NRT",
          "residential": "residential",
          "exit": {"ip": "198.51.100.7", "country": "Japan", "country_code": "JP",
                   "city": "Tokyo", "asn": 1234, "org": "NTT EAST", "is_datacenter": false}
        }
      ]
    }
  }
}
```

## 本地运行

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 只检测前 5 个节点，结果写到 ./public
CHECK_WORKER="https://abc.workers.dev/check?sstp=vpn:vpn@" MAX_CHECK_NODES=5 python vpngate.py
```

未设置 `CHECK_WORKER` 时会直接报错并提示如何配置，不会跑出一份坏数据。

## 测试

```bash
pip install -r requirements-dev.txt
pytest        # 含离线端到端测试：本地假数据源 + 假 Worker
ruff check .
```

## 常见问题

**Q：运行失败，提示 `未配置检测地址`**
A：没加 Secret `DOMAIN`，或 Secret 名字写错（区分大小写）。

**Q：自动启用 Pages 失败（403）**
A：去 `Settings → Pages` 手动把 Source 选为 **GitHub Actions**，再重新运行工作流。

**Q：所有节点都检测失败**
A：先确认 Worker 地址能手动访问：浏览器打开
`https://<DOMAIN>/check?sstp=vpn:vpn@www.iplocate.io:443`
能返回 JSON 才说明 Worker 正常。若返回错误，检查 Worker 是否部署、路由是否过期。

**Q：Worker 全部请求异常 / 节点全红**
A：流水线会**拒绝发布**并保留上一次结果，这是预期行为，避免你的订阅被清空。

**Q：成功数很少**
A：VPN Gate 免费节点本身不稳定，且 Cloudflare 免费套餐的 CPU 配额可能不足以完成 SSTP 握手。可先用 `MAX_CHECK_NODES=10` 抽样确认，再考虑换自建检测机。

**Q：`data.json` 里的住宅/机房准不准**
A：主要依据 Worker 返回的出口 ASN 与 `is_datacenter` 标记（来自第三方 IP 库），仅供参考；标记为「未识别」的节点两者都不满足。

## 已知限制

- VPN Gate 官方 API 只提供约 100 个节点，TCP(SSTP) 约 80–90 个，覆盖量受源站限制。
- VPN Gate 没有 HTTPS 接口，只能走 `http://`，部分网络环境可能访问不了。
- 「`proto tcp` 即 SSTP」是基于 VPN Gate 行为推断的近似：官方 API 没有 SSTP 字段，TCP 端口即 SSTP 监听端口。
- 检测依赖第三方 Worker 与 IP 库，结果不代表节点长期稳定。

## 免责声明

本项目仅用于学习网络协议与自动化流水线，请遵守当地法律法规与 VPN Gate 的使用条款，不要用于任何违法用途。节点由第三方无偿提供，可用性与安全性不做任何保证。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=hezhanleiok/gate&type=Date)](https://star-history.com/#hezhanleiok/gate&Date)