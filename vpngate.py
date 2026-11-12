#!/usr/bin/env python3
"""VPN Gate SSTP 节点检测流水线（模板仓库）。

流程:
  1. 抓取 VPN Gate 原始节点（官方 API，失败回退 GitHub 镜像）
  2. 只保留带 TCP 入口的 SSTP 节点（VPN Gate 的 TCP 端口即 SSTP 端口）
  3. 去重 → 按 Ping 预排序 →（可选）截断
  4. 并发调用检测 Worker
  5. 合并静态优选域名与优选 API 端点
  6. 生成 public/data.json + public/index.html + public/nodes.txt

配置全部来自环境变量。模板仓库约定：用户只需在仓库里配置 Secret `DOMAIN`，
工作流会拼出检测地址；本地运行时可以直接设置 CHECK_WORKER。
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import quote, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

SCHEMA_VERSION = 1

# VPN Gate 没有 HTTPS 接口，官方 API 只提供 HTTP。
DEFAULT_VPNGATE_API = "http://www.vpngate.net/api/iphone/"
DEFAULT_VPNGATE_MIRROR = (
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json"
)
DEFAULT_OPTIMAL_API = "https://cf.090227.xyz/cu&port=443"

# 占位符检测：命中任意一个就认为用户还没配置
PLACEHOLDER_MARKERS = ("你的", "YOUR_", "YOUR-", "example.com", "yourdomain")

# 静态优选域名池（可用 EDGE_HOSTS 整体覆盖）
DEFAULT_EDGE_HOSTS = [
    "saas.sin.fan:443",
    "www.mfyx.cn:443",
    "cf.nyanya.moe:443",
    "cf.877774.xyz:443",
    "cdn.204910.best:443",
    "cdn.ctn32.us.kg:443",
    "p.etime.vip:443",
    "cmcc.vvvv.ee:443",
    "cfsaas.080112.xyz:443",
    "cdn.aneko.ink:443",
    "hk.cf.3666888.xyz:443",
    "best.hzample.kdns.fr:443",
    "ctsg.cfyx.aliyun.20237737.xyz:443",
    "china-unicom.cname.cloudflare.468123.xyz:443",
]

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASEWEB",
]

RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6|tcp-client)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+(\S+)\s+(\d+)", re.M)


# ---------------------------------------------------------------------------
# 日志与错误
# ---------------------------------------------------------------------------
_section: str | None = None


def log(section: str, msg: str = "") -> None:
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


class ConfigError(Exception):
    """配置缺失或非法；main 会把它转成可读的失败信息。"""


def die(section: str, msg: str, code: int = 2) -> None:
    log(section, f"[失败] {msg}")
    raise SystemExit(code)


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} 需要是整数，当前值：{raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} 不能小于 {minimum}，当前值：{value}")
    return value


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} 需要是数字，当前值：{raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} 不能小于 {minimum}，当前值：{value}")
    return value


def normalize_worker_base(raw: str) -> str:
    """把 CHECK_WORKER / DOMAIN 归一化成以 `sstp=vpn:vpn@` 结尾的检测地址前缀。

    允许的写法：
      - https://abc.workers.dev/check?sstp=vpn:vpn@
      - abc.workers.dev                （自动补 https:// 与 /check?sstp=vpn:vpn@）
      - https://abc.workers.dev/check  （自动补查询串）
    """
    value = (raw or "").strip()
    if not value:
        raise ConfigError(
            "未配置检测 Worker 地址。请在仓库 Settings → Secrets and variables → Actions "
            "添加 Secret `DOMAIN`（只填 host，例如 abc.workers.dev），"
            "或本地运行时设置环境变量 CHECK_WORKER。"
        )
    lowered = value.lower()
    if any(marker.lower() in lowered for marker in PLACEHOLDER_MARKERS):
        raise ConfigError(
            "检测地址仍是占位符。请在仓库 Settings → Secrets and variables → Actions "
            "添加 Secret `DOMAIN`（只填 host，例如 abc.workers.dev），工作流会自动拼出检测地址。"
        )
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        value = "https://" + value
    parts = urlsplit(value)
    if not parts.netloc:
        raise ConfigError(f"无法解析检测 Worker 地址：{value!r}")

    path = parts.path.rstrip("/")
    if not path.endswith("/check"):
        path = path + "/check"

    query = parts.query
    if "sstp=" not in query:
        query = (query + "&" if query else "") + "sstp=vpn:vpn@"
    else:
        params = [item for item in query.split("&") if item]
        for i, item in enumerate(params):
            if item.startswith("sstp="):
                target = item[len("sstp="):]
                if "@" not in target:
                    params[i] = "sstp=" + (target or "vpn:vpn") + "@"
        query = "&".join(params)
    return f"{parts.scheme}://{parts.netloc}{path}?{query}"


def normalize_endpoint(raw: str) -> str | None:
    """把 `IP:端口` / 域名 / IPv6 归一化成可用的 `host:port` 或 `[v6]:port`。"""
    text = (raw or "").strip()
    if not text:
        return None
    text = text.split("#", 1)[0].strip().split("/", 1)[0].strip()
    if not text:
        return None

    host: str
    port: str
    if text.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?", text)
        if not match:
            return None
        host = match.group(1)
        port = match.group(2) or "443"
    else:
        colons = text.count(":")
        if colons == 0:
            host, port = text, "443"
        elif colons == 1:
            host, port = text.rsplit(":", 1)
        else:  # 裸 IPv6
            host, port = text, "443"
        if colons <= 1 and not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            return None

    try:
        port_number = int(port)
    except ValueError:
        return None
    if not 1 <= port_number <= 65535:
        return None
    if ":" in host:
        return f"[{host}]:{port_number}"
    return f"{host}:{port_number}"


def parse_edge_hosts(raw: str) -> list[str]:
    endpoints: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        endpoint = normalize_endpoint(item)
        if endpoint and endpoint not in seen:
            seen.add(endpoint)
            endpoints.append(endpoint)
    return endpoints


def derive_nodes_url() -> str:
    """从 GITHUB_REPOSITORY 推导 nodes.txt 地址；本地运行回退占位。"""
    explicit = os.environ.get("NODES_URL", "").strip()
    if explicit:
        return explicit
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if "/" in repo:
        owner, name = repo.split("/", 1)
        if owner and name:
            return f"https://{owner}.github.io/{name}/nodes.txt"
    return "https://<owner>.github.io/<repo>/nodes.txt"


@dataclass(frozen=True)
class Config:
    vpngate_api: str
    vpngate_mirror: str
    worker_base: str
    concurrency: int
    check_timeout: float
    deadline_s: float
    http_timeout: float
    max_check_nodes: int
    public_dir: str
    template_html: str
    edge_hosts: tuple[str, ...]
    optimal_api: str
    nodes_url: str
    min_success_ratio: float
    max_residential_per_country: int
    max_datacenter_per_country: int

    @classmethod
    def load(cls) -> "Config":
        raw_worker = os.environ.get("CHECK_WORKER", "").strip()
        if not raw_worker:
            domain = os.environ.get("DOMAIN", "").strip()
            if domain:
                raw_worker = f"https://{domain}/check?sstp=vpn:vpn@"
        worker_base = normalize_worker_base(raw_worker)

        static_raw = os.environ.get("HOSTS_ENTRY", "").strip()
        if not static_raw:
            static_raw = os.environ.get("EDGE_HOSTS", "").strip()
        edge_hosts = parse_edge_hosts(static_raw) if static_raw else []
        if not edge_hosts:
            edge_hosts = [h for h in (normalize_endpoint(x) for x in DEFAULT_EDGE_HOSTS) if h]

        return cls(
            vpngate_api=os.environ.get("VPNGATE_API", DEFAULT_VPNGATE_API),
            vpngate_mirror=os.environ.get("VPNGATE_MIRROR", DEFAULT_VPNGATE_MIRROR),
            worker_base=worker_base,
            concurrency=_env_int("CHECK_CONCURRENCY", 32, minimum=1),
            check_timeout=_env_float("CHECK_TIMEOUT", 25.0, minimum=1.0),
            deadline_s=_env_float("CHECK_DEADLINE", 1200.0, minimum=30.0),
            http_timeout=_env_float("HTTP_TIMEOUT", 60.0, minimum=5.0),
            max_check_nodes=_env_int("MAX_CHECK_NODES", 0),
            public_dir=os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public")),
            template_html=os.path.join(REPO_DIR, "web", "index.html"),
            edge_hosts=tuple(edge_hosts),
            optimal_api=os.environ.get("OPTIMAL_API", DEFAULT_OPTIMAL_API),
            nodes_url=derive_nodes_url(),
            min_success_ratio=_env_float("MIN_SUCCESS_RATIO", 0.0, minimum=0.0),
            max_residential_per_country=_env_int("MAX_RESIDENTIAL_PER_COUNTRY", 20),
            max_datacenter_per_country=_env_int("MAX_DATACENTER_PER_COUNTRY", 10),
        )


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def make_session(pool_size: int = 32, retries: int = 2) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=retry,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
    return session


# ---------------------------------------------------------------------------
# 数据抓取与解析
# ---------------------------------------------------------------------------
def fetch_vpngate(cfg: Config, session: requests.Session) -> tuple[list[dict[str, Any]], str]:
    try:
        log("VPN GATE", f"获取官方 API: {cfg.vpngate_api}")
        resp = session.get(cfg.vpngate_api, timeout=cfg.http_timeout)
        resp.raise_for_status()
        rows = parse_csv(resp.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:  # noqa: BLE001 - 需要降级到镜像
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {cfg.vpngate_mirror}")
        resp = session.get(cfg.vpngate_mirror, timeout=cfg.http_timeout)
        resp.raise_for_status()
        rows = parse_mirror_json(resp.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:  # noqa: BLE001
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN GATE", "官方 API 与回退镜像均不可用，数据源完全失败")


def parse_csv(text: str) -> list[dict[str, Any]]:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, line in enumerate(lines):
        if line.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = [h.strip().lstrip("*").lower() for h in lines[header_idx].lstrip("#").split(",")]
    column = {name: idx for idx, name in enumerate(header) if name}

    def pick(*names: str, default: int | None = None) -> int | None:
        for name in names:
            if name in column:
                return column[name]
        return default

    idx_host = pick("hostname", default=0)
    idx_ip = pick("ip", default=1)
    idx_long = pick("countrylong", default=5)
    idx_short = pick("countryshort", default=6)
    idx_ping = pick("ping")
    idx_score = pick("score")
    idx_config = pick("openvpn_configdata_base64")
    if idx_config is None:
        idx_config = next(
            (i for i, name in enumerate(header) if "base64" in name),
            len(header) - 1,
        )

    rows: list[dict[str, Any]] = []
    for line in lines[header_idx + 1:]:
        if line.startswith(("*", "#")):
            continue
        try:
            fields = next(csv.reader(io.StringIO(line)))
        except Exception:  # noqa: BLE001 - 坏行直接跳过
            continue
        if len(fields) <= max(idx_host or 0, idx_ip or 0):
            continue

        def cell(index: int | None) -> str:
            if index is None or index >= len(fields):
                return ""
            return fields[index].strip()

        host = cell(idx_host)
        ip = cell(idx_ip)
        if not host or not ip:
            continue

        def to_int(index: int | None) -> int | None:
            raw = cell(index)
            return int(raw) if raw.isdigit() else None

        rows.append(
            {
                "host": host,
                "ip": ip,
                "country_long": cell(idx_long),
                "country_short": cell(idx_short),
                "config_b64": cell(idx_config),
                "ping": to_int(idx_ping),
                "score": to_int(idx_score),
            }
        )
    return rows


def parse_mirror_json(data: Any) -> list[dict[str, Any]]:
    servers: list[dict[str, Any]] = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict) and item.get("hostname"):
            servers.append(item)

    rows: list[dict[str, Any]] = []
    for server in servers:
        if not isinstance(server, dict):
            continue
        host = str(server.get("hostname") or server.get("host") or "").strip()
        ip = str(server.get("ip") or "").strip()
        if not host or not ip:
            continue

        def as_int(key: str) -> int | None:
            try:
                return int(str(server.get(key) or "").strip())
            except (TypeError, ValueError):
                return None

        rows.append(
            {
                "host": host,
                "ip": ip,
                "country_long": str(
                    server.get("countrylong") or server.get("country_long") or server.get("country") or ""
                ).strip(),
                "country_short": str(
                    server.get("countryshort") or server.get("country_short") or ""
                ).strip(),
                "config_b64": str(
                    server.get("openvpn_configdata_base64") or server.get("config_b64") or ""
                ).strip(),
                "ping": as_int("ping"),
                "score": as_int("score"),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
@dataclass
class Node:
    host: str
    port: int
    ip: str
    country: str
    country_code: str
    ping: int | None = None
    score: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "ping": self.ping,
            "score": self.score,
        }


def to_sstp_nodes(rows: Iterable[dict[str, Any]]) -> list[Node]:
    nodes: list[Node] = []
    for row in rows:
        config_b64 = row.get("config_b64") or ""
        if not config_b64:
            continue
        try:
            config = base64.b64decode(config_b64, validate=False).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        if not _PROTO_TCP_RE.search(config):
            continue
        match = _REMOTE_RE.search(config)
        if not match:
            continue
        port = int(match.group(2))
        if not 1 <= port <= 65535:
            continue

        host = (row.get("host") or "").strip().lower()
        if not host:
            continue
        # VPN Gate 主机名有时是 public-vpn-153，有时已是完整域名
        if "." not in host:
            host = f"{host}.opengw.net"

        nodes.append(
            Node(
                host=host,
                port=port,
                ip=(row.get("ip") or "").strip(),
                country=(row.get("country_long") or "").strip(),
                country_code=(row.get("country_short") or "").strip().upper(),
                ping=row.get("ping"),
                score=row.get("score"),
            )
        )
    return nodes


def dedupe_nodes(nodes: Iterable[Node]) -> list[Node]:
    seen: set[tuple[str, int]] = set()
    unique: list[Node] = []
    for node in nodes:
        key = (node.host, node.port)
        if key in seen:
            continue
        seen.add(key)
        unique.append(node)
    return unique


def prioritize(nodes: list[Node]) -> list[Node]:
    """按 Ping 升序、Score 降序预排序，让抽样先测质量更好的节点。"""
    return sorted(
        nodes,
        key=lambda n: (n.ping is None, n.ping or 0, -(n.score or 0), n.host),
    )


# ---------------------------------------------------------------------------
# 分类（以 Worker 的出口信息为准，缺失时才看 Operator 关键字）
# ---------------------------------------------------------------------------
def classify_network(org: str | None, is_datacenter: bool | None) -> str:
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    upper = (org or "").upper()
    if upper:
        if any(keyword in upper for keyword in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(keyword in upper for keyword in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    return "unknown"


# ---------------------------------------------------------------------------
# 检测
# ---------------------------------------------------------------------------
def check_one(
    node: Node,
    session: requests.Session,
    worker_base: str,
    timeout: float,
) -> dict[str, Any]:
    result: dict[str, Any] = node.to_dict()
    result.update(
        {
            "protocol": "sstp",
            "link": f"sstp://vpn:vpn@{node.host}:{node.port}",
            "status": "failed",
            "success": False,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "exit": None,
            "latency_ms": None,
            "colo": None,
            "error": None,
            "worker_error": False,
            "residential": "unknown",
        }
    )
    url = worker_base + quote(f"{node.host}:{node.port}", safe="")
    try:
        response = session.get(url, timeout=timeout)
        if response.status_code != 200:
            result["error"] = f"HTTP {response.status_code}"
            result["worker_error"] = True
            return result

        payload = response.json()
        success = bool(payload.get("success"))
        result["success"] = success
        result["status"] = "success" if success else "failed"
        result["latency_ms"] = payload.get("responseTime")
        result["colo"] = payload.get("colo")
        result["error"] = None if success else (
            payload.get("error") or payload.get("message") or "check failed"
        )

        exit_info = payload.get("exit") or {}
        if success and exit_info:
            asn = exit_info.get("asn") or {}
            org = str(asn.get("org") or asn.get("name") or "")
            result["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            result["residential"] = classify_network(org, exit_info.get("is_datacenter"))
        elif success:
            result["residential"] = "unknown"
        return result
    except Exception as exc:  # noqa: BLE001 - 单节点失败不影响整体
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["worker_error"] = True
        return result


def check_all(
    nodes: list[Node],
    session: requests.Session,
    cfg: Config,
) -> tuple[list[dict[str, Any]], int]:
    """并发检测；返回 (结果列表, 因整体超时未完成的数量)。"""
    results: list[dict[str, Any]] = []
    deadline = time.monotonic() + cfg.deadline_s
    with ThreadPoolExecutor(max_workers=cfg.concurrency) as pool:
        futures = {
            pool.submit(check_one, node, session, cfg.worker_base, cfg.check_timeout): node
            for node in nodes
        }
        pending = set(futures)
        try:
            for future in as_completed(pending, timeout=max(0.1, deadline - time.monotonic())):
                pending.discard(future)
                results.append(future.result())
        except TimeoutError:
            log("CLOUDFLARE WORKER", f"整体检测超时（{cfg.deadline_s:.0f}s），未完成的节点按失败处理")

    timed_out = 0
    for future in pending:
        node = futures[future]
        if future.done() and not future.cancelled():
            # 截止瞬间刚好完成的请求，结果依然有效，不要丢掉
            try:
                results.append(future.result())
                continue
            except Exception:  # noqa: BLE001
                pass
        future.cancel()
        stub = node.to_dict()
        stub.update(
            {
                "protocol": "sstp",
                "link": f"sstp://vpn:vpn@{node.host}:{node.port}",
                "status": "failed",
                "success": False,
                "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                "exit": None,
                "latency_ms": None,
                "colo": None,
                "error": "整体检测超时，未完成",
                "worker_error": False,
                "residential": "unknown",
            }
        )
        results.append(stub)
        timed_out += 1
    return results, timed_out


# ---------------------------------------------------------------------------
# 优选入口
# ---------------------------------------------------------------------------
def fetch_optimal_endpoints(cfg: Config, session: requests.Session) -> list[str]:
    raw = (cfg.optimal_api or "").strip()
    if not raw:
        return []
    endpoints: list[str] = []
    seen: set[str] = set()
    for url in (u.strip() for u in raw.split(",") if u.strip()):
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            response = session.get(url, timeout=min(cfg.http_timeout, 15))
            if response.status_code != 200:
                log("OPTIMAL API", f"API 返回状态码异常: {response.status_code}")
                continue
            count = 0
            for line in response.text.splitlines():
                endpoint = normalize_endpoint(line)
                if endpoint and endpoint not in seen:
                    seen.add(endpoint)
                    endpoints.append(endpoint)
                    count += 1
            log("OPTIMAL API", f"成功从 API 获取到 {count} 个优选端点")
        except Exception as exc:  # noqa: BLE001
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {exc}")
    return endpoints


def get_combined_edge_hosts(cfg: Config, session: requests.Session) -> list[str]:
    api_endpoints = fetch_optimal_endpoints(cfg, session)
    combined: list[str] = []
    seen: set[str] = set()
    for endpoint in list(cfg.edge_hosts) + api_endpoints:
        if endpoint and endpoint not in seen:
            seen.add(endpoint)
            combined.append(endpoint)
    if not combined:  # 双保险：静态池在 Config 里已兜底，这里再兜一次
        combined = [h for h in (normalize_endpoint(x) for x in DEFAULT_EDGE_HOSTS) if h]
    log(
        "EDGE POOL",
        f"入口地址池: 静态/配置 {len(cfg.edge_hosts)} 个, API {len(api_endpoints)} 个, 合并 {len(combined)} 个",
    )
    return combined


# ---------------------------------------------------------------------------
# 产物
# ---------------------------------------------------------------------------
def sanitize_remark(text: str) -> str:
    """备注会出现在 nodes.txt 的 `入口#备注$链接` 里，去掉分隔符与换行。"""
    return re.sub(r"[#$\r\n]", "", text).strip() or "节点"


def build_outputs(
    results: list[dict[str, Any]],
    raw_count: int,
    sstp_count: int,
    source: str,
    worker_host: str,
    duration_s: float,
    timed_out: int,
) -> dict[str, Any]:
    available = [r for r in results if r.get("success")]
    countries: dict[str, dict[str, Any]] = {}
    for node in available:
        code = (node.get("country_code") or "").upper() or "??"
        name = node.get("country") or COUNTRY_ZH.get(code) or code
        group = countries.setdefault(
            code, {"code": code, "name": name, "count": 0, "residential": 0, "datacenter": 0, "unknown": 0, "nodes": []}
        )
        if group["name"] == code and name:
            group["name"] = name
        group["nodes"].append(node)

    for group in countries.values():
        group["count"] = len(group["nodes"])
        group["residential"] = sum(1 for n in group["nodes"] if n.get("residential") == "residential")
        group["datacenter"] = sum(1 for n in group["nodes"] if n.get("residential") == "datacenter")
        group["unknown"] = group["count"] - group["residential"] - group["datacenter"]
        group["nodes"].sort(
            key=lambda n: (n.get("residential") != "residential", n.get("latency_ms") is None, n.get("latency_ms") or 0)
        )

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "worker_errors": sum(1 for r in results if r.get("worker_error")),
        "timed_out": timed_out,
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n.get("residential") == "residential"),
        "datacenter_est": sum(1 for n in available if n.get("residential") == "datacenter"),
        "unknown_est": sum(1 for n in available if n.get("residential") == "unknown"),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker_host": worker_host,
        "duration_s": round(duration_s, 1),
        "stats": stats,
        "countries": countries,
    }


def build_nodes_text(data: dict[str, Any], edge_hosts: list[str], cfg: Config) -> str:
    if not edge_hosts:
        raise ConfigError("优选入口池为空，无法生成 nodes.txt")
    lines: list[str] = []
    seen_links: set[str] = set()
    index = 0
    ordered = sorted(
        data["countries"].items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for code, group in ordered:
        name = COUNTRY_ZH.get(code) or group.get("name") or code
        nodes = sorted(
            group["nodes"],
            key=lambda n: (n.get("residential") != "residential", n.get("latency_ms") is None, n.get("latency_ms") or 0),
        )
        residential = [n for n in nodes if n.get("residential") == "residential"]
        others = [n for n in nodes if n.get("residential") != "residential"]
        chosen = residential[: cfg.max_residential_per_country] + others[: cfg.max_datacenter_per_country]
        counters = {"residential": 0, "datacenter": 0, "unknown": 0}
        for node in chosen:
            link = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
            if link in seen_links:
                continue
            seen_links.add(link)
            kind_key = node.get("residential") if node.get("residential") in counters else "unknown"
            counters[kind_key] += 1
            kind = {"residential": "住宅", "datacenter": "机房", "unknown": "未知"}[kind_key]
            entry = edge_hosts[index % len(edge_hosts)]
            index += 1
            lines.append(f"{entry}#{sanitize_remark(f'{name}-{kind}-{counters[kind_key]:02d}')}${link}")
    return "\n".join(lines) + ("\n" if lines else "")


def atomic_write_text(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temp_path = f"{path}.tmp-{os.getpid()}"
    with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    os.replace(temp_path, path)


def write_outputs(
    data: dict[str, Any], cfg: Config, edge_hosts: list[str]
) -> tuple[str, str, str, str]:
    os.makedirs(cfg.public_dir, exist_ok=True)
    data_path = os.path.join(cfg.public_dir, "data.json")
    html_path = os.path.join(cfg.public_dir, "index.html")
    nodes_path = os.path.join(cfg.public_dir, "nodes.txt")

    atomic_write_text(data_path, json.dumps(data, ensure_ascii=False, separators=(",", ":")))

    if os.path.exists(cfg.template_html):
        with open(cfg.template_html, "r", encoding="utf-8") as handle:
            html = handle.read()
    else:
        html = (
            "<!doctype html><html><head><meta charset='utf-8'><title>VPN Gate SSTP</title></head>"
            "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'>加载中…</pre></body>"
            "<script>fetch('data.json').then(r=>r.json())"
            ".then(d=>out.textContent=JSON.stringify(d.stats,null,2))"
            ".catch(e=>out.textContent='加载失败: '+e)</script></html>"
        )
    atomic_write_text(html_path, html)
    nodes_text = build_nodes_text(data, edge_hosts, cfg)
    atomic_write_text(nodes_path, nodes_text)
    return data_path, html_path, nodes_path, nodes_text


def write_step_summary(data: dict[str, Any], nodes_count: int, cfg: Config) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if not summary_path:
        return
    stats = data["stats"]
    rows = [
        "| 指标 | 数值 |\n| :--- | ---: |\n",
        f"| 原始节点 | {stats['raw_nodes']} |\n",
        f"| SSTP 候选 | {stats['sstp_nodes']} |\n",
        f"| 已检测 | {stats['checked']} |\n",
        f"| 可用 | {stats['success']} |\n",
        f"| 失败 | {stats['failed']}（Worker 异常 {stats['worker_errors']}）|\n",
        f"| 国家/地区 | {stats['countries']} |\n",
        f"| 住宅 / 机房 / 未知 | {stats['residential_est']} / {stats['datacenter_est']} / {stats['unknown_est']} |\n",
        f"| 发布节点行数 | {nodes_count} |\n",
        f"| 用时 | {data['duration_s']}s |\n",
        f"| 数据源 | {data['source']} |\n",
    ]
    top = sorted(data["countries"].values(), key=lambda g: -g["count"])[:5]
    if top:
        rows.append("\n**节点最多的 5 个国家/地区**\n\n| 国家/地区 | 数量 | 住宅 |\n| :--- | ---: | ---: |\n")
        for group in top:
            rows.append(f"| {group['name']}（{group['code']}）| {group['count']} | {group['residential']} |\n")
    rows.append(f"\n订阅地址：`{cfg.nodes_url}`\n")
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("".join(rows))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    started = time.time()
    try:
        cfg = Config.load()
    except ConfigError as exc:
        die("配置", str(exc))

    session = make_session(pool_size=cfg.concurrency)
    log("CONFIG", f"检测地址: {cfg.worker_base.rsplit('?', 1)[0]}?sstp=***")
    log("CONFIG", f"并发 {cfg.concurrency}, 单节点超时 {cfg.check_timeout}s, 整体截止 {cfg.deadline_s}s")

    rows, source = fetch_vpngate(cfg, session)
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN GATE", "VPN Gate 返回 0 个原始节点，拒绝生成空结果")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die("VPN GATE", f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点")

    unique_nodes = prioritize(dedupe_nodes(sstp_nodes))
    if cfg.max_check_nodes > 0:
        unique_nodes = unique_nodes[: cfg.max_check_nodes]

    log("VPN GATE", f"原始节点 {raw_count}, SSTP {sstp_count}, 去重后 {len(unique_nodes)}")
    log("CLOUDFLARE WORKER", f"提交检测: {len(unique_nodes)}")

    check_started = time.time()
    results, timed_out = check_all(unique_nodes, session, cfg)
    elapsed = time.time() - check_started

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"成功 {len(success)}, 失败 {len(failed)}（Worker 异常 {len(worker_errors)}）, 用时 {elapsed:.1f}s")

    if unique_nodes and not success and len(worker_errors) == len(unique_nodes):
        die("CLOUDFLARE WORKER", "检测 Worker 全部请求异常，本次不发布（保留上一次产物）")

    if unique_nodes and not success:
        die("RESULT", "所有节点检测失败，本次不发布（保留上一次产物）")

    ratio = len(success) / len(unique_nodes) if unique_nodes else 0.0
    if cfg.min_success_ratio > 0 and ratio < cfg.min_success_ratio:
        die(
            "RESULT",
            f"成功率 {ratio:.1%} 低于阈值 {cfg.min_success_ratio:.1%}，"
            "本次不发布（保留上一次产物）；确认无误可调低 MIN_SUCCESS_RATIO",
        )

    worker_host = urlsplit(cfg.worker_base).netloc or "unknown"
    data = build_outputs(
        results=results,
        raw_count=raw_count,
        sstp_count=sstp_count,
        source=source,
        worker_host=worker_host,
        duration_s=time.time() - started,
        timed_out=timed_out,
    )

    edge_hosts = get_combined_edge_hosts(cfg, session)
    data_path, html_path, nodes_path, nodes_text = write_outputs(data, cfg, edge_hosts)
    nodes_count = len([line for line in nodes_text.splitlines() if line.strip()])
    log("RESULT", f"可用节点 {data['stats']['success']}, 国家/地区 {data['stats']['countries']}, nodes.txt {nodes_count} 行")
    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"把 {cfg.nodes_url} 填入 edgetunnel 后台「自定义优选 IP」")
    write_step_summary(data, nodes_count, cfg)
    log("WEBSITE", "完成（GitHub Pages 部署由 workflow 执行）")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        die("INTERRUPT", "已被中断")
    except Exception as exc:  # noqa: BLE001
        die("FATAL", f"程序异常: {type(exc).__name__}: {exc}")
