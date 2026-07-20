#!/usr/bin/env python3
"""
Scrapes public Telegram channels' HTML preview pages (telegram.me/s/<channel>)
for V2Ray/V2Ray-family config URIs, dedupes them, tests basic TCP
reachability + latency, and writes a ranked subscription file.

Runs on GitHub Actions (or any host where telegram.me is NOT filtered).
No Telegram API/login required — this only touches the public web preview.
"""

import asyncio
import base64
import json
import re
import socket
import time
import urllib.request
from dataclasses import dataclass, field

CHANNELS = [
    # add your channel usernames here, no @ and no URL, just the slug
    "filembad",
    "FreakConfig"
]

URI_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://")
CONFIG_RE = re.compile(r"(?:%s)[^\s\"'<>]+" % "|".join(re.escape(s) for s in URI_SCHEMES))

MAX_LATENCY_MS = 4000        # drop anything slower than this
TCP_TIMEOUT_S = 5
MAX_CONCURRENT_TESTS = 50
TOP_N = 50                  # how many best configs to keep in the final subscription


@dataclass
class Candidate:
    uri: str
    host: str = ""
    port: int = 0
    latency_ms: float = field(default=float("inf"))


def fetch_channel_html(channel: str) -> str:
    url = f"https://telegram.me/s/{channel}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def extract_configs(html: str) -> list[str]:
    # Telegram HTML-escapes the messages; unescape common entities first
    html = html.replace("&amp;", "&").replace("&quot;", '"')
    return CONFIG_RE.findall(html)


def parse_host_port(uri: str) -> tuple[str, int] | None:
    try:
        if uri.startswith("vmess://"):
            payload = uri[len("vmess://"):]
            payload += "=" * (-len(payload) % 4)  # fix padding
            data = json.loads(base64.b64decode(payload))
            return data["add"], int(data["port"])
        else:
            # vless/trojan/ss share a URI-ish layout: scheme://[userinfo@]host:port?...
            rest = uri.split("://", 1)[1]
            hostport = rest.split("@")[-1].split("?")[0].split("#")[0]
            host, port = hostport.rsplit(":", 1)
            return host, int(port)
    except Exception:
        return None


def tcp_ping(host: str, port: int) -> float:
    """Returns latency in ms, or inf on failure."""
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT_S):
            pass
        return (time.perf_counter() - start) * 1000
    except Exception:
        return float("inf")


async def test_candidate(cand: Candidate, sem: asyncio.Semaphore, loop) -> None:
    async with sem:
        cand.latency_ms = await loop.run_in_executor(None, tcp_ping, cand.host, cand.port)


async def rank_candidates(candidates: list[Candidate]) -> list[Candidate]:
    sem = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
    loop = asyncio.get_event_loop()
    await asyncio.gather(*(test_candidate(c, sem, loop) for c in candidates))
    good = [c for c in candidates if c.latency_ms <= MAX_LATENCY_MS]
    good.sort(key=lambda c: c.latency_ms)
    return good


def main() -> None:
    all_uris: set[str] = set()
    for ch in CHANNELS:
        try:
            html = fetch_channel_html(ch)
        except Exception as e:
            print(f"[warn] failed to fetch channel {ch}: {e}")
            continue
        found = extract_configs(html)
        print(f"[info] {ch}: found {len(found)} config URIs")
        all_uris.update(found)

        candidates = []
        for uri in all_uris:
            hp = parse_host_port(uri)
            if hp:
                candidates.append(Candidate(uri=uri, host=hp[0], port=hp[1]))

        print(f"[info] {len(candidates)} candidates with parseable host:port, testing connectivity...")
        ranked = asyncio.run(rank_candidates(candidates))
        print(f"[info] {len(ranked)} reachable within {MAX_LATENCY_MS}ms")

        top = ranked[:TOP_N]

        # Plain list (one URI per line) - useful for the Arch client script
        with open(f"configs/{ch}-raw_list.txt", "w") as f:
            f.write("\n".join(c.uri for c in top))

        # Base64 blob subscription format, importable directly by v2rayNG / v2rayN / NekoBox etc.
        blob = "\n".join(c.uri for c in top).encode()
        with open(f"configs/{ch}.txt", "w") as f:
            f.write(base64.b64encode(blob).decode())

        # Small JSON with latency info, handy for the local client to pick "best"
        with open(f"configs/{ch}-ranked.json", "w") as f:
            json.dump(
                [{"uri": c.uri, "host": c.host, "port": c.port, "latency_ms": round(c.latency_ms, 1)} for c in top],
                f,
                indent=2,
            )

        print(f"[done] wrote {len(top)} configs to configs/")


if __name__ == "__main__":
    import os
    os.makedirs("configs", exist_ok=True)
    main()
