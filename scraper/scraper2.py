#!/usr/bin/env python3
"""
telegram_v2ray_aggregator.py

Fetches the N latest V2Ray/Xray-style proxy configs from a list of public
Telegram channels (via the public t.me/s/<channel> preview pages — no bot
token or login needed), classifies each config by TLS/security mode and
transport type, writes them to per-category raw files, and builds a
subscription (base64) file per category plus one combined "all" subscription.

Usage:
    python3 telegram_v2ray_aggregator.py --channels channel1,channel2 -n 50
    python3 telegram_v2ray_aggregator.py --channels-file channels.txt -n 100 -o output

Output layout:
    output/
      raw/
        vless_tls_ws.txt
        vmess_none_tcp.txt
        ...
      subs/
        vless_tls_ws_sub.txt     (base64 subscription, one category)
        ...
        all_sub.txt              (base64 subscription, everything combined)
      summary.json
"""

import argparse
import base64
import json
import re
import sys
import time
import urllib.error
import urllib.request
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependency. Install with: pip install beautifulsoup4 --break-system-packages",
          file=sys.stderr)
    sys.exit(1)

CONFIG_URI_RE = re.compile(
    r'(?:vmess|vless|trojan|ss|ssr|hysteria2|hy2|tuic)://[^\s<>"\'\\]+',
    re.IGNORECASE,
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------

def fetch_page(channel: str, before: int | None = None, timeout: int = 15) -> str:
    url = f"https://t.me/s/{channel}"
    if before is not None:
        url += f"?before={before}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_messages(html: str) -> list[tuple[int, str]]:
    """Returns list of (message_id, text) in the order they appear on the
    page (oldest -> newest), same as Telegram's preview layout."""
    soup = BeautifulSoup(html, "html.parser")
    messages = []
    for wrap in soup.select("div.tgme_widget_message"):
        data_post = wrap.get("data-post", "")
        try:
            msg_id = int(data_post.split("/")[-1])
        except (ValueError, IndexError):
            continue
        text_div = wrap.select_one("div.tgme_widget_message_text")
        code_blocks = wrap.select("code")
        pieces = []
        if text_div is not None:
            pieces.append(unescape(text_div.get_text(separator="\n")))
        for cb in code_blocks:
            pieces.append(unescape(cb.get_text()))
        messages.append((msg_id, "\n".join(pieces)))
    return messages


def fetch_latest_configs(channel: str, n: int, delay: float, max_pages: int = 40) -> list[str]:
    """Walks backward through a channel's public preview pages until it has
    collected n configs (or runs out of pages), returning newest-first."""
    collected: list[str] = []
    seen = set()
    before = None
    pages_fetched = 0

    while pages_fetched < max_pages and len(collected) < n:
        try:
            html = fetch_page(channel, before=before)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            print(f"  [!] {channel}: failed to fetch page ({exc}) — stopping", file=sys.stderr)
            break

        pages_fetched += 1
        messages = parse_messages(html)
        if not messages:
            break

        # newest message on this page first, so we can stop early once we have enough
        for msg_id, text in reversed(messages):
            for match in CONFIG_URI_RE.finditer(text):
                uri = match.group(0).rstrip(").,;")
                if uri not in seen:
                    seen.add(uri)
                    collected.append(uri)
            if len(collected) >= n:
                break

        # prepare to page further back (t.me paginates with ?before=<oldest id on page>)
        oldest_id = messages[0][0]
        if before is not None and oldest_id >= before:
            break  # no progress, avoid infinite loop
        before = oldest_id

        time.sleep(delay)

    return collected[:n]


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

def _b64_json(payload: str) -> dict:
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.b64decode(padded))


def classify(uri: str) -> tuple[str, str, str]:
    """Returns (scheme, security, transport)."""
    scheme = uri.split("://", 1)[0].lower()
    security = "unknown"
    transport = "unknown"

    try:
        if scheme == "vmess":
            data = _b64_json(uri[len("vmess://"):])
            net = str(data.get("net", "tcp")).lower() or "tcp"
            tls_field = str(data.get("tls", "")).lower()
            security = "tls" if tls_field in ("tls", "reality") else "none"
            transport = net

        elif scheme in ("vless", "trojan"):
            parsed = urlparse(uri)
            qs = parse_qs(parsed.query)
            security = qs.get("security", ["none"])[0].lower() or "none"
            transport = qs.get("type", ["tcp"])[0].lower() or "tcp"

        elif scheme in ("hysteria2", "hy2", "tuic"):
            # QUIC-based protocols are always TLS + udp/quic
            security = "tls"
            transport = "quic"

        elif scheme in ("ss", "ssr"):
            parsed = urlparse(uri)
            qs = parse_qs(parsed.query)
            plugin = qs.get("plugin", [""])[0].lower()
            security = "tls" if "tls" in plugin else "none"
            transport = "ws" if ("ws" in plugin or "websocket" in plugin) else "tcp"

    except Exception:
        pass  # leave as unknown/unknown — still gets saved, just uncategorized

    security = re.sub(r"[^a-z0-9]+", "", security) or "unknown"
    transport = re.sub(r"[^a-z0-9]+", "", transport) or "unknown"
    return scheme, security, transport


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def build_subscription(uris: list[str]) -> str:
    return base64.b64encode("\n".join(uris).encode("utf-8")).decode("ascii")


def write_outputs(categorized: dict[str, list[str]], output_dir: Path) -> dict:
    raw_dir = output_dir / "raw"
    subs_dir = output_dir / "subs"
    raw_dir.mkdir(parents=True, exist_ok=True)
    subs_dir.mkdir(parents=True, exist_ok=True)

    summary = {"categories": {}, "total_configs": 0}
    all_uris: list[str] = []

    for category, uris in sorted(categorized.items()):
        (raw_dir / f"{category}.txt").write_text("\n".join(uris) + "\n", encoding="utf-8")
        (subs_dir / f"{category}_sub.txt").write_text(build_subscription(uris), encoding="utf-8")
        summary["categories"][category] = len(uris)
        summary["total_configs"] += len(uris)
        all_uris.extend(uris)

    (subs_dir / "all_sub.txt").write_text(build_subscription(all_uris), encoding="utf-8")
    (raw_dir / "all.txt").write_text("\n".join(all_uris) + "\n", encoding="utf-8")

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def load_channels(args) -> list[str]:
    channels: list[str] = []
    if args.channels:
        channels.extend(c.strip().lstrip("@") for c in args.channels.split(",") if c.strip())
    if args.channels_file:
        path = Path(args.channels_file)
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().lstrip("@")
            if line and not line.startswith("#"):
                channels.append(line)
    # de-dupe, preserve order
    seen = set()
    result = []
    for c in channels:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--channels", help="Comma-separated list of Telegram channel usernames/IDs (no @ needed)")
    parser.add_argument("--channels-file", help="Path to a text file with one channel username/ID per line")
    parser.add_argument("-n", "--count", type=int, default=50, help="Number of latest configs to fetch per channel (default: 50)")
    parser.add_argument("-o", "--output-dir", default="output", help="Output directory (default: ./output)")
    parser.add_argument("--delay", type=float, default=1.5, help="Delay in seconds between page requests, per channel (default: 1.5)")
    args = parser.parse_args()

    channels = load_channels(args)
    if not channels:
        parser.error("Provide channels via --channels and/or --channels-file")

    categorized: dict[str, list[str]] = {}
    per_channel_counts = {}

    for channel in channels:
        print(f"[*] Fetching latest {args.count} configs from '{channel}' ...")
        uris = fetch_latest_configs(channel, args.count, args.delay)
        per_channel_counts[channel] = len(uris)
        print(f"    -> found {len(uris)} config(s)")

        for uri in uris:
            scheme, security, transport = classify(uri)
            category = f"{scheme}_{security}_{transport}"
            categorized.setdefault(category, []).append(uri)

    output_dir = Path(args.output_dir)
    summary = write_outputs(categorized, output_dir)
    summary["per_channel"] = per_channel_counts
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n=== Summary ===")
    for channel, count in per_channel_counts.items():
        print(f"  {channel}: {count} configs")
    print(f"\n  Total unique configs: {summary['total_configs']}")
    for category, count in sorted(summary["categories"].items()):
        print(f"    {category}: {count}")
    print(f"\nWrote raw configs to:   {output_dir / 'raw'}")
    print(f"Wrote subscriptions to: {output_dir / 'subs'}")
    print(f"  (per-category: <category>_sub.txt, combined: all_sub.txt)")


if __name__ == "__main__":
    main()
