#!/usr/bin/env python3
"""Convert a single vmess://, vless://, trojan://, or ss:// URI into an
xray-core outbound JSON block, printed to stdout."""
import base64
import json
import sys
import urllib.parse


def vmess_outbound(uri: str) -> dict:
    payload = uri[len("vmess://"):]
    payload += "=" * (-len(payload) % 4)
    d = json.loads(base64.b64decode(payload))
    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": d["add"],
                "port": int(d["port"]),
                "users": [{
                    "id": d["id"],
                    "alterId": int(d.get("aid", 0)),
                    "security": d.get("scy", "auto"),
                }],
            }]
        },
        "streamSettings": {
            "network": d.get("net", "tcp"),
            "security": d.get("tls", ""),
        },
    }


def vless_outbound(uri: str) -> dict:
    parsed = urllib.parse.urlparse(uri)
    q = urllib.parse.parse_qs(parsed.query)
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "users": [{
                    "id": parsed.username,
                    "encryption": q.get("encryption", ["none"])[0],
                }],
            }]
        },
        "streamSettings": {
            "network": q.get("type", ["tcp"])[0],
            "security": q.get("security", [""])[0],
        },
    }


def trojan_outbound(uri: str) -> dict:
    parsed = urllib.parse.urlparse(uri)
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "password": parsed.username,
            }]
        },
    }


def ss_outbound(uri: str) -> dict:
    # ss://base64(method:password)@host:port  (or fully base64'd — handle both)
    rest = uri[len("ss://"):]
    if "@" in rest:
        userinfo, hostport = rest.split("@", 1)
        userinfo += "=" * (-len(userinfo) % 4)
        method, password = base64.urlsafe_b64decode(userinfo).decode().split(":", 1)
        host, port = hostport.split("#")[0].split(":")
    else:
        rest = rest.split("#")[0]
        rest += "=" * (-len(rest) % 4)
        decoded = base64.urlsafe_b64decode(rest).decode()
        method_password, hostport = decoded.split("@")
        method, password = method_password.split(":", 1)
        host, port = hostport.split(":")
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host,
                "port": int(port),
                "method": method,
                "password": password,
            }]
        },
    }


def main():
    uri = sys.argv[1]
    if uri.startswith("vmess://"):
        out = vmess_outbound(uri)
    elif uri.startswith("vless://"):
        out = vless_outbound(uri)
    elif uri.startswith("trojan://"):
        out = trojan_outbound(uri)
    elif uri.startswith("ss://"):
        out = ss_outbound(uri)
    else:
        print(f"unsupported scheme: {uri}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
