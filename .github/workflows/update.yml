#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import ipaddress
import json
import socket
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

# Один проверяемый upstream и несколько его официальных зеркал.
# Это надежнее, чем смешивать случайные публичные сборники без проверки.
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main/BLACK_VLESS_RUS_mobile.txt",
    "https://codeberg.org/igareck/vpn-configs-for-russia/raw/branch/main/BLACK_VLESS_RUS_mobile.txt",
    "https://gitea.com/igareck/vpn-configs-for-russia/raw/branch/main/BLACK_VLESS_RUS_mobile.txt",
    "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
]

COUNTRY_ORDER = ("FI", "EE", "LV", "DE", "NL", "PL", "SE")
COUNTRY_NAMES = {
    "FI": "Finland", "EE": "Estonia", "LV": "Latvia",
    "DE": "Germany", "NL": "Netherlands", "PL": "Poland", "SE": "Sweden",
}
MOBILE_LIMIT = 12
FULL_LIMIT = 50
BACKUP_LIMIT = 30
UA = "buda1969/incy-sub updater"


def fetch(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def get_source() -> tuple[str, str]:
    errors = []
    for url in SOURCES:
        try:
            text = fetch(url)
            if "vless://" in text or len(text.strip()) > 100:
                return text, url
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError("Все зеркала upstream недоступны:\n" + "\n".join(errors))


def decode_lines(text: str) -> list[str]:
    raw = [x.strip() for x in text.splitlines() if x.strip()]
    direct = [x for x in raw if x.startswith("vless://")]
    if direct:
        return direct

    compact = "".join(raw)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = compact + "=" * (-len(compact) % 4)
            decoded = decoder(padded).decode("utf-8", errors="replace")
            found = [
                x.strip() for x in decoded.splitlines()
                if x.strip().startswith("vless://")
            ]
            if found:
                return found
        except Exception:
            pass
    return []


def endpoint(uri: str) -> tuple[str, int] | None:
    try:
        p = urllib.parse.urlsplit(uri)
        if p.scheme != "vless" or not p.hostname or not p.port:
            return None
        return p.hostname, p.port
    except Exception:
        return None


def resolve_ipv4(host: str) -> str | None:
    try:
        ip = ipaddress.ip_address(host)
        return str(ip) if ip.version == 4 else None
    except ValueError:
        pass
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
            return info[4][0]
    except OSError:
        return None
    return None


def tcp_probe(host: str, port: int, timeout: float = 2.5) -> float | None:
    import time
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.monotonic() - start) * 1000, 1)
    except OSError:
        return None


def geo_batch(ips: list[str]) -> dict[str, tuple[str | None, str | None]]:
    """Batch lookup. If unavailable, return unknowns without destroying old files."""
    result = {ip: (None, None) for ip in ips}
    if not ips:
        return result

    # ip-api accepts max 100 records per request.
    for start in range(0, len(ips), 100):
        chunk = ips[start:start + 100]
        payload = json.dumps([
            {"query": ip, "fields": "status,countryCode,city,query"} for ip in chunk
        ]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": UA},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            for row in data:
                ip = row.get("query")
                if ip in result and row.get("status") == "success":
                    result[ip] = (row.get("countryCode"), row.get("city"))
        except Exception as exc:
            print(f"WARNING: геолокация недоступна: {exc}")
    return result


def fingerprint(uri: str) -> tuple:
    p = urllib.parse.urlsplit(uri)
    q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    # Fragment/name intentionally excluded.
    return (p.username, p.hostname, p.port, tuple(sorted(q)))


def rename(uri: str, country: str, city: str | None, latency: float, idx: int) -> str:
    p = urllib.parse.urlsplit(uri)
    place = COUNTRY_NAMES.get(country, country)
    if city:
        place += f" {city}"
    label = f"{place} · {latency:.0f}ms · #{idx:02d}"
    return urllib.parse.urlunsplit(
        (p.scheme, p.netloc, p.path, p.query, urllib.parse.quote(label, safe=" ·#"))
    )


def write_atomic(path: str, configs: list[str]) -> None:
    if not configs:
        raise RuntimeError(f"Отказ обновления {path}: итоговый список пуст.")
    target = Path(path)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text("\n".join(configs) + "\n", encoding="utf-8")
    tmp.replace(target)


def main() -> None:
    text, source = get_source()
    print(f"Используется зеркало: {source}")

    configs = decode_lines(text)
    unique = {}
    for uri in configs:
        ep = endpoint(uri)
        if ep:
            unique.setdefault(fingerprint(uri), uri)
    configs = list(unique.values())
    if not configs:
        raise RuntimeError("В upstream не найдено корректных VLESS URI.")

    resolved = {}
    for uri in configs:
        host, port = endpoint(uri)  # type: ignore[misc]
        ip = resolve_ipv4(host)
        if ip:
            resolved[uri] = (host, port, ip)

    probe_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        future_map = {
            pool.submit(tcp_probe, host, port): uri
            for uri, (host, port, _ip) in resolved.items()
        }
        for future in concurrent.futures.as_completed(future_map):
            uri = future_map[future]
            latency = future.result()
            if latency is not None:
                probe_results[uri] = latency

    ips = sorted({resolved[uri][2] for uri in probe_results})
    geo = geo_batch(ips)

    selected = []
    fallback = []
    for uri, latency in probe_results.items():
        ip = resolved[uri][2]
        country, city = geo.get(ip, (None, None))
        row = (uri, country, city, latency)
        if country in COUNTRY_ORDER:
            selected.append(row)
        else:
            fallback.append(row)

    selected.sort(key=lambda x: (
        COUNTRY_ORDER.index(x[1]), x[3], x[2] or "", x[0]  # type: ignore[arg-type]
    ))
    fallback.sort(key=lambda x: (x[3], x[0]))

    # Не перезаписываем рабочие файлы пустым результатом при сбое геолокации.
    if len(selected) < 5:
        raise RuntimeError(
            f"Найдено только {len(selected)} европейских узлов. "
            "Старые subscription-файлы сохранены без изменений."
        )

    named = [
        rename(uri, country, city, latency, i)
        for i, (uri, country, city, latency) in enumerate(selected, 1)
    ]
    backup = [
        rename(uri, country or "Other", city, latency, i)
        for i, (uri, country, city, latency) in enumerate(fallback, 1)
    ]

    write_atomic("mobile.txt", named[:MOBILE_LIMIT])
    write_atomic("full.txt", named[:FULL_LIMIT])
    if backup:
        write_atomic("backup.txt", backup[:BACKUP_LIMIT])

    status = {
        "source": source,
        "upstream_vless": len(configs),
        "tcp_reachable": len(probe_results),
        "europe_selected": len(selected),
        "mobile": min(len(named), MOBILE_LIMIT),
        "full": min(len(named), FULL_LIMIT),
        "backup": min(len(backup), BACKUP_LIMIT),
    }
    Path("status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(status, ensure_ascii=False))


if __name__ == "__main__":
    main()
