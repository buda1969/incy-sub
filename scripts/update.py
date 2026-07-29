#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import datetime as dt
import ipaddress
import json
import socket
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from pathlib import Path

SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main/BLACK_VLESS_RUS_mobile.txt",
    "https://codeberg.org/igareck/vpn-configs-for-russia/raw/branch/main/BLACK_VLESS_RUS_mobile.txt",
    "https://gitea.com/igareck/vpn-configs-for-russia/raw/branch/main/BLACK_VLESS_RUS_mobile.txt",
]

COUNTRY_ORDER = ("FI", "EE", "LV", "DE", "NL", "PL", "SE")
COUNTRY_NAMES = {
    "FI": "Finland",
    "EE": "Estonia",
    "LV": "Latvia",
    "DE": "Germany",
    "NL": "Netherlands",
    "PL": "Poland",
    "SE": "Sweden",
}
MOBILE_LIMIT = 12
FULL_LIMIT = 50
BACKUP_LIMIT = 30
MIN_EUROPE_NODES = 5
UA = "buda1969/incy-sub updater-v3"


def fetch(url: str, timeout: int = 30) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def get_source() -> tuple[str, str]:
    errors: list[str] = []
    for url in SOURCES:
        try:
            text = fetch(url)
            if "vless://" in text or len(text.strip()) > 100:
                return text, url
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError("Все зеркала источника недоступны:\n" + "\n".join(errors))


def decode_lines(text: str) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    direct = [line for line in lines if line.startswith("vless://")]
    if direct:
        return direct

    compact = "".join(lines)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = compact + "=" * (-len(compact) % 4)
            decoded = decoder(padded).decode("utf-8", errors="replace")
            configs = [
                line.strip()
                for line in decoded.splitlines()
                if line.strip().startswith("vless://")
            ]
            if configs:
                return configs
        except Exception:
            continue
    return []


def endpoint(uri: str) -> tuple[str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme != "vless" or not parsed.hostname or not parsed.port:
            return None
        return parsed.hostname, parsed.port
    except Exception:
        return None


def resolve_ipv4(host: str) -> str | None:
    try:
        ip = ipaddress.ip_address(host)
        return str(ip) if ip.version == 4 else None
    except ValueError:
        pass

    try:
        result = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return result[0][4][0] if result else None
    except OSError:
        return None


def tcp_probe(host: str, port: int, timeout: float = 2.5) -> float | None:
    # Это задержка от GitHub Actions до сервера, а не пинг пользователя.
    import time
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.monotonic() - started) * 1000, 1)
    except OSError:
        return None


def geo_batch(ips: list[str]) -> dict[str, tuple[str | None, str | None]]:
    result = {ip: (None, None) for ip in ips}
    for start in range(0, len(ips), 100):
        chunk = ips[start:start + 100]
        payload = json.dumps([
            {"query": ip, "fields": "status,countryCode,city,query"}
            for ip in chunk
        ]).encode("utf-8")
        request = urllib.request.Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": UA},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))
            for row in data:
                ip = row.get("query")
                if ip in result and row.get("status") == "success":
                    result[ip] = (row.get("countryCode"), row.get("city"))
        except Exception as exc:
            print(f"WARNING: геолокация недоступна: {exc}")
    return result


def fingerprint(uri: str) -> tuple:
    parsed = urllib.parse.urlsplit(uri)
    query = tuple(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    return parsed.username, parsed.hostname, parsed.port, query


def rename(uri: str, country: str, city: str | None, index: int) -> str:
    parsed = urllib.parse.urlsplit(uri)
    place = COUNTRY_NAMES.get(country, country)
    if city:
        place += f" {city}"
    label = f"{place} #{index:02d}"
    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.query,
            urllib.parse.quote(label, safe=" #"),
        )
    )


def balanced_order(
    rows: list[tuple[str, str, str | None, float]]
) -> list[tuple[str, str, str | None, float]]:
    """Round-robin по странам: mobile не заполняется одной страной."""
    buckets: dict[str, deque] = defaultdict(deque)
    for row in sorted(rows, key=lambda item: item[3]):
        buckets[row[1]].append(row)

    result: list[tuple[str, str, str | None, float]] = []
    while any(buckets[country] for country in COUNTRY_ORDER):
        for country in COUNTRY_ORDER:
            if buckets[country]:
                result.append(buckets[country].popleft())
    return result


def write_atomic(path: str, configs: list[str]) -> None:
    if not configs:
        raise RuntimeError(f"Отказ обновления {path}: итоговый список пуст.")
    target = Path(path)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text("\n".join(configs) + "\n", encoding="utf-8")
    temporary.replace(target)


def main() -> None:
    text, source = get_source()
    configs = decode_lines(text)

    unique: dict[tuple, str] = {}
    for uri in configs:
        if endpoint(uri):
            unique.setdefault(fingerprint(uri), uri)
    configs = list(unique.values())
    if not configs:
        raise RuntimeError("Не найдено корректных VLESS-конфигураций.")

    resolved: dict[str, tuple[str, int, str]] = {}
    for uri in configs:
        ep = endpoint(uri)
        if not ep:
            continue
        host, port = ep
        ip = resolve_ipv4(host)
        if ip:
            resolved[uri] = (host, port, ip)

    reachable: dict[str, float] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
        futures = {
            executor.submit(tcp_probe, host, port): uri
            for uri, (host, port, _ip) in resolved.items()
        }
        for future in concurrent.futures.as_completed(futures):
            latency = future.result()
            if latency is not None:
                reachable[futures[future]] = latency

    ips = sorted({resolved[uri][2] for uri in reachable})
    geodata = geo_batch(ips)

    europe: list[tuple[str, str, str | None, float]] = []
    other: list[tuple[str, str, str | None, float]] = []
    for uri, probe_ms in reachable.items():
        ip = resolved[uri][2]
        country, city = geodata.get(ip, (None, None))
        if country in COUNTRY_ORDER:
            europe.append((uri, country, city, probe_ms))
        else:
            other.append((uri, country or "Other", city, probe_ms))

    if len(europe) < MIN_EUROPE_NODES:
        raise RuntimeError(
            f"Найдено только {len(europe)} европейских узлов. "
            "Старые подписки сохранены."
        )

    ordered = balanced_order(europe)
    named = [
        rename(uri, country, city, index)
        for index, (uri, country, city, _probe_ms) in enumerate(ordered, 1)
    ]

    other.sort(key=lambda item: item[3])
    backup = [
        rename(uri, country, city, index)
        for index, (uri, country, city, _probe_ms) in enumerate(other, 1)
    ]

    write_atomic("mobile.txt", named[:MOBILE_LIMIT])
    write_atomic("full.txt", named[:FULL_LIMIT])
    if backup:
        write_atomic("backup.txt", backup[:BACKUP_LIMIT])

    country_counts = {
        country: sum(
            1
            for _uri, row_country, _city, _probe in europe
            if row_country == country
        )
        for country in COUNTRY_ORDER
    }
    status = {
        "updated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": source,
        "upstream_vless": len(configs),
        "resolved_ipv4": len(resolved),
        "tcp_reachable_from_github": len(reachable),
        "europe_selected": len(europe),
        "country_counts": country_counts,
        "mobile_nodes": min(len(named), MOBILE_LIMIT),
        "full_nodes": min(len(named), FULL_LIMIT),
        "backup_nodes": min(len(backup), BACKUP_LIMIT),
        "note": (
            "TCP reachability is measured from GitHub Actions, "
            "not from the user's network."
        ),
    }
    Path("status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(status, ensure_ascii=False))


if __name__ == "__main__":
    main()
