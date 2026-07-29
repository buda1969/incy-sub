#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import ipaddress
import json
import socket
import time
import urllib.parse
import urllib.request
from pathlib import Path

SOURCE = (
    "https://raw.githubusercontent.com/igareck/"
    "vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt"
)
TARGET_COUNTRIES = ("FI", "EE", "LV", "DE", "NL", "PL", "SE")
COUNTRY_NAMES = {
    "FI": "Finland",
    "EE": "Estonia",
    "LV": "Latvia",
    "DE": "Germany",
    "NL": "Netherlands",
    "PL": "Poland",
    "SE": "Sweden",
}
USER_AGENT = "incy-sub-updater/1.0"


def download_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def normalize_subscription(text: str) -> list[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    configs = [line for line in lines if line.startswith("vless://")]
    if configs:
        return configs

    compact = "".join(lines)
    try:
        compact += "=" * (-len(compact) % 4)
        decoded = base64.b64decode(compact).decode("utf-8", errors="replace")
        return [
            line.strip()
            for line in decoded.splitlines()
            if line.strip().startswith("vless://")
        ]
    except Exception:
        return []


def host_from_vless(uri: str) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(uri)
        return parsed.hostname
    except Exception:
        return None


def resolve_host(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for result in results:
            candidate = result[4][0]
            try:
                if ipaddress.ip_address(candidate).version == 4:
                    return candidate
            except ValueError:
                continue
        return results[0][4][0] if results else None
    except OSError:
        return None


def geolocate_ip(ip: str) -> tuple[str | None, str | None]:
    # Бесплатный API без ключа. При временном отказе узел просто пропускается.
    url = f"https://ipwho.is/{urllib.parse.quote(ip)}?fields=success,country_code,city"
    try:
        data = json.loads(download_text(url))
        if data.get("success"):
            return data.get("country_code"), data.get("city")
    except Exception:
        pass
    return None, None


def classify(uri: str) -> tuple[str, str | None, str | None]:
    host = host_from_vless(uri)
    if not host:
        return uri, None, None
    ip = resolve_host(host)
    if not ip:
        return uri, None, None
    country, city = geolocate_ip(ip)
    return uri, country, city


def rename(uri: str, country: str, city: str | None, index: int) -> str:
    parsed = urllib.parse.urlsplit(uri)
    label = f"{COUNTRY_NAMES.get(country, country)}"
    if city:
        label += f" {city}"
    label += f" #{index:02d}"
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.query,
         urllib.parse.quote(label, safe=" "))
    )


def deduplicate(configs: list[str]) -> list[str]:
    seen: set[tuple[str | None, int | None, str]] = set()
    result: list[str] = []
    for uri in configs:
        parsed = urllib.parse.urlsplit(uri)
        key = (parsed.hostname, parsed.port, parsed.query)
        if key not in seen:
            seen.add(key)
            result.append(uri)
    return result


def write_file(path: str, configs: list[str]) -> None:
    Path(path).write_text("\n".join(configs) + ("\n" if configs else ""), encoding="utf-8")


def main() -> None:
    configs = deduplicate(normalize_subscription(download_text(SOURCE)))
    if not configs:
        raise RuntimeError("В исходной подписке не найдено ни одной VLESS-конфигурации.")

    selected: list[tuple[str, str, str | None]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(classify, uri) for uri in configs]
        for future in concurrent.futures.as_completed(futures):
            uri, country, city = future.result()
            if country in set(TARGET_COUNTRIES):
                selected.append((uri, country, city))
            time.sleep(0.03)

    if not selected:
        raise RuntimeError(
            "Не удалось определить европейские узлы. "
            "Старые файлы подписки оставлены без изменений."
        )

    selected.sort(key=lambda item: (
        TARGET_COUNTRIES.index(item[1])
        if item[1] in set(TARGET_COUNTRIES) else 999,
        item[2] or "",
        item[0],
    ))

    renamed = [
        rename(uri, country, city, index)
        for index, (uri, country, city) in enumerate(selected, start=1)
    ]
    write_file("mobile.txt", renamed[:12])
    write_file("full.txt", renamed[:50])
    print(f"Готово: mobile={min(len(renamed), 12)}, full={min(len(renamed), 50)}")


if __name__ == "__main__":
    main()
