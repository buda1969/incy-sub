#!/usr/bin/env python3
from __future__ import annotations

import base64
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import socket
import statistics
import time
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

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
MIN_CURRENT_EUROPE_NODES = 5

PROBE_ATTEMPTS = 3
PROBE_TIMEOUT = 2.5
MIN_SUCCESSFUL_PROBES = 2
MAX_WORKERS = 24

HISTORY_FILE = Path("node_history.json")
HISTORY_WINDOW = 12
HISTORY_RETENTION_DAYS = 30
UA = "buda1969/incy-sub updater-v4"


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


def probe_once(host: str, port: int) -> float | None:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT):
            return round((time.monotonic() - started) * 1000, 1)
    except OSError:
        return None


def probe_node(host: str, port: int) -> dict[str, Any]:
    samples: list[float] = []
    for attempt in range(PROBE_ATTEMPTS):
        latency = probe_once(host, port)
        if latency is not None:
            samples.append(latency)
        if attempt + 1 < PROBE_ATTEMPTS:
            time.sleep(0.15)

    reachable = len(samples) >= MIN_SUCCESSFUL_PROBES
    return {
        "reachable": reachable,
        "successes": len(samples),
        "attempts": PROBE_ATTEMPTS,
        "latency_ms": round(statistics.median(samples), 1) if samples else None,
    }


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


def node_id(uri: str) -> str:
    raw = json.dumps(fingerprint(uri), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def rename(
    uri: str,
    country: str,
    city: str | None,
    index: int,
    success_rate: float,
) -> str:
    parsed = urllib.parse.urlsplit(uri)

    place = COUNTRY_NAMES.get(country, country)

    if city:
        safe_city = "".join(
            ch if ch.isascii() and (ch.isalnum() or ch in " -_")
            else "-"
            for ch in city
        )
        safe_city = " ".join(safe_city.split())
        if safe_city:
            place += f" {safe_city}"

    quality = round(success_rate * 100)
    label = f"{place} {index:02d} stable-{quality}"

    encoded_label = urllib.parse.quote(
        label,
        safe="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_ "
    )

    return urllib.parse.urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.query,
            encoded_label,
        )
    )


def load_history() -> dict[str, Any]:
    if not HISTORY_FILE.exists():
        return {"version": 1, "nodes": {}}
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("nodes"), dict):
            raise ValueError("Некорректная структура")
        return data
    except Exception as exc:
        print(f"WARNING: история повреждена и будет создана заново: {exc}")
        return {"version": 1, "nodes": {}}


def parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed
    except ValueError:
        return None


def update_history(
    history: dict[str, Any],
    configs: list[str],
    resolved: dict[str, tuple[str, int, str]],
    probe_results: dict[str, dict[str, Any]],
    geodata: dict[str, tuple[str | None, str | None]],
    now: dt.datetime,
) -> dict[str, dict[str, Any]]:
    nodes: dict[str, Any] = history.setdefault("nodes", {})
    active: dict[str, dict[str, Any]] = {}

    for uri in configs:
        nid = node_id(uri)
        old = nodes.get(nid, {})
        checks = deque(old.get("checks", []), maxlen=HISTORY_WINDOW)

        probe = probe_results.get(uri)
        reachable = bool(probe and probe["reachable"])
        latency = probe.get("latency_ms") if probe else None

        checks.append({
            "at": now.isoformat(),
            "ok": reachable,
            "latency_ms": latency,
        })

        previous_streak = int(old.get("failure_streak", 0))
        failure_streak = 0 if reachable else previous_streak + 1

        ep = endpoint(uri)
        host, port = ep if ep else (None, None)
        ip = resolved.get(uri, (None, None, None))[2]
        country, city = geodata.get(ip, (None, None)) if ip else (None, None)

        successful_checks = [item for item in checks if item.get("ok")]
        success_rate = len(successful_checks) / len(checks) if checks else 0.0
        latencies = [
            float(item["latency_ms"])
            for item in successful_checks
            if item.get("latency_ms") is not None
        ]
        median_latency = round(statistics.median(latencies), 1) if latencies else None

        record = {
            "uri": uri,
            "host": host,
            "port": port,
            "last_ip": ip,
            "country": country,
            "city": city,
            "checks": list(checks),
            "success_rate": round(success_rate, 4),
            "median_latency_ms": median_latency,
            "failure_streak": failure_streak,
            "last_checked_at": now.isoformat(),
            "last_success_at": (
                now.isoformat()
                if reachable
                else old.get("last_success_at")
            ),
        }
        nodes[nid] = record
        active[nid] = record

    cutoff = now - dt.timedelta(days=HISTORY_RETENTION_DAYS)
    for nid in list(nodes):
        if nid in active:
            continue
        last_checked = parse_iso(nodes[nid].get("last_checked_at"))
        if last_checked is None or last_checked < cutoff:
            del nodes[nid]

    history["updated_at_utc"] = now.isoformat()
    return active


def rank_score(record: dict[str, Any]) -> float:
    success_rate = float(record.get("success_rate", 0.0))
    latency = record.get("median_latency_ms")
    latency_penalty = min(float(latency or 1500), 1500) / 1500
    history_depth = min(len(record.get("checks", [])) / HISTORY_WINDOW, 1.0)
    failure_penalty = min(int(record.get("failure_streak", 0)), 5) * 0.12

    return (
        success_rate * 0.72
        + (1.0 - latency_penalty) * 0.18
        + history_depth * 0.10
        - failure_penalty
    )


def balanced_order(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, deque] = defaultdict(deque)
    for row in sorted(rows, key=rank_score, reverse=True):
        buckets[row["country"]].append(row)

    result: list[dict[str, Any]] = []
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
    now = dt.datetime.now(dt.timezone.utc)
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

    probe_results: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(probe_node, host, port): uri
            for uri, (host, port, _ip) in resolved.items()
        }
        for future in concurrent.futures.as_completed(futures):
            uri = futures[future]
            try:
                probe_results[uri] = future.result()
            except Exception as exc:
                print(f"WARNING: проверка узла завершилась ошибкой: {exc}")

    ips = sorted({resolved[uri][2] for uri in resolved})
    geodata = geo_batch(ips)

    history = load_history()
    active = update_history(
        history, configs, resolved, probe_results, geodata, now
    )

    current_europe: list[dict[str, Any]] = []
    historical_reserve: list[dict[str, Any]] = []

    for record in active.values():
        country = record.get("country")
        if country not in COUNTRY_ORDER:
            continue

        uri = record["uri"]
        currently_reachable = bool(
            probe_results.get(uri, {}).get("reachable")
        )

        if currently_reachable:
            current_europe.append(record)
        elif (
            record.get("failure_streak") == 1
            and float(record.get("success_rate", 0.0)) >= 0.75
            and record.get("last_success_at")
        ):
            # После одного промаха стабильный узел не удаляется из full/backup,
            # но в mobile попадают только узлы, прошедшие текущую проверку.
            historical_reserve.append(record)

    if len(current_europe) < MIN_CURRENT_EUROPE_NODES:
        raise RuntimeError(
            f"Сейчас доступно только {len(current_europe)} европейских узлов. "
            "Старые mobile.txt/full.txt сохранены."
        )

    ordered_current = balanced_order(current_europe)
    ordered_reserve = sorted(
        historical_reserve, key=rank_score, reverse=True
    )

    mobile_records = ordered_current[:MOBILE_LIMIT]
    full_records = (ordered_current + ordered_reserve)[:FULL_LIMIT]

    mobile = [
        rename(
            record["uri"],
            record["country"],
            record.get("city"),
            index,
            float(record.get("success_rate", 0.0)),
        )
        for index, record in enumerate(mobile_records, 1)
    ]
    full = [
        rename(
            record["uri"],
            record["country"],
            record.get("city"),
            index,
            float(record.get("success_rate", 0.0)),
        )
        for index, record in enumerate(full_records, 1)
    ]
    backup = [
        rename(
            record["uri"],
            record["country"],
            record.get("city"),
            index,
            float(record.get("success_rate", 0.0)),
        )
        for index, record in enumerate(ordered_reserve[:BACKUP_LIMIT], 1)
    ]

    write_atomic("mobile.txt", mobile)
    write_atomic("full.txt", full)
    if backup:
        write_atomic("backup.txt", backup)

    HISTORY_FILE.write_text(
        json.dumps(history, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    country_counts = {
        country: sum(
            1 for record in current_europe
            if record.get("country") == country
        )
        for country in COUNTRY_ORDER
    }
    status = {
        "updated_at_utc": now.isoformat(),
        "source": source,
        "upstream_vless": len(configs),
        "resolved_ipv4": len(resolved),
        "currently_reachable": sum(
            1 for result in probe_results.values()
            if result.get("reachable")
        ),
        "current_europe": len(current_europe),
        "historical_reserve": len(historical_reserve),
        "country_counts": country_counts,
        "mobile_nodes": len(mobile),
        "full_nodes": len(full),
        "backup_nodes": len(backup),
        "probe_policy": {
            "attempts_per_node": PROBE_ATTEMPTS,
            "minimum_successes": MIN_SUCCESSFUL_PROBES,
            "timeout_seconds": PROBE_TIMEOUT,
        },
        "history_policy": {
            "checks_per_node": HISTORY_WINDOW,
            "retention_days": HISTORY_RETENTION_DAYS,
        },
        "note": (
            "Задержка измеряется от GitHub Actions, а не от сети пользователя. "
            "mobile.txt содержит только узлы, прошедшие текущую проверку."
        ),
    }
    Path("status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(status, ensure_ascii=False))


if __name__ == "__main__":
    main()
