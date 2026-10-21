#!/usr/bin/env python3
"""
Automatyzacja Wazuh:
- pobiera alerty z API Wazuh
- filtruje podejrzane zdarzenia
- wyciąga źródłowe adresy IP
- blokuje IP przez Active Response
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


IPV4_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
)


@dataclass
class WazuhConfig:
    base_url: str
    username: str
    password: str
    verify_ssl: bool
    timeout: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pobieranie alertów Wazuh i blokowanie podejrzanych IP."
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("WAZUH_BASE_URL", "https://192.168.118.133:55000"),
        help="Adres API Wazuh, np. https://wazuh.local:55000",
    )
    parser.add_argument(
        "--username",
        default=os.getenv("WAZUH_USERNAME", "wazuh-wui"),
        help="Użytkownik API Wazuh",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("WAZUH_PASSWORD","MyS3cr37P450r.*-"),
        help="Hasło API Wazuh",
    )
    parser.add_argument(
        "--rule-ids",
        default=os.getenv("WAZUH_RULE_IDS", "100011,100013,100014,100015"),
        help="Lista rule.id oddzielona przecinkami",
    )
    parser.add_argument(
        "--min-level",
        type=int,
        default=int(os.getenv("WAZUH_MIN_LEVEL", "10")),
        help="Minimalny poziom rule.level",
    )
    parser.add_argument(
        "--lookback-minutes",
        type=int,
        default=int(os.getenv("WAZUH_LOOKBACK_MINUTES", "15")),
        help="Zakres czasowy alertów w minutach wstecz",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=int(os.getenv("WAZUH_ALERT_LIMIT", "200")),
        help="Maksymalna liczba alertów do pobrania",
    )
    parser.add_argument(
        "--agent-id",
        default=os.getenv("WAZUH_AGENT_ID", "001"),
        help="ID agenta, na którym wykonać active response",
    )
    parser.add_argument(
        "--block-command",
        default=os.getenv("WAZUH_BLOCK_COMMAND", "firewall-drop"),
        help="Komenda Active Response do blokowania IP",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("WAZUH_TIMEOUT", "20")),
        help="Timeout HTTP (sekundy)",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Wyłącz walidację certyfikatu SSL (lab/dev)",
    )
    parser.add_argument(
        "--execute-block",
        action="store_true",
        help="Wykonaj blokowanie (domyślnie tylko dry-run)",
    )
    return parser.parse_args()


def _build_ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    if verify_ssl:
        return ssl.create_default_context()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    timeout: int = 20,
    verify_ssl: bool = True,
) -> Any:
    data = None
    request_headers = headers.copy() if headers else {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=request_headers,
        method=method.upper(),
    )
    context = _build_ssl_context(verify_ssl)

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Connection error for {url}: {exc}") from exc


def get_token(config: WazuhConfig) -> str:
    credentials = f"{config.username}:{config.password}".encode("utf-8")
    basic = base64.b64encode(credentials).decode("ascii")
    headers = {"Authorization": f"Basic {basic}"}
    token_url = f"{config.base_url.rstrip('/')}/security/user/authenticate?raw=true"
    response = _http_json(
        "POST",
        token_url,
        headers=headers,
        timeout=config.timeout,
        verify_ssl=config.verify_ssl,
    )

    if isinstance(response, str):
        return response.strip()
    if isinstance(response, dict) and response.get("data"):
        return str(response["data"]).strip()
    raise RuntimeError("Nie udało się pobrać tokenu z API Wazuh.")


def get_alerts(config: WazuhConfig, token: str, limit: int) -> list[dict[str, Any]]:
    params = urllib.parse.urlencode({"limit": str(limit), "sort": "-timestamp"})
    alerts_url = f"{config.base_url.rstrip('/')}/alerts?{params}"
    headers = {"Authorization": "Bearer " + token}
    response = _http_json(
        "GET",
        alerts_url,
        headers=headers,
        timeout=config.timeout,
        verify_ssl=config.verify_ssl,
    )

    if isinstance(response, dict):
        data = response.get("data", {})
        items = data.get("affected_items", [])
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    raise RuntimeError("Niepoprawna odpowiedź z endpointu /alerts.")


def parse_timestamp(value: str) -> dt.datetime | None:
    value = value.strip()
    patterns = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S")
    for pattern in patterns:
        try:
            parsed = dt.datetime.strptime(value, pattern)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc)
        except ValueError:
            continue
    return None


def extract_ip(alert: dict[str, Any]) -> str | None:
    data = alert.get("data")
    candidates: list[str] = []
    if isinstance(data, dict):
        for key in ("srcip", "src_ip", "ip"):
            value = data.get(key)
            if isinstance(value, str):
                candidates.append(value)

    agent = alert.get("agent")
    if isinstance(agent, dict):
        ip = agent.get("ip")
        if isinstance(ip, str):
            candidates.append(ip)

    full_log = alert.get("full_log")
    if isinstance(full_log, str):
        candidates.extend(IPV4_REGEX.findall(full_log))

    for candidate in candidates:
        match = IPV4_REGEX.search(candidate)
        if match:
            return match.group(0)
    return None


def filter_suspicious_alerts(
    alerts: list[dict[str, Any]],
    *,
    allowed_rule_ids: set[str],
    min_level: int,
    lookback_minutes: int,
) -> list[dict[str, Any]]:
    threshold = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(minutes=lookback_minutes)
    suspicious: list[dict[str, Any]] = []

    for alert in alerts:
        rule = alert.get("rule")
        if not isinstance(rule, dict):
            continue

        rule_id = str(rule.get("id", ""))
        level = int(rule.get("level", 0))
        if rule_id not in allowed_rule_ids or level < min_level:
            continue

        timestamp = str(alert.get("timestamp", "")).strip()
        parsed_ts = parse_timestamp(timestamp) if timestamp else None
        if parsed_ts and parsed_ts < threshold:
            continue

        suspicious.append(alert)

    return suspicious


def block_ip(
    config: WazuhConfig,
    token: str,
    ip: str,
    *,
    agent_id: str,
    block_command: str,
) -> dict[str, Any]:
    headers = {"Authorization": "Bearer " + token}
    block_url = f"{config.base_url.rstrip('/')}/active-response"
    payload = {
        "command": block_command,
        "custom": False,
        "arguments": [ip],
        "agents_list": [agent_id],
    }
    return _http_json(
        "PUT",
        block_url,
        headers=headers,
        payload=payload,
        timeout=config.timeout,
        verify_ssl=config.verify_ssl,
    )


def main() -> int:
    args = parse_args()
    if not args.password:
        print("Brak hasła: ustaw --password lub WAZUH_PASSWORD.", file=sys.stderr)
        return 2

    config = WazuhConfig(
        args.base_url,
        args.username,
        args.password,
        not args.no_verify_ssl,
        args.timeout,
    )
    rule_ids = {item.strip() for item in args.rule_ids.split(",") if item.strip()}
    if not rule_ids:
        print("Lista --rule-ids nie może być pusta.", file=sys.stderr)
        return 2

    try:
        token = get_token(config)
        alerts = get_alerts(config, token, args.limit)
        suspicious_alerts = filter_suspicious_alerts(
            alerts,
            allowed_rule_ids=rule_ids,
            min_level=args.min_level,
            lookback_minutes=args.lookback_minutes,
        )
    except RuntimeError as exc:
        print(f"Błąd API: {exc}", file=sys.stderr)
        return 1

    ips = sorted(
        {
            ip
            for alert in suspicious_alerts
            if (ip := extract_ip(alert)) and not ip.startswith(("127.", "10.", "192.168."))
        }
    )

    print(f"Pobrane alerty: {len(alerts)}")
    print(f"Podejrzane alerty: {len(suspicious_alerts)}")
    print(f"Unikalne IP do blokady: {len(ips)}")

    for ip in ips:
        if not args.execute_block:
            print(f"[DRY-RUN] do blokady: {ip}")
            continue
        try:
            result = block_ip(
                config,
                token,
                ip,
                agent_id=args.agent_id,
                block_command=args.block_command,
            )
            print(f"[BLOCKED] {ip}: {json.dumps(result, ensure_ascii=False)}")
        except RuntimeError as exc:
            print(f"[ERROR] {ip}: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
