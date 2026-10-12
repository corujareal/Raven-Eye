"""Passive asset enrichment through configured provider APIs.

Only compact metadata is returned. Raw banners, leak bodies, credentials,
request headers, and API keys are never copied into RavenEye reports.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import quote

import requests

from raveneye_pkg.config_io import get_api_key
from raveneye_pkg import state


_CENSYS_HOST_URL = "https://api.platform.censys.io/v3/global/asset/host/{}"
_NETLAS_HOST_URL = "https://app.netlas.io/api/host/{}/"
_LEAKIX_DOMAIN_URL = "https://leakix.net/domain/{}"
_CENSYS_ACCEPT = "application/vnd.censys.api.v3.host.v1+json"


def _result(provider: str, status: str, *, http_status: int | None = None,
            message: str | None = None, data: dict[str, Any] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"provider": provider, "status": status}
    if http_status is not None:
        value["http_status"] = http_status
    if message:
        value["message"] = message
    if data is not None:
        value["data"] = data
    return value


def _fetch(provider: str, url: str, *, headers: dict[str, str], params: dict[str, str] | None = None,
           requester=None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    get = requester or requests.get
    try:
        response = get(url, headers=headers, params=params, timeout=(4, 12), allow_redirects=False)
    except requests.RequestException as exc:
        return None, _result(provider, "request_error", message=type(exc).__name__)
    status_code = int(getattr(response, "status_code", 0) or 0)
    if 300 <= status_code < 400:
        return None, _result(provider, "redirect_blocked", http_status=status_code,
                             message="O redirecionamento da API não foi seguido.")
    if status_code == 401:
        return None, _result(provider, "authentication_failed", http_status=status_code,
                             message="Verifique a chave API.")
    if status_code == 402:
        return None, _result(provider, "plan_limit", http_status=status_code,
                             message="O plano ou saldo do provedor não permite esta consulta.")
    if status_code == 403:
        return None, _result(provider, "permission_denied", http_status=status_code,
                             message="A credencial foi recebida, mas não tem permissão para este recurso.")
    if status_code == 404:
        return None, _result(provider, "asset_not_found", http_status=status_code,
                             message="O provedor não encontrou dados para o ativo consultado.")
    if status_code == 400:
        return None, _result(provider, "invalid_request", http_status=status_code,
                             message="O provedor rejeitou o formato ou os parâmetros desta consulta.")
    if status_code == 422:
        return None, _result(provider, "invalid_request", http_status=status_code,
                             message="O provedor rejeitou os parâmetros desta consulta.")
    if status_code == 408:
        return None, _result(provider, "provider_timeout", http_status=status_code,
                             message="O provedor demorou demais para responder à consulta.")
    if status_code == 429:
        response_headers = getattr(response, "headers", {}) or {}
        retry_after = response_headers.get("Retry-After")
        message = "Limite do provedor atingido; nenhuma repetição automática foi feita."
        if retry_after:
            message += f" Retry-After: {str(retry_after)[:32]}s."
        elif provider.lower() == "leakix" and response_headers.get("x-limited-for"):
            message += f" X-Limited-For: {str(response_headers['x-limited-for'])[:32]}."
        return None, _result(provider, "rate_limited", http_status=status_code, message=message)
    if 500 <= status_code <= 599:
        return None, _result(provider, "provider_unavailable", http_status=status_code,
                             message="O provedor falhou ao processar a consulta; tente novamente mais tarde.")
    if status_code == 204:
        return None, _result(
            provider, "no_content", http_status=status_code,
            message="A API aceitou a consulta, mas respondeu sem conteúdo; nenhum metadado foi retornado.",
        )
    if status_code != 200:
        return None, _result(provider, "http_error", http_status=status_code,
                             message="O provedor retornou uma resposta HTTP inesperada.")
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return None, _result(provider, "invalid_json", http_status=status_code,
                             message="A resposta não contém JSON válido.")
    if not isinstance(payload, dict):
        return None, _result(provider, "invalid_response", http_status=status_code,
                             message="A resposta JSON não é um objeto.")
    return payload, None


def _censys_summary(payload: dict[str, Any]) -> dict[str, Any]:
    result = payload.get("result")
    resource = result.get("resource") if isinstance(result, dict) else None
    if not isinstance(resource, dict):
        resource = payload
    services = resource.get("services")
    services = services if isinstance(services, list) else []
    ports = sorted({int(item["port"]) for item in services
                    if isinstance(item, dict) and str(item.get("port", "")).isdigit()})
    asn = resource.get("autonomous_system")
    dns = resource.get("dns")
    names = dns.get("names", []) if isinstance(dns, dict) else []
    return {
        "ip": str(resource.get("ip", "")),
        "service_count": int(resource.get("service_count", len(services)) or 0),
        "ports": ports[:100],
        "asn": asn.get("asn") if isinstance(asn, dict) else None,
        "organization": str(asn.get("name", ""))[:200] if isinstance(asn, dict) else "",
        "dns_names": [str(name)[:253] for name in names[:50] if isinstance(name, str)],
    }


def _netlas_summary(payload: dict[str, Any]) -> dict[str, Any]:
    ports = payload.get("ports")
    port_values = sorted({int(item["port"]) for item in ports
                          if isinstance(item, dict) and str(item.get("port", "")).isdigit()}) if isinstance(ports, list) else []
    software = payload.get("software")
    software_names: set[str] = set()
    if isinstance(software, list):
        for item in software:
            if not isinstance(item, dict):
                continue
            for tag in item.get("tag", []) if isinstance(item.get("tag"), list) else []:
                if isinstance(tag, dict):
                    for field in ("name", "fullname"):
                        value = tag.get(field)
                        if isinstance(value, str) and value.strip():
                            software_names.add(value.strip()[:120])
                    for value in tag.values():
                        if isinstance(value, dict) and value.get("name"):
                            software_names.add(str(value["name"])[:120])
            if item.get("name"):
                software_names.add(str(item["name"])[:120])
    asn = payload.get("asn")
    return {
        "type": str(payload.get("type", ""))[:32],
        "ip": str(payload.get("ip", ""))[:64],
        "organization": str(payload.get("organization", ""))[:200],
        "asn": asn.get("number") if isinstance(asn, dict) else None,
        "ports": port_values[:100],
        "domains": [str(item)[:253] for item in payload.get("domains", [])[:50]
                    if isinstance(item, str)] if isinstance(payload.get("domains"), list) else [],
        "software": sorted(software_names)[:50],
    }


def _leakix_summary(payload: dict[str, Any]) -> dict[str, Any]:
    services = payload.get("services", payload.get("Services"))
    leaks = payload.get("leaks", payload.get("Leaks"))
    services = services if isinstance(services, list) else []
    leaks = leaks if isinstance(leaks, list) else []

    def compact(items: list[Any]) -> list[dict[str, Any]]:
        out = []
        for item in items[:25]:
            if not isinstance(item, dict):
                continue
            leak = item.get("leak") if isinstance(item.get("leak"), dict) else {}
            out.append({
                "host": str(item.get("host", ""))[:253],
                "ip": str(item.get("ip", ""))[:64],
                "port": item.get("port") if isinstance(item.get("port"), (int, str)) else None,
                "protocol": str(item.get("protocol", ""))[:32],
                "event_type": str(item.get("event_type", ""))[:120],
                "leak_type": str(leak.get("type", ""))[:120],
                "severity": str(leak.get("severity", ""))[:32],
            })
        return out

    return {
        "services_count": len(services),
        "leaks_count": len(leaks),
        "services": compact(services),
        "leaks": compact(leaks),
    }


def collect_asset_intelligence(domain: str, ip: str, *, requester=None) -> dict[str, Any]:
    """Query only providers with configured credentials; never emit raw payloads."""
    keys = {name: get_api_key(name) for name in ("censys", "netlas", "leakix")}
    results: dict[str, Any] = {}

    if keys["censys"]:
        try:
            address = ipaddress.ip_address(str(ip))
        except ValueError:
            results["censys"] = _result("Censys", "target_ip_unavailable",
                                        message="Censys host lookup precisa de um endereço IP resolvido.")
        else:
            organization = os.environ.get("CENSYS_ORGANIZATION_ID", "").strip() or str(
                state.config.get("censys_organization_id", "") or ""
            ).strip()
            headers = {
                "Authorization": f"Bearer {keys['censys']}",
                "Accept": _CENSYS_ACCEPT,
            }
            if organization:
                headers["X-Organization-ID"] = organization
            payload, error = _fetch("Censys", _CENSYS_HOST_URL.format(quote(address.compressed, safe="")),
                                    headers=headers, requester=requester)
            results["censys"] = error or _result("Censys", "ok", http_status=200,
                                                 data=_censys_summary(payload or {}))

    if keys["netlas"]:
        host = str(domain or ip or "").strip().strip(".")
        if not host:
            results["netlas"] = _result("Netlas", "target_unavailable", message="Domínio/IP do alvo ausente.")
        else:
            headers = {"Authorization": f"Bearer {keys['netlas']}", "Accept": "application/json"}
            payload, error = _fetch("Netlas", _NETLAS_HOST_URL.format(quote(host, safe="")),
                                    headers=headers, requester=requester)
            results["netlas"] = error or _result("Netlas", "ok", http_status=200,
                                                 data=_netlas_summary(payload or {}))

    if keys["leakix"]:
        host = str(domain or "").strip().strip(".")
        if not host:
            results["leakix"] = _result("LeakIX", "target_unavailable", message="Domínio do alvo ausente.")
        else:
            headers = {"api-key": keys["leakix"], "Accept": "application/json"}
            payload, error = _fetch("LeakIX", _LEAKIX_DOMAIN_URL.format(quote(host, safe="")),
                                    headers=headers, requester=requester)
            results["leakix"] = error or _result("LeakIX", "ok", http_status=200,
                                                 data=_leakix_summary(payload or {}))

    return results
