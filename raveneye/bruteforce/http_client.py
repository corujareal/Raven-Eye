from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests

from raveneye_pkg.network import _pin_dns_to


class ProtectedRequestError(RuntimeError):
    """A request was rejected or failed without exposing URL/credential data."""


@dataclass(frozen=True, slots=True)
class LoginResponse:
    status_code: int
    url: str
    text: str
    headers: dict[str, str]


def _origin(url: str) -> tuple[str, str, int]:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return parsed.scheme.lower(), parsed.hostname.rstrip(".").lower(), port
    except (ValueError, UnicodeError):
        raise ProtectedRequestError("URL precisa ser HTTP(S), sem userinfo e com host valido.") from None


def _resolve_and_pin(host: str, port: int) -> str:
    try:
        try:
            values = [str(ipaddress.ip_address(host))]
        except ValueError:
            values = list(dict.fromkeys(
                str(ipaddress.ip_address(item[4][0]))
                for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            ))
        if not values:
            raise ValueError
        parsed = [ipaddress.ip_address(value) for value in values]
        # Explicitly entered private/loopback lab targets are allowed after the
        # CLI confirmation. Mixed public/private answers are rejected to avoid
        # DNS rebinding and resolver-dependent destination selection.
        scopes = {"global" if value.is_global else "local" for value in parsed}
        if len(scopes) != 1 or any(
            value.is_multicast or value.is_reserved or value.is_unspecified or value.is_link_local
            for value in parsed
        ):
            raise ValueError
        return values[0]
    except (OSError, ValueError, IndexError):
        raise ProtectedRequestError("Destino DNS/IP nao passou na validacao segura.") from None


class ProtectedLoginClient:
    """Requests session confined to the explicitly entered origin and IP."""

    def __init__(self, target: str, *, timeout: float = 8.0, max_bytes: int = 2_000_000):
        self.target = target
        self.origin = _origin(target)
        self.pinned_ip = _resolve_and_pin(self.origin[1], self.origin[2])
        self.timeout = min(30.0, max(1.0, float(timeout)))
        self.max_bytes = max(1024, int(max_bytes))
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.proxies.clear()
        self.session.headers.update({"User-Agent": "RavenEye authorized login audit"})

    def close(self) -> None:
        self.session.close()

    def _assert_origin(self, url: str) -> None:
        if _origin(url) != self.origin:
            raise ProtectedRequestError("Redirect fora da origem explicitamente confirmada foi bloqueado.")

    def validate_origin(self, url: str) -> None:
        """Validate a discovered form action before credentials are prepared."""
        self._assert_origin(url)

    def request(self, method: str, url: str, *, data: dict[str, str] | None = None) -> LoginResponse:
        current = url
        current_method = method.upper()
        current_data = data
        for _hop in range(6):
            self._assert_origin(current)
            try:
                with _pin_dns_to(self.pinned_ip):
                    response = self.session.request(
                        current_method,
                        current,
                        data=current_data,
                        headers={"Accept": "text/html,application/json;q=0.9,*/*;q=0.5"},
                        timeout=self.timeout,
                        allow_redirects=False,
                        stream=True,
                    )
            except ProtectedRequestError:
                raise
            except requests.RequestException:
                raise ProtectedRequestError("Falha de conexao no alvo confirmado.") from None

            location = response.headers.get("Location")
            if response.status_code in {301, 302, 303, 307, 308} and location:
                next_url = urljoin(current, location)
                response.close()
                self._assert_origin(next_url)
                if current_method == "POST" and response.status_code in {307, 308}:
                    raise ProtectedRequestError("Redirect que repetiria credenciais foi bloqueado.")
                if response.status_code == 303 or (
                    response.status_code in {301, 302} and current_method == "POST"
                ):
                    current_method, current_data = "GET", None
                current = next_url
                continue

            try:
                length = response.headers.get("Content-Length", "")
                if length.isdigit() and int(length) > self.max_bytes:
                    raise ProtectedRequestError("Resposta excedeu o limite configurado.")
                pieces: list[bytes] = []
                total = 0
                for chunk in response.iter_content(chunk_size=16 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise ProtectedRequestError("Resposta excedeu o limite configurado.")
                    pieces.append(chunk)
                encoding = response.encoding or "utf-8"
                try:
                    body = b"".join(pieces).decode(encoding, errors="replace")
                except LookupError:
                    body = b"".join(pieces).decode("utf-8", errors="replace")
                return LoginResponse(
                    status_code=int(response.status_code),
                    url=current,
                    text=body,
                    headers={str(key): str(value) for key, value in response.headers.items()},
                )
            except ProtectedRequestError:
                raise
            except requests.RequestException:
                raise ProtectedRequestError("Falha ao ler resposta no alvo confirmado.") from None
            finally:
                response.close()
        raise ProtectedRequestError("Limite de redirects da mesma origem excedido.")
