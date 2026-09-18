from __future__ import annotations
import asyncio, ipaddress, socket
from urllib.parse import urlsplit

BLOCKED_NETS = tuple(ipaddress.ip_network(x) for x in (
    '0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
    '172.16.0.0/12','192.0.0.0/24','192.168.0.0/16','198.18.0.0/15',
    '198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','::/128','::1/128',
    'fc00::/7','fe80::/10','ff00::/8','2001:db8::/32'))

class SSRFBlocked(ValueError): pass

def _blocked_ip(ip: str) -> bool:
    obj = ipaddress.ip_address(ip)
    if obj.version == 6 and obj.ipv4_mapped:
        obj = obj.ipv4_mapped
    return obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved or obj.is_multicast or any(obj in n for n in BLOCKED_NETS)

async def resolve_public_ips(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
    ips=[]
    for info in infos:
        ip=info[4][0]
        if _blocked_ip(ip):
            raise SSRFBlocked(f'Destino privado/link-local bloqueado: {ip}')
        if ip not in ips: ips.append(ip)
    if not ips: raise SSRFBlocked('Host sem resolução')
    return ips

def validate_url(url: str, allowed_domains: set[str] | None = None) -> str:
    p=urlsplit(url); host=(p.hostname or '').lower().rstrip('.')
    if p.scheme not in {'http','https'} or not host: raise SSRFBlocked('URL não é HTTP(S) válida')
    if allowed_domains and not any(host == d.lower().rstrip('.') or host.endswith('.'+d.lower().rstrip('.')) for d in allowed_domains):
        raise SSRFBlocked('Host fora do escopo')
    try:
        ip=ipaddress.ip_address(host)
        if _blocked_ip(str(ip)): raise SSRFBlocked('Destino privado/link-local bloqueado')
    except ValueError:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == 'https' else 80), type=socket.SOCK_STREAM)
        for info in infos:
            if _blocked_ip(info[4][0]): raise SSRFBlocked('Destino privado/link-local bloqueado')
        return url
    return url

async def validate_url_async(url: str, allowed_domains: set[str] | None = None) -> list[str]:
    validate_url(url, allowed_domains)
    host=urlsplit(url).hostname or ''
    try:
        ipaddress.ip_address(host); return [host]
    except ValueError:
        return await resolve_public_ips(host, urlsplit(url).port or (443 if urlsplit(url).scheme=='https' else 80))
