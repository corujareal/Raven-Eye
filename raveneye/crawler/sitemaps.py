from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit


_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)


def parse_robots(text: str, base_url: str, user_agent: str = "*") -> dict:
    """Parse applicable robots groups, preserving RFC 9309 rule precedence."""
    groups: list[dict] = []
    sitemaps: list[str] = []
    current = {"agents": [], "rules": []}
    saw_rule = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if saw_rule:
                if current["agents"]:
                    groups.append(current)
                current = {"agents": [], "rules": []}
                saw_rule = False
            current["agents"].append(value.lower())
        elif key in {"allow", "disallow"}:
            saw_rule = True
            if value:
                current["rules"].append({"allow": key == "allow", "path": value})
        elif key == "sitemap":
            sitemaps.append(urljoin(base_url, value))
    if current["agents"]:
        groups.append(current)

    agent_string = user_agent.strip().lower()
    matching = []
    best_specificity = 0
    for group in groups:
        specificity = max((len(agent) for agent in group["agents"] if agent != "*" and agent in agent_string), default=0)
        if specificity > best_specificity:
            matching = [group]
            best_specificity = specificity
        elif specificity and specificity == best_specificity:
            matching.append(group)
    if not matching:
        matching = [group for group in groups if "*" in group["agents"]]

    selected_rules = [rule for group in matching for rule in group["rules"]]
    allowed = [urljoin(base_url, rule["path"]) for rule in selected_rules if rule["allow"]]
    disallowed = [urljoin(base_url, rule["path"]) for rule in selected_rules if not rule["allow"]]
    return {
        "allow": list(dict.fromkeys(allowed)),
        "disallow": list(dict.fromkeys(disallowed)),
        "sitemaps": list(dict.fromkeys(sitemaps)),
        "rules": selected_rules,
    }


def robots_allows(url: str, robots_url: str, rules: list[dict]) -> bool:
    """Apply longest matching rule; Allow wins ties as required by RFC 9309."""
    target, robots = urlsplit(url), urlsplit(robots_url)
    def origin(p):
        scheme = p.scheme.lower()
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port or (443 if scheme == "https" else 80)
        return scheme, host, port
    if origin(target) != origin(robots):
        return True
    candidate = target.path or "/"
    if target.query:
        candidate += "?" + target.query
    matches = []
    for rule in rules:
        pattern = rule.get("path", "")
        if not pattern:
            continue
        regex = "^" + re.escape(pattern).replace(r"\*", ".*")
        if pattern.endswith("$"):
            regex = regex[:-2] + "$"
        else:
            regex += ".*"
        try:
            if re.match(regex, candidate):
                specificity = len(pattern.replace("*", "").replace("$", ""))
                matches.append((specificity, bool(rule.get("allow"))))
        except re.error:
            continue
    if not matches:
        return True
    longest = max(size for size, _ in matches)
    return any(allow for size, allow in matches if size == longest)


def parse_sitemap(text: str, base_url: str):
    """Return URLs from both urlset and sitemapindex documents."""
    return list(dict.fromkeys(urljoin(base_url, x.strip()) for x in _LOC_RE.findall(text) if x.strip()))
