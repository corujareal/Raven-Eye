from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json

@dataclass(frozen=True, slots=True)
class CVEMatch:
    product: str
    version: str
    cve: str
    confidence: str = "MEDIUM"
    severity: str | None = None
    summary: str | None = None
    cwe: str | None = None

def correlate_exact(product: str, version: str, records: list[dict]) -> list[CVEMatch]:
    """Exact product+version correlation; never infers a vulnerable version from proximity."""
    p, v = product.strip().lower(), version.strip()
    out = []
    for r in records:
        if (str(r.get("product", "")).strip().lower() == p and
            str(r.get("version", "")).strip() == v and r.get("cve")):
            out.append(CVEMatch(product, version, str(r["cve"]), "HIGH",
                                str(r.get("severity")) if r.get("severity") else None,
                                str(r.get("summary")) if r.get("summary") else None,
                                str(r.get("cwe")) if r.get("cwe") else None))
    return out

def records_from_nvd_json(data: dict) -> list[dict]:
    """Normalize a local NVD JSON export into the exact-match record shape.

    This parser is intentionally offline: callers decide when/how to download data.
    It does not fetch, execute, or suggest exploits.
    """
    rows = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        configs = cve.get("configurations", [])
        for cfg in configs:
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    crit = str(match.get("criteria", ""))
                    parts = crit.split(":")
                    if len(parts) < 6:
                        continue
                    product, version = parts[4], parts[5]
                    if version in ("*", "-", ""):
                        continue
                    metrics = cve.get("metrics", {})
                    severity = None
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if metrics.get(key):
                            severity = metrics[key][0].get("cvssData", {}).get("baseSeverity")
                            if severity: break
                    summary = next((d.get("value") for d in cve.get("descriptions", [])
                                    if d.get("lang") == "en"), None)
                    weaknesses = cve.get("weaknesses", [])
                    cwe = next((d.get("value") for w in weaknesses for d in w.get("description", [])
                                if d.get("lang") == "en" and str(d.get("value", "")).startswith("CWE-")), None)
                    rows.append({"product": product, "version": version, "cve": cid,
                                 "severity": severity, "summary": summary, "cwe": cwe})
    return rows

def load_local_records(path: str | Path) -> list[dict]:
    """Load local normalized rows or an NVD JSON export; never contacts a feed."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        return records_from_nvd_json(data) if "vulnerabilities" in data else list(data.get("records", []))
    return []

def correlate_technologies(technologies: list[dict], records: list[dict], *, url: str) -> list[dict]:
    """Emit only exact version matches from high-confidence fingerprints."""
    findings = []
    for tech in technologies:
        name, version = str(tech.get("name", "")), tech.get("version")
        if not name or not version or tech.get("confidence") not in {"HIGH", "MEDIUM"}:
            continue
        for match in correlate_exact(name, str(version), records):
            findings.append({
                "id": f"cve.exact.{match.cve}", "name": f"Exact CVE correlation: {match.cve}",
                "severity": match.severity or "UNKNOWN", "confidence": match.confidence, "url": url,
                "evidence": f"{match.product} {match.version} identified by {tech.get('source', 'fingerprint')}; local advisory exact match.",
                "remediation": "Confirm the deployed component inventory and apply the vendor's fixed release or mitigation.",
                "cve": match.cve, "cwe": match.cwe or "", "tags": ["cve", "offline-correlation", "exact-version"],
            })
    return findings
