from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import re
from typing import Any

_CVE_VERSION = re.compile(r"^[vV]?(\d+(?:\.\d+)*)$")


@dataclass(frozen=True, slots=True)
class CVEMatch:
    product: str
    version: str
    cve: str
    confidence: str = "LOW"
    severity: str | None = None
    summary: str | None = None
    cwe: str | None = None
    stage: str = "POSSIBLE"
    vendor: str = ""
    source: str = "unversioned-local"


def _split_cpe(cpe: str) -> list[str]:
    """Split a formatted CPE 2.3 name without splitting escaped colons."""
    fields, part, escaped = [], [], False
    for char in str(cpe):
        if escaped:
            part.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(part))
            part = []
        else:
            part.append(char)
    if escaped:
        part.append("\\")
    fields.append("".join(part))
    return fields


def _version_parts(value: str) -> tuple[int, ...] | None:
    hit = _CVE_VERSION.fullmatch(str(value or "").strip())
    if not hit:
        return None
    return tuple(int(x) for x in hit.group(1).split("."))


def _compare_versions(left: str, right: str) -> int | None:
    a, b = _version_parts(left), _version_parts(right)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)


def version_matches(version: str, record: dict) -> bool:
    """Conservative CPE version/range match; unknown formats never match ranges."""
    exact = str(record.get("version") or "").strip()
    start_in = record.get("version_start_including")
    start_ex = record.get("version_start_excluding")
    end_in = record.get("version_end_including")
    end_ex = record.get("version_end_excluding")
    if not any((start_in, start_ex, end_in, end_ex)):
        return exact not in {"", "*", "-", "NA"} and str(version).strip() == exact
    if not _version_parts(version):
        return False
    if exact not in {"", "*", "-", "NA"} and str(version).strip() != exact:
        return False
    if start_in:
        cmp = _compare_versions(version, str(start_in))
        if cmp is None or cmp < 0:
            return False
    if start_ex:
        cmp = _compare_versions(version, str(start_ex))
        if cmp is None or cmp <= 0:
            return False
    if end_in:
        cmp = _compare_versions(version, str(end_in))
        if cmp is None or cmp > 0:
            return False
    if end_ex:
        cmp = _compare_versions(version, str(end_ex))
        if cmp is None or cmp >= 0:
            return False
    return True


def _product_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def correlate_exact(product: str, version: str, records: list[dict]) -> list[CVEMatch]:
    """Compatibility API; unversioned records stay POSSIBLE, never confirmed."""
    wanted = _product_key(product)
    out = []
    for record in records:
        record_product = _product_key(record.get("product", ""))
        cve = str(record.get("cve", ""))
        if (record_product == wanted and version_matches(version, record)
                and cve and record.get("vulnerable", True) is not False):
            out.append(CVEMatch(
                product=str(record.get("product", product)),
                version=version,
                cve=cve,
                confidence="MEDIUM",
                severity=str(record.get("severity")) if record.get("severity") else None,
                summary=str(record.get("summary")) if record.get("summary") else None,
                cwe=str(record.get("cwe")) if record.get("cwe") else None,
                stage="POSSIBLE",
                vendor=str(record.get("vendor", "")),
                source=str(record.get("source", "unversioned-local")),
            ))
    return out


def _leaf_matches(cve: dict):
    """Yield CPE leaves with a flag when sibling/configuration context is unknown."""
    def visit(node: dict, inherited_context: bool = False):
        if not isinstance(node, dict):
            return
        matches = node.get("cpeMatch", []) or []
        children = node.get("children", []) or []
        node_context = (
            inherited_context
            or bool(node.get("negate"))
            or str(node.get("operator", "OR")).upper() == "AND"
            or len(matches) > 1
            or bool(children)
        )
        for match in matches:
            yield match, node_context
        for child in children:
            yield from visit(child, node_context)
    for config in cve.get("configurations", []) or []:
        if not isinstance(config, dict):
            continue
        roots = config.get("nodes", []) or []
        root_context = len(roots) > 1
        for node in roots:
            yield from visit(node, root_context)


def records_from_nvd_json(data: dict) -> list[dict]:
    """Normalize NVD 2.0 CVE JSON while retaining applicability semantics."""
    rows = []
    for item in data.get("vulnerabilities", []) or []:
        cve = item.get("cve", {}) if isinstance(item, dict) else {}
        cid = cve.get("id")
        if not cid or str(cve.get("vulnStatus", "")).lower() == "rejected":
            continue
        metrics = cve.get("metrics", {}) or {}
        severity = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                metric = metrics[key][0].get("cvssData", {})
                severity = metric.get("baseSeverity") or metric.get("baseScore")
                if severity:
                    break
        summary = next((d.get("value") for d in cve.get("descriptions", [])
                        if d.get("lang") == "en"), None)
        weaknesses = cve.get("weaknesses", []) or []
        cwe = next((d.get("value") for w in weaknesses for d in w.get("description", [])
                    if d.get("lang") == "en" and str(d.get("value", "")).startswith("CWE-")), None)
        for match, context_required in _leaf_matches(cve):
            if match.get("vulnerable") is False:
                continue
            criteria = str(match.get("criteria", ""))
            parts = _split_cpe(criteria)
            if len(parts) < 6 or parts[0:2] != ["cpe", "2.3"]:
                continue
            product = parts[4]
            version = parts[5]
            rows.append({
                "vendor": parts[3],
                "product": product,
                "version": version,
                "version_start_including": match.get("versionStartIncluding"),
                "version_start_excluding": match.get("versionStartExcluding"),
                "version_end_including": match.get("versionEndIncluding"),
                "version_end_excluding": match.get("versionEndExcluding"),
                "vulnerable": match.get("vulnerable", True),
                "context_required": context_required,
                "criteria": criteria,
                "match_criteria_id": match.get("matchCriteriaId", ""),
                "cve": str(cid),
                "severity": severity,
                "summary": summary,
                "cwe": cwe,
            })
    return rows


def _nvd_metadata(data: dict) -> dict[str, str]:
    supplied = data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {}
    is_nvd = "vulnerabilities" in data
    return {
        "schema_version": str(supplied.get("schema_version") or ("NVD-2.0" if is_nvd else "normalized-unversioned")),
        "source": str(supplied.get("source") or ("NVD" if is_nvd else "local-normalized")),
        "source_url": str(supplied.get("source_url") or ("https://nvd.nist.gov/vuln/data-feeds" if is_nvd else "")),
        "api_version": str(supplied.get("api_version") or data.get("version", "")),
        "retrieved_at": str(supplied.get("retrieved_at") or data.get("timestamp", "")),
    }


def load_local_snapshot(path: str | Path) -> tuple[list[dict], dict]:
    """Load an offline snapshot and return provenance plus a content checksum."""
    raw = Path(path).read_bytes()
    data = json.loads(raw.decode("utf-8"))
    if isinstance(data, list):
        records = [x for x in data if isinstance(x, dict)]
        metadata = _nvd_metadata({})
    elif isinstance(data, dict):
        records = (records_from_nvd_json(data) if "vulnerabilities" in data
                   else [x for x in data.get("records", []) if isinstance(x, dict)])
        metadata = _nvd_metadata(data)
    else:
        records, metadata = [], _nvd_metadata({})
    metadata["sha256"] = hashlib.sha256(raw).hexdigest()
    return records, metadata


def load_local_records(path: str | Path) -> list[dict]:
    """Backward-compatible local-only reader; it never contacts a feed."""
    return load_local_snapshot(path)[0]


def correlate_technologies(
    technologies: list[dict],
    records: list[dict],
    *,
    url: str,
    source_metadata: dict | None = None,
) -> list[dict]:
    """Correlate observed products with locally supplied exact/range advisories."""
    metadata = dict(source_metadata or {})
    findings = []
    for tech in technologies:
        name = str(tech.get("name", ""))
        version = str(tech.get("version") or "")
        if not name or not version or tech.get("confidence") not in {"HIGH", "MEDIUM"}:
            continue
        for record in records:
            if _product_key(record.get("product", "")) != _product_key(name):
                continue
            if record.get("vulnerable", True) is False or not version_matches(version, record):
                continue
            cve = str(record.get("cve", record.get("id", "")))
            if not cve:
                continue
            context_required = bool(record.get("context_required", False))
            if context_required:
                # This normalizer preserves NVD AND/negation/sibling semantics
                # but does not evaluate the complete boolean CPE tree. Do not
                # promote an individual matching leaf to an advisory match.
                continue
            # A response fingerprint cannot prove the installed build, package
            # backports, or deployment configuration. Keep correlation POSSIBLE
            # until an authenticated inventory source is available.
            stage = "POSSIBLE"
            confidence = "LOW"
            finding = {
                "id": f"cve.local-correlation.{cve}",
                "name": f"Potentially applicable advisory: {cve}",
                "severity": str(record.get("severity") or "INFO").upper(),
                "confidence": confidence,
                "stage": stage,
                "url": url,
                "evidence": (
                    f"{record.get('vendor') + ' ' if record.get('vendor') else ''}{name} {version} "
                    f"matched local {metadata.get('source', 'unversioned')} advisory criteria."
                ),
                "remediation": "Verify the deployed package/build and vendor backports, then apply the fixed release or mitigation if affected.",
                "cve": cve,
                "cwe": str(record.get("cwe") or ""),
                "tags": ["cve", "offline-correlation", "version-range" if any(
                    record.get(k) for k in ("version_start_including", "version_start_excluding",
                                            "version_end_including", "version_end_excluding")
                ) else "exact-version"],
                "cve_source": metadata.get("source", "unversioned-local"),
                "cve_schema_version": metadata.get("schema_version", "normalized-unversioned"),
                "cve_retrieved_at": metadata.get("retrieved_at", ""),
                "cve_dataset_sha256": metadata.get("sha256", ""),
                "cpe_context_required": context_required,
                "fingerprint_source": str(tech.get("source", "unknown")),
                "fingerprint_confidence": str(tech.get("confidence", "LOW")),
            }
            findings.append(finding)
    return findings
