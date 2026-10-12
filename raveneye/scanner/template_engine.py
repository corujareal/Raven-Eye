from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from ..core.logger import redact
from .engine import Finding
from .evidence import STAGES

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is declared by the package
    yaml = None

_ROOT_KEYS = {"schema_version", "id", "info", "matchers-condition", "matchers", "extractors"}
_INFO_KEYS = {"name", "severity", "confidence", "stage", "description",
              "remediation", "tags", "cwe", "cve", "references"}
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}
_CONDITIONS = {"and", "or"}
_PARTS = {"all", "body", "header"}
_MAX_FILE_BYTES = 65536
_MAX_REGEX_CHARS = 256
_MAX_MATCHERS = 12
_MAX_VALUES = 12
_MAX_EVIDENCE_CHARS = 500


class TemplateValidationError(ValueError):
    """A local passive template is invalid or unsupported."""


if yaml is not None:
    class _UniqueKeyLoader(yaml.SafeLoader):
        pass

    def _construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise TemplateValidationError(f"duplicate YAML key: {key}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    _UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
    )


def _validate_regex(pattern: Any) -> str:
    if not isinstance(pattern, str) or not pattern or len(pattern) > _MAX_REGEX_CHARS:
        raise TemplateValidationError("regex must be a non-empty string up to 256 characters")
    # Python's backtracking regex engine has no execution timeout. The passive DSL
    # rejects quantified groups/alternations to avoid common catastrophic patterns.
    unescaped = re.sub(r"\\.", "", pattern)
    unbounded = re.findall(r"(?<![?\\])(?:[*+]|\{\d+,\})", unescaped)
    wildcards = re.findall(r"\.[*+]", unescaped)
    if (
        re.search(r"\)[+*{]", pattern)
        or re.search(r"\([^)]*[+*{][^)]*\)[+*{]", pattern)
        or len(unbounded) > 8
        or len(wildcards) > 1
    ):
        raise TemplateValidationError("quantified groups/alternations are not supported")
    try:
        re.compile(pattern, re.I | re.M)
    except re.error as exc:
        raise TemplateValidationError(f"invalid regex: {exc}") from exc
    return pattern


def _validate_template(data: Any) -> dict:
    if not isinstance(data, dict):
        raise TemplateValidationError("template root must be a mapping")
    unknown = set(data) - _ROOT_KEYS
    if unknown:
        raise TemplateValidationError(f"unsupported root fields: {', '.join(sorted(map(str, unknown)))}")
    if data.get("schema_version") != "1.0":
        raise TemplateValidationError("schema_version must be '1.0'")
    template_id = data.get("id")
    if not isinstance(template_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,95}", template_id):
        raise TemplateValidationError("id must be unique lowercase text (1–96 chars)")

    info = data.get("info")
    if not isinstance(info, dict):
        raise TemplateValidationError("info must be a mapping")
    unknown_info = set(info) - _INFO_KEYS
    if unknown_info:
        raise TemplateValidationError(f"unsupported info fields: {', '.join(sorted(map(str, unknown_info)))}")
    if not isinstance(info.get("name"), str) or not info["name"].strip():
        raise TemplateValidationError("info.name is required")
    if str(info.get("severity", "INFO")).upper() not in _SEVERITIES:
        raise TemplateValidationError("info.severity must be CRITICAL/HIGH/MEDIUM/LOW/INFO")
    if str(info.get("confidence", "LOW")).upper() not in _CONFIDENCE:
        raise TemplateValidationError("info.confidence must be HIGH/MEDIUM/LOW")
    stage = str(info.get("stage", "POSSIBLE")).upper()
    if stage not in {"POSSIBLE", "PROBABLE"}:
        raise TemplateValidationError("templates may declare only POSSIBLE or PROBABLE; they cannot confirm a vulnerability")
    tags = info.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 32 or any(not isinstance(x, str) for x in tags):
        raise TemplateValidationError("info.tags must be a list of at most 32 strings")

    condition = str(data.get("matchers-condition", "or")).lower()
    if condition not in _CONDITIONS:
        raise TemplateValidationError("matchers-condition must be and/or")
    matchers = data.get("matchers")
    if not isinstance(matchers, list) or not 1 <= len(matchers) <= _MAX_MATCHERS:
        raise TemplateValidationError("matchers must contain 1–12 matcher mappings")
    for matcher in matchers:
        if not isinstance(matcher, dict):
            raise TemplateValidationError("each matcher must be a mapping")
        if set(matcher) - {"type", "words", "regex", "status", "condition", "negative", "part"}:
            raise TemplateValidationError("matcher contains unsupported fields")
        typ = str(matcher.get("type", "")).lower()
        part = str(matcher.get("part", "all")).lower()
        if part not in _PARTS:
            raise TemplateValidationError("matcher part must be all/body/header")
        if str(matcher.get("condition", "or")).lower() not in _CONDITIONS:
            raise TemplateValidationError("matcher condition must be and/or")
        if not isinstance(matcher.get("negative", False), bool):
            raise TemplateValidationError("matcher negative must be boolean")
        if typ in {"word", "regex"}:
            field = "words" if typ == "word" else "regex"
            values = matcher.get(field)
            if not isinstance(values, list) or not 1 <= len(values) <= _MAX_VALUES:
                raise TemplateValidationError(f"{field} must contain 1–12 values")
            if typ == "word" and any(not isinstance(x, str) or not x for x in values):
                raise TemplateValidationError("words must be non-empty strings")
            if typ == "regex":
                matcher[field] = [_validate_regex(x) for x in values]
        elif typ == "status":
            values = matcher.get("status")
            if not isinstance(values, list) or not 1 <= len(values) <= _MAX_VALUES:
                raise TemplateValidationError("status must contain 1–12 HTTP status codes")
            if any(not isinstance(x, int) or x < 100 or x > 599 for x in values):
                raise TemplateValidationError("status values must be HTTP codes 100–599")
        else:
            raise TemplateValidationError("matcher type must be word/regex/status")

    extractors = data.get("extractors", [])
    if not isinstance(extractors, list) or len(extractors) > 4:
        raise TemplateValidationError("extractors must be a list of at most four items")
    for extractor in extractors:
        if not isinstance(extractor, dict) or set(extractor) - {"type", "regex", "keys"}:
            raise TemplateValidationError("extractor contains unsupported fields")
        typ = str(extractor.get("type", "regex")).lower()
        if typ == "regex":
            values = extractor.get("regex")
            if not isinstance(values, list) or not 1 <= len(values) <= 4:
                raise TemplateValidationError("extractor regex must contain 1–4 patterns")
            extractor["regex"] = [_validate_regex(x) for x in values]
        elif typ == "kval":
            keys = extractor.get("keys")
            if not isinstance(keys, list) or not 1 <= len(keys) <= 8 or any(not isinstance(x, str) for x in keys):
                raise TemplateValidationError("kval keys must contain 1–8 strings")
        else:
            raise TemplateValidationError("extractor type must be regex/kval")
    return data


class TemplateEngine:
    """Versioned local DSL that matches already collected responses only."""

    def __init__(self, directory="raveneye/scanner/templates"):
        self.directory = Path(directory)
        self.errors: list[dict[str, str]] = []

    def load(self) -> list[dict]:
        self.errors = []
        if not self.directory.exists():
            return []
        if yaml is None:
            raise RuntimeError("PyYAML is required to load scanner templates")
        templates = []
        seen: set[str] = set()
        for path in sorted(self.directory.glob("*.y*ml")):
            try:
                raw = path.read_bytes()
                if len(raw) > _MAX_FILE_BYTES:
                    raise TemplateValidationError("template exceeds 65536 bytes")
                data = yaml.load(raw.decode("utf-8"), Loader=_UniqueKeyLoader)
                data = _validate_template(data)
                if data["id"] in seen:
                    raise TemplateValidationError(f"duplicate template id: {data['id']}")
                seen.add(data["id"])
                templates.append(data)
            except (OSError, UnicodeError, yaml.YAMLError, TemplateValidationError) as exc:
                self.errors.append({"file": path.name, "error": str(exc)[:300]})
        return templates

    @staticmethod
    def _part_text(part, body, headers):
        header_text = "\n".join(f"{key}: {value}" for key, value in headers.items())
        if part == "body":
            return body
        if part == "header":
            return header_text
        return (body + "\n" + header_text)[:200000]

    @staticmethod
    def _match(matcher: dict, body: str, headers: dict, status=None):
        typ = str(matcher.get("type", "word")).lower()
        negative = bool(matcher.get("negative", False))
        text = TemplateEngine._part_text(str(matcher.get("part", "all")).lower(), body, headers)[:20000]
        condition = str(matcher.get("condition", "or")).lower()
        if typ == "word":
            values = [str(x) for x in matcher.get("words", [])]
            states = [value.lower() in text.lower() for value in values]
        elif typ == "regex":
            values = [str(x) for x in matcher.get("regex", [])]
            states = [re.search(value, text, re.I | re.M) is not None for value in values]
        elif typ == "status":
            values = [str(x) for x in matcher.get("status", [])]
            states = [str(status) == value for value in values]
        else:
            return False, ""
        matched = all(states) if condition == "and" else any(states)
        if negative:
            matched = not matched
        # Record a description, never a matched response fragment or secret.
        return matched, f"{typ}:{len(states)} condition(s)"

    @staticmethod
    def _extract(extractor: dict, body: str, headers: dict) -> list[str]:
        text = (body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()))[:20000]
        typ = str(extractor.get("type", "regex")).lower()
        if typ == "regex":
            out = []
            for pattern in extractor.get("regex", []):
                out.extend(m.group(1) if m.groups() else m.group(0)
                           for m in re.finditer(str(pattern), text, re.I | re.M))
            return out[:8]
        if typ == "kval":
            out = []
            for key in extractor.get("keys", []):
                hit = re.search(rf"(?im)^\s*{re.escape(str(key))}\s*[:=]\s*(.+?)\s*$", text)
                if hit:
                    out.append(f"{key}={hit.group(1)}")
            return out[:8]
        return []

    def match(self, template, response_text="", headers=None, url="", status=None):
        # Direct callers keep the original API, but now receive the same schema
        # and regex safety checks as templates loaded from disk.
        template = dict(template or {})
        template.setdefault("schema_version", "1.0")
        _validate_template(template)
        headers = {str(k): str(v) for k, v in (headers or {}).items()}
        body = str(response_text or "")[:200000]
        info = template.get("info") or {}
        matchers = template.get("matchers") or []
        if not isinstance(matchers, list) or not matchers:
            return []
        results = [self._match(m, body, headers, status) for m in matchers]
        selected = [item for item in results if item[0]]
        condition = str(template.get("matchers-condition", "or")).lower()
        overall = all(item[0] for item in results) if condition == "and" else any(item[0] for item in results)
        if not overall:
            return []
        evidence = "; ".join(item[1] for item in selected)[:_MAX_EVIDENCE_CHARS]
        extracts = []
        for extractor in template.get("extractors") or []:
            extracts.extend(self._extract(extractor, body, headers))
        if extracts:
            summaries = [f"value redacted (length={len(value)})" for value in extracts[:8]]
            evidence = redact(evidence + " | extracted: " + ", ".join(summaries))[:_MAX_EVIDENCE_CHARS]
        stage = str(info.get("stage", "POSSIBLE")).upper()
        if stage not in {"POSSIBLE", "PROBABLE"}:
            stage = "POSSIBLE"
        finding = Finding(
            template.get("id", "unknown"),
            str(info.get("name", "template")),
            str(info.get("severity", "INFO")).upper(),
            str(info.get("confidence", "LOW")).upper(),
            url,
            evidence,
            str(info.get("remediation", "Review the finding and apply vendor guidance.")),
            list(info.get("tags", []) or []),
            str(info.get("cwe", "")),
            str(info.get("cve", "")),
            stage=stage,
        )
        return [finding]
