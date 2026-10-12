from __future__ import annotations
import csv, io
from ..scanner.evidence import sanitize_url
def render(findings):
    out=io.StringIO(); w=csv.writer(out); w.writerow(["severity","stage","confidence","confidence_score","name","url","cwe","cve","remediation","evidence","observed_at","request_sha256","response_sha256","baseline_sha256"])
    for f in findings:
        metadata=f.get("evidence_metadata") or {}
        w.writerow([f.get("severity","INFO"),f.get("stage","POSSIBLE"),f.get("confidence","MEDIUM"),f.get("confidence_score",0),f.get("name",""),sanitize_url(f.get("url","")),f.get("cwe",""),f.get("cve",""),str(f.get("remediation",""))[:500],str(f.get("evidence",""))[:500],metadata.get("observed_at",""),(metadata.get("request") or {}).get("sha256",""),(metadata.get("response") or {}).get("sha256",""),(metadata.get("baseline") or {}).get("sha256","")])
    return out.getvalue()
