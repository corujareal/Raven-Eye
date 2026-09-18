from __future__ import annotations
import csv, io
def render(findings):
    out=io.StringIO(); w=csv.writer(out); w.writerow(["severity","confidence","name","url","cwe","cve","remediation","evidence"])
    for f in findings: w.writerow([f.get("severity","INFO"),f.get("confidence","MEDIUM"),f.get("name",""),f.get("url",""),f.get("cwe",""),f.get("cve",""),str(f.get("remediation",""))[:500],str(f.get("evidence",""))[:500]])
    return out.getvalue()
