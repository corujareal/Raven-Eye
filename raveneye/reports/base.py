from __future__ import annotations
WEIGHTS={'CRITICAL':10,'HIGH':7,'MEDIUM':4,'LOW':1,'INFO':0}
def risk_score(findings):
    fs=list(findings)
    if not fs: return 0.0
    weighted=sum(WEIGHTS.get(str(f.get('severity','INFO')).upper(),0) for f in fs)
    # Diminishing returns: many low findings should not automatically become critical.
    return round(min(10.0, weighted / max(1, len(fs)) + min(2.0, len([f for f in fs if str(f.get('severity','')).upper() in {'CRITICAL','HIGH'}]) * .25)),1)
