from __future__ import annotations
from dataclasses import dataclass, field
@dataclass
class FindingRecord:
    target:str
    name:str
    severity:str
    confidence:str
    url:str
    evidence:str=''
    remediation:str=''
    cwe:str=''
    cve:str=''
    stage:str='POSSIBLE'
    confidence_score:int=0
    observed_at:str=''
    source:str=''
    request_sha256:str=''
    response_sha256:str=''
    baseline_sha256:str=''
    evidence_metadata:dict=field(default_factory=dict)
