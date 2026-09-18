from __future__ import annotations
from dataclasses import dataclass
@dataclass
class FindingRecord:
    target:str; name:str; severity:str; confidence:str; url:str; evidence:str=''; remediation:str=''; cwe:str=''; cve:str=''
