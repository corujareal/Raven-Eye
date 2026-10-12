import json
from ..scanner.evidence import sanitize_url

def render(target, findings):
    safe_findings = []
    for finding in findings:
        item = dict(finding)
        if item.get('url'):
            item['url'] = sanitize_url(item['url'])
        item['evidence'] = str(item.get('evidence', ''))[:500]
        safe_findings.append(item)
    return json.dumps({'version':'6.6.6','target':sanitize_url(target) or target,
                       'findings':safe_findings},ensure_ascii=False,indent=2)
