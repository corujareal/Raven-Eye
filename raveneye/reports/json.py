import json
def render(target, findings): return json.dumps({'version':'6.6.6','target':target,'findings':list(findings)},ensure_ascii=False,indent=2)
