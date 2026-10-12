from raveneye.scanner.endpoint_checks import inspect_endpoint
from raveneye.crawler.security_txt import parse_security_txt, validate_security_txt
from raveneye.scanner.api_security import inspect_operations


def test_security_txt_parser_and_validation():
    data=parse_security_txt('Contact: mailto:security@example.test\nPolicy: https://example.test/policy\n')
    assert data['contact'] == ['mailto:security@example.test']
    assert validate_security_txt('Contact: x\nPolicy: y\n') == []


def test_endpoint_sensitive_reference_is_advisory():
    findings=inspect_endpoint('https://example.test/api/users', parameters=['user_id'])
    assert findings and findings[0]['id']=='api-object-reference-review'
    assert findings[0]['severity']=='INFO'


def test_openapi_operations():
    spec={'security':[{'bearerAuth':[]}], 'paths':{
        '/users/{id}': {'get': {'parameters':[{'name':'id'}], 'security':[]}}
    }}
    findings=inspect_operations(spec,'https://example.test')
    ids={f['id'] for f in findings}
    assert 'openapi-operation-security-empty' in ids
    assert 'api-object-reference-review' in ids
