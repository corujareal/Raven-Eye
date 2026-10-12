from raveneye.scanner.safe_vuln_checks import inspect_categories


FIXTURES = [
    (
        'sqli.error-indicator', True, 'You have an error in your SQL syntax near FROM', {},
    ),
    (
        'sqli.error-indicator', False, 'This service stores records in MySQL.', {},
    ),
    (
        'cmdi.execution-indicator', True, 'sh: archive.sh: command not found', {},
    ),
    (
        'cmdi.execution-indicator', False, 'PowerShell and child_process are runtime APIs.', {},
    ),
    (
        'directory-traversal.file-indicator', True, 'root:x:0:0:root:/root:/bin/bash', {},
    ),
    (
        'directory-traversal.file-indicator', False,
        'A directory traversal guide mentions /etc/passwd and missing paths.', {},
    ),
    (
        'xxe.xml-indicator', True, 'XML parser error: failed to load external entity',
        {'Content-Type': 'application/xml'},
    ),
    (
        'xxe.xml-indicator', False, 'DOCTYPE and external entities are covered in this guide.',
        {'Content-Type': 'application/xml'},
    ),
    (
        'xss.dom-source-sink-indicator', True,
        "<script>const q=location.search; document.querySelector('#x').innerHTML=q;</script>", {},
    ),
    (
        'xss.dom-source-sink-indicator', False,
        "<script>const version=1; alert('static')</script><img onerror='handle()'>", {},
    ),
    (
        'ldap.error-indicator', True,
        'javax.naming.InvalidNameException: invalid DN syntax', {},
    ),
    (
        'ldap.error-indicator', False, 'This guide explains LDAP query syntax.', {},
    ),
]


def test_labeled_safe_category_signatures():
    for finding_id, expected, body, headers in FIXTURES:
        findings = inspect_categories(
            'https://fixture.test/', 200, headers, body,
        )
        observed = finding_id in {finding.id for finding in findings}
        assert observed is expected, (finding_id, expected, body)

    categories = {finding_id for finding_id, _expected, _body, _headers in FIXTURES}
    for finding_id in categories:
        cases = [case for case in FIXTURES if case[0] == finding_id]
        true_positive = false_positive = false_negative = 0
        for _id, expected, body, headers in cases:
            observed = finding_id in {
                finding.id for finding in inspect_categories('https://fixture.test/', 200, headers, body)
            }
            true_positive += bool(expected and observed)
            false_positive += bool(not expected and observed)
            false_negative += bool(expected and not observed)
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
        assert precision == 1.0
        assert recall == 1.0
