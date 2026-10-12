from raveneye.scanner.passive_checks import scan_headers


def test_labeled_debug_and_private_address_fixtures():
    fixtures = [
        {
            'label': 'debug',
            'expected': True,
            'body': 'Traceback (most recent call last): internal error',
            'finding_id': 'debug-information-disclosure',
        },
        {
            'label': 'debug',
            'expected': False,
            'body': 'Laravel and Django are frameworks; this page describes debug settings.',
            'finding_id': 'debug-information-disclosure',
        },
        {
            'label': 'private_ip',
            'expected': True,
            'body': 'Internal service: 10.0.0.5.',
            'finding_id': 'private-address-disclosure',
        },
        {
            'label': 'private_ip',
            'expected': False,
            'body': 'Example value: 192.168.999.999; public: 203.0.113.8.',
            'finding_id': 'private-address-disclosure',
        },
    ]

    for fixture in fixtures:
        findings = scan_headers('https://fixture.test/', {}, fixture['body'])
        observed = fixture['finding_id'] in {finding.id for finding in findings}
        assert observed is fixture['expected'], fixture

    for label in ('debug', 'private_ip'):
        cases = [fixture for fixture in fixtures if fixture['label'] == label]
        true_positive = sum(
            fixture['expected'] and fixture['finding_id'] in {
                finding.id for finding in scan_headers('https://fixture.test/', {}, fixture['body'])
            }
            for fixture in cases
        )
        false_positive = sum(
            not fixture['expected'] and fixture['finding_id'] in {
                finding.id for finding in scan_headers('https://fixture.test/', {}, fixture['body'])
            }
            for fixture in cases
        )
        false_negative = sum(
            fixture['expected'] and fixture['finding_id'] not in {
                finding.id for finding in scan_headers('https://fixture.test/', {}, fixture['body'])
            }
            for fixture in cases
        )
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
        assert precision == 1.0
        assert recall == 1.0


def test_phpinfo_exposure_requires_multiple_specific_markers_and_redacts_body():
    fixtures = [
        (
            True,
            '<html><head><title>phpinfo()</title></head><body>'
            '<h1>PHP Version 8.3.1</h1><table><tr><td>Loaded Configuration File</td>'
            '<td>/etc/php/8.3/fpm/php.ini</td></tr></table></body></html>',
        ),
        (
            False,
            '<html><title>PHP configuration guide</title><body>'
            'The phpinfo() function can display PHP Version and Loaded Configuration File. '
            'See the manual for details.</body></html>',
        ),
    ]
    finding_id = 'phpinfo-page-exposed'
    observations = []
    for expected, body in fixtures:
        findings = scan_headers('https://fixture.test/', {'Content-Type': 'text/html'}, body)
        match = next((finding for finding in findings if finding.id == finding_id), None)
        observed = match is not None
        assert observed is expected, body
        if match:
            assert '/etc/php/8.3/fpm/php.ini' not in match.evidence
            observations.append(match)

    assert len(observations) == 1
    assert observations[0].severity == 'LOW'
    assert observations[0].confidence == 'MEDIUM'
    true_positive = sum(expected and any(f.id == finding_id for f in scan_headers(
        'https://fixture.test/', {'Content-Type': 'text/html'}, body,
    )) for expected, body in fixtures)
    false_positive = sum(not expected and any(f.id == finding_id for f in scan_headers(
        'https://fixture.test/', {'Content-Type': 'text/html'}, body,
    )) for expected, body in fixtures)
    false_negative = sum(expected and not any(f.id == finding_id for f in scan_headers(
        'https://fixture.test/', {'Content-Type': 'text/html'}, body,
    )) for expected, body in fixtures)
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
    assert precision == recall == 1.0


def test_directory_listing_requires_generated_index_structure():
    fixtures = [
        (
            True,
            '<!doctype html><title>Index of /archive/</title><h1>Index of /archive/</h1>'
            '<table><tr><td><a href="../">Parent Directory</a></td></tr></table>',
        ),
        (
            False,
            '<html><title>Help</title><body>'
            'This manual explains the phrase "Index of /" and directory listing risks.'
            '</body></html>',
        ),
        (
            False,
            '<html><title>Index of /guide</title><body>'
            'Documentation uses this heading but exposes no generated directory links.'
            '</body></html>',
        ),
    ]
    observed = [
        any(f.id == 'directory-listing' for f in scan_headers(
            'https://fixture.test/', {'Content-Type': 'text/html'}, body,
        ))
        for _expected, body in fixtures
    ]
    expected = [item[0] for item in fixtures]
    assert observed == expected
    true_positive = sum(want and got for want, got in zip(expected, observed))
    false_positive = sum(not want and got for want, got in zip(expected, observed))
    false_negative = sum(want and not got for want, got in zip(expected, observed))
    assert true_positive / (true_positive + false_positive) == 1.0
    assert true_positive / (true_positive + false_negative) == 1.0


def test_credentialed_cors_wildcard_is_reported_as_browser_rejected_configuration():
    findings = scan_headers('https://fixture.test/api', {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
    })
    finding = next(item for item in findings if item.id == 'cors.invalid-credentialed-wildcard')
    assert finding.stage == 'CONFIRMED'
    assert finding.severity == 'INFO'
    assert 'reject' in finding.evidence.lower()
