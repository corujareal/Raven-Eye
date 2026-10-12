from pathlib import Path
from raveneye.reports.pdf import render_pdf
from raveneye.cli.log_viewer import export_category
from PIL import Image as PILImage
import json


def test_pdf_report_renders(tmp_path):
    out = tmp_path / 'report.pdf'
    render_pdf({
        'target': {'domain': 'authorized.example', 'ip': '192.0.2.10'},
        'findings': [
            {'name': 'Example finding', 'severity': 'HIGH', 'confidence': 'HIGH',
             'url': 'https://authorized.example/test',
             'description': 'Synthetic test finding.',
             'evidence': 'safe evidence',
             'remediation': 'Apply the documented fix.'}
        ],
        'endpoints': ['/api/example'],
    }, str(out))
    assert out.exists() and out.stat().st_size > 2000
    assert out.read_bytes().startswith(b'%PDF')


def test_log_export_pdf(tmp_path):
    src = tmp_path / 'raveneye.log'
    src.write_text(json.dumps({'category':'scanner','severity':'HIGH','event':'synthetic'})+'\n', encoding='utf-8')
    out = export_category(str(src), 'scanner', str(tmp_path / 'events.pdf'))
    assert out.exists() and out.read_bytes().startswith(b'%PDF')


def test_pdf_embeds_local_evidence_image(tmp_path):
    image = tmp_path / 'evidence.png'
    PILImage.new('RGB', (320, 180), (20, 10, 30)).save(image)
    out = tmp_path / 'visual.pdf'
    render_pdf({'target': {'domain': 'authorized.example'}, 'findings': [], 'screenshots': [str(image)]}, str(out))
    assert out.exists() and out.stat().st_size > 2500


def test_pdf_renders_vpn_route_dork_responses_and_stages(tmp_path):
    out = tmp_path / "vpn-report.pdf"
    render_pdf({
        "target": {"domain": "authorized.example"},
        "findings": [
            {"name": "Confirmed configuration", "severity": "HIGH", "stage": "CONFIRMED", "confidence": "HIGH",
             "confidence_score": 92, "url": "https://authorized.example/security", "description": "Fixture-backed observation."},
            {"name": "Possible reflection", "severity": "INFO", "stage": "POSSIBLE", "confidence": "LOW",
             "url": "https://authorized.example/search?q=%5Bredacted%5D", "description": "Candidate requiring review."},
        ],
        "google_dorks": ["private query must not be copied"],
        "google_dorks_results": {
            "provider": "SearXNG local (Docker)", "dorks_executados": 1, "total_bruto": 2,
            "total_em_escopo": 1, "total_interessantes": 1,
            "interessantes": [{
                "titulo": "Fixture search result", "link": "https://authorized.example/.env",
                "snippet": "Sanitized response from the local engine", "provider": "SearXNG local (Docker)",
                "confidence": "alta", "score": 6, "motivo": "arquivo potencialmente sensível",
                "evidencias": ["extensão ou caminho sensível na URL"], "confirmed": False,
            }],
        },
        "asset_intelligence": {"netlas": {"status": "connected", "http_status": 200, "message": "Fixture status"}},
        "surface": {"urls": 12, "endpoints": 4, "javascript_files": 2,
                    "javascript_route_templates": 1, "crawl_errors": 1},
        "javascript_route_templates": ["https://authorized.example/api/users/{param}"],
        "surface_hints": [{"category": "backup_files", "url": "https://authorized.example/db.bak"}],
        "secrets_js": [{"tipo": "API key pattern", "url": "https://authorized.example/app.js", "valor": "RAW_JS_SECRET_SENTINEL"}],
    }, str(out))
    assert out.exists() and out.stat().st_size > 2500
    assert out.read_bytes().startswith(b"%PDF")
