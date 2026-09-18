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
