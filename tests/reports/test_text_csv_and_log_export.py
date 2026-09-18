from raveneye.reports.txt import render,risk_score
from raveneye.reports.csv import render as csv_render
from raveneye.database.repository import ScanRepository
from raveneye.cli.log_viewer import export_category
import json

def test_report_and_score(tmp_path):
    fs=[{'name':'A','severity':'CRITICAL','confidence':'HIGH','url':'https://example.test','evidence':'x'*700,'remediation':'fix'}]
    t=render('example.test',fs); assert 'RAVENEYE v6.6.6' in t and '10.0/10' in t and len(t)>0
    assert 'CRITICAL' in csv_render(fs)

def test_repo(tmp_path):
    p=tmp_path/'db.sqlite'; r=ScanRepository(p); sid=r.save_scan('example.test',[{'name':'A','severity':'HIGH','confidence':'HIGH','url':'u'}],7.0); assert sid==1

def test_log_export(tmp_path):
    p=tmp_path/'log.jsonl'; p.write_text(json.dumps({'category':'scanner','x':1})+'\n'+json.dumps({'category':'crawler','x':2})+'\n')
    out=tmp_path/'o.jsonl'; export_category(p,'scanner',out); assert 'scanner' in out.read_text() and 'crawler' not in out.read_text()
