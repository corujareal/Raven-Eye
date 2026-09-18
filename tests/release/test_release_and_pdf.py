from pathlib import Path
import subprocess, sys

def test_build_release_help_and_output_option():
    root = Path(__file__).resolve().parents[2]
    script = root / 'scripts' / 'build_release.py'
    help_result = subprocess.run([sys.executable, str(script), '--help'], capture_output=True, text=True, check=True)
    assert '--output' in help_result.stdout
