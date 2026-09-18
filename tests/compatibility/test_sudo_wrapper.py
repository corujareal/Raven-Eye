from pathlib import Path

def test_installer_configures_sudo_wrapper_automatically_in_one_run():
    text = Path("installer/install.sh").read_text(encoding="utf-8")
    assert "sudo" in text
    assert "/usr/local/bin" in text
    # O instalador simplificado não expõe mais um modo/flag separado para
    # configurar o wrapper global; tudo acontece numa única execução.
    assert "--system-wrapper" not in text
    assert "--minimal" not in text
    assert "--no-sudo-wrapper" not in text

def test_nuke_initializes_root_mode_before_execution():
    text = Path("raveneye_pkg/menus.py").read_text(encoding="utf-8")
    marker = 'root_mode = choice in ("1", "3")'
    assert marker in text
