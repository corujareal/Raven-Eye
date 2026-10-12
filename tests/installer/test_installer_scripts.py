from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import pytest


ROOT = Path(__file__).resolve().parents[2]


def _env(tmp_path: Path) -> dict[str, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    sudo_log = tmp_path / "sudo.log"
    sudo = fake_bin / "sudo"
    sudo.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$SUDO_LOG"\nexec "$@"\n',
        encoding="utf-8",
    )
    sudo.chmod(0o755)
    tools_bin = tmp_path / "system-tools"
    tools_bin.mkdir()
    for tool in (
        "sh", "env", "dirname", "sed", "head", "uname", "id", "tar",
        "mktemp", "find", "mkdir", "rm", "rmdir", "cp", "mv", "grep",
        "chmod", "cat",
    ):
        executable = shutil.which(tool)
        if executable:
            (tools_bin / tool).symlink_to(executable)
    fake_python = tmp_path / "fake-python"
    fake_python.write_text(
        '#!/bin/sh\n'
        'if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then printf "%s\\n" "$*" >> "$PYTHON_LOG"; requirement_file=0; for argument in "$@"; do if [ "$requirement_file" = 1 ]; then cat "$argument" >> "$PIP_REQUIREMENTS_LOG"; requirement_file=0; elif [ "$argument" = "-r" ]; then requirement_file=1; fi; done; exit 0; fi\n'
        'if [ "${1:-}" = "-m" ] && [ "${2:-}" = "playwright" ]; then printf "%s\\n" "$*" >> "$PYTHON_LOG"; exit 0; fi\n'
        'if [ "${1:-}" = "-c" ]; then case "${2:-}" in *"chromium_runtime_smoke"*) if [ "${FAIL_BROWSER_SMOKE:-0}" = "1" ]; then exit 47; fi ;; esac; printf "%s\\n" "$*" >> "$PYTHON_LOG"; exit 0; fi\n'
        'case "${1:-}" in "$RAVENEYE_LIB_DIR"/.raveneye-source.*/RavenEye.py|"$RAVENEYE_LIB_DIR"/RavenEye.py) if [ "${2:-}" = "--version" ]; then echo "RavenEye 6.6.6"; exit 0; fi ;; esac\n'
        'exec "$REAL_PYTHON" "$@"\n',
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    env = os.environ.copy()
    env.update({
        "HOME": str(tmp_path / "home"),
        # Keep package managers out of the default fake environment so tests
        # can never alter the host OS. Individual cases add a fake manager.
        "PATH": str(fake_bin) + os.pathsep + str(tools_bin),
        "PYTHON": str(fake_python),
        "REAL_PYTHON": sys.executable,
        "PYTHON_LOG": str(tmp_path / "python.log"),
        "PIP_REQUIREMENTS_LOG": str(tmp_path / "pip-requirements.log"),
        "RAVENEYE_BIN_DIR": str(tmp_path / "home" / ".local" / "bin"),
        "RAVENEYE_LIB_DIR": str(tmp_path / "home" / ".local" / "share" / "raveneye"),
        "RAVENEYE_SYSTEM_BIN_DIR": str(tmp_path / "system-bin"),
        "SUDO_LOG": str(sudo_log),
        "TMPDIR": str(tmp_path),
    })
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=unknown\nPRETTY_NAME="Test Unix"\n', encoding="utf-8")
    env["RAVENEYE_OS_RELEASE_FILE"] = str(os_release)
    return env


def _configure_fake_system_chromium(tmp_path: Path, env: dict[str, str]) -> Path:
    fake_bin = Path(env["PATH"].split(os.pathsep)[0])
    chromium = fake_bin / "chromium"
    stub = tmp_path / "chromium.stub"
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    env["CHROMIUM_STUB"] = str(stub)
    env["SYSTEM_CHROMIUM_PATH"] = str(chromium)
    return chromium


def _run(script: str, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(ROOT / "installer" / script), *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )


def test_install_dry_run_has_no_files_or_sudo_calls(tmp_path):
    env = _env(tmp_path)
    result = _run("install.sh", env, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert "Modo dry-run" in result.stdout
    assert not Path(env["RAVENEYE_BIN_DIR"]).exists()
    assert not Path(env["RAVENEYE_LIB_DIR"]).exists()
    assert not Path(env["RAVENEYE_SYSTEM_BIN_DIR"]).exists()
    assert not Path(env["SUDO_LOG"]).exists()


def test_termux_dry_run_reports_static_mode_without_installing_packages(tmp_path):
    env = _env(tmp_path)
    env["PREFIX"] = "/data/data/com.termux/files/usr"
    env["TERMUX_VERSION"] = "0.118"
    pkg_log = tmp_path / "pkg.log"
    pkg = Path(env["PATH"].split(os.pathsep)[0]) / "pkg"
    pkg.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$PKG_LOG"\nexit 0\n', encoding="utf-8")
    pkg.chmod(0o755)
    env["PKG_LOG"] = str(pkg_log)

    result = _run("install.sh", env, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert "Ambiente: Termux" in result.stdout
    assert "runtime estático" in result.stdout or "headless é opcional" in result.stdout
    assert not pkg_log.exists()


def test_termux_install_filters_uvloop_and_skips_unsupported_headless(tmp_path):
    env = _env(tmp_path)
    prefix = str(tmp_path / "data" / "data" / "com.termux" / "files" / "usr")
    env["PREFIX"] = prefix
    env["TERMUX_VERSION"] = "0.118"
    env.pop("RAVENEYE_BIN_DIR")
    env.pop("RAVENEYE_LIB_DIR")
    pkg_log = tmp_path / "pkg.log"
    pkg = Path(env["PATH"].split(os.pathsep)[0]) / "pkg"
    pkg.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$PKG_LOG"\nexit 0\n',
        encoding="utf-8",
    )
    pkg.chmod(0o755)
    env["PKG_LOG"] = str(pkg_log)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    assert pkg_log.read_text(encoding="utf-8").splitlines() == [
        "install -y clang make pkg-config rust openssl libffi libxml2 libxslt "
        "libjpeg-turbo libpng freetype libwebp littlecms"
    ]
    requirements = Path(env["PIP_REQUIREMENTS_LOG"]).read_text(encoding="utf-8")
    assert not re.search(r"(?m)^uvloop[><=~]", requirements)
    python_calls = Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")
    assert "-m playwright install chromium" not in python_calls
    assert "chromium_runtime_smoke" not in python_calls
    assert Path(prefix, "bin", "raven").is_file()
    assert Path(prefix, "share", "raveneye", ".raveneye-install").is_file()
    assert not Path(env["RAVENEYE_SYSTEM_BIN_DIR"], "raven").exists()
    assert "Termux não usa o Chromium Linux do Playwright" in result.stderr


def test_install_is_repeatable_and_launcher_sidecar_points_to_library(tmp_path):
    env = _env(tmp_path)
    for _ in range(2):
        result = _run("install.sh", env)
        assert result.returncode == 0, result.stderr
    bin_dir = Path(env["RAVENEYE_BIN_DIR"])
    lib_dir = Path(env["RAVENEYE_LIB_DIR"])
    system_dir = Path(env["RAVENEYE_SYSTEM_BIN_DIR"])
    assert (lib_dir / ".raveneye-install").read_text(encoding="utf-8").startswith("RavenEye")
    assert not (lib_dir / "raveneye.log").exists()
    assert (bin_dir / "raven.home").read_text(encoding="utf-8").strip() == str(lib_dir)
    assert (system_dir / "raven.home").read_text(encoding="utf-8").strip() == str(lib_dir)
    result = subprocess.run([str(bin_dir / "raven"), "--version"], env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    calls = Path(env["SUDO_LOG"]).read_text(encoding="utf-8").splitlines()
    assert len(calls) == 10
    python_calls = Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")
    assert python_calls.count("-m pip install") == 2
    assert python_calls.count("-m playwright install chromium\n") == 2


def test_arch_installs_native_chromium_with_pacman_and_never_calls_apt(tmp_path):
    env = _env(tmp_path)
    Path(env["RAVENEYE_OS_RELEASE_FILE"]).write_text('ID=archcraft\nID_LIKE=arch\n', encoding="utf-8")
    fake_bin = Path(env["PATH"].split(os.pathsep)[0])
    _configure_fake_system_chromium(tmp_path, env)
    pacman_log = tmp_path / "pacman.log"
    pacman = fake_bin / "pacman"
    pacman.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$PACMAN_LOG"\ncp "$CHROMIUM_STUB" "$SYSTEM_CHROMIUM_PATH"\nchmod +x "$SYSTEM_CHROMIUM_PATH"\nexit "${PACMAN_EXIT_CODE:-0}"\n',
        encoding="utf-8",
    )
    pacman.chmod(0o755)
    apt_log = tmp_path / "apt.log"
    apt = fake_bin / "apt-get"
    apt.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$APT_LOG"\nexit 0\n', encoding="utf-8")
    apt.chmod(0o755)
    env["PACMAN_LOG"] = str(pacman_log)
    env["APT_LOG"] = str(apt_log)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    calls = pacman_log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 1
    assert calls[0] == "-S --needed chromium"
    assert Path(env["SYSTEM_CHROMIUM_PATH"]).is_file()
    python_calls = Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")
    assert "-m playwright install chromium\n" not in python_calls
    assert "--with-deps" not in python_calls
    assert not apt_log.exists()


def test_existing_native_chromium_skips_system_package_install(tmp_path):
    env = _env(tmp_path)
    Path(env["RAVENEYE_OS_RELEASE_FILE"]).write_text('ID=archcraft\nID_LIKE=arch\n', encoding="utf-8")
    chromium = _configure_fake_system_chromium(tmp_path, env)
    shutil.copy(env["CHROMIUM_STUB"], chromium)
    chromium.chmod(0o755)
    pacman_log = tmp_path / "pacman.log"
    pacman = Path(env["PATH"].split(os.pathsep)[0]) / "pacman"
    pacman.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$PACMAN_LOG"\nexit 0\n', encoding="utf-8")
    pacman.chmod(0o755)
    env["PACMAN_LOG"] = str(pacman_log)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    assert "Chromium nativo encontrado" in result.stdout
    assert not pacman_log.exists()
    python_calls = Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")
    assert "-m playwright install chromium\n" not in python_calls


@pytest.mark.parametrize(
    "os_release",
    [
        'ID=ubuntu\nID_LIKE=debian\n',
        'ID=pop\nID_LIKE="ubuntu debian"\n',
    ],
)
def test_apt_system_uses_playwright_with_deps(tmp_path, os_release):
    env = _env(tmp_path)
    Path(env["RAVENEYE_OS_RELEASE_FILE"]).write_text(os_release, encoding="utf-8")
    apt = Path(env["PATH"].split(os.pathsep)[0]) / "apt-get"
    apt.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    apt.chmod(0o755)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    python_calls = Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")
    assert "-m playwright install --with-deps chromium\n" in python_calls


def test_fedora_uses_dnf_for_native_chromium_and_never_calls_apt(tmp_path):
    env = _env(tmp_path)
    Path(env["RAVENEYE_OS_RELEASE_FILE"]).write_text('ID=fedora\nID_LIKE="rhel fedora"\n', encoding="utf-8")
    fake_bin = Path(env["PATH"].split(os.pathsep)[0])
    _configure_fake_system_chromium(tmp_path, env)
    dnf_log = tmp_path / "dnf.log"
    dnf = fake_bin / "dnf"
    dnf.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$DNF_LOG"\ncp "$CHROMIUM_STUB" "$SYSTEM_CHROMIUM_PATH"\nchmod +x "$SYSTEM_CHROMIUM_PATH"\nexit 0\n',
        encoding="utf-8",
    )
    dnf.chmod(0o755)
    apt_log = tmp_path / "apt.log"
    apt = fake_bin / "apt-get"
    apt.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$APT_LOG"\nexit 0\n', encoding="utf-8")
    apt.chmod(0o755)
    env["DNF_LOG"] = str(dnf_log)
    env["APT_LOG"] = str(apt_log)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    dnf_call = dnf_log.read_text(encoding="utf-8").splitlines()[0]
    assert dnf_call == "install chromium"
    assert not apt_log.exists()
    assert "-m playwright install chromium\n" not in Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")


def test_opensuse_uses_zypper_for_chromium_libraries(tmp_path):
    env = _env(tmp_path)
    Path(env["RAVENEYE_OS_RELEASE_FILE"]).write_text('ID=opensuse-tumbleweed\nID_LIKE="suse opensuse"\n', encoding="utf-8")
    fake_bin = Path(env["PATH"].split(os.pathsep)[0])
    _configure_fake_system_chromium(tmp_path, env)
    zypper_log = tmp_path / "zypper.log"
    zypper = fake_bin / "zypper"
    zypper.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$ZYPPER_LOG"\ncp "$CHROMIUM_STUB" "$SYSTEM_CHROMIUM_PATH"\nchmod +x "$SYSTEM_CHROMIUM_PATH"\nexit 0\n',
        encoding="utf-8",
    )
    zypper.chmod(0o755)
    env["ZYPPER_LOG"] = str(zypper_log)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    zypper_call = zypper_log.read_text(encoding="utf-8").splitlines()[0]
    assert zypper_call == "install chromium"
    assert "-m playwright install chromium\n" not in Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("os_release", "manager", "expected_call"),
    [
        ('ID=alpine\nID_LIKE="alpine"\n', "apk", "add chromium gcompat"),
        ('ID=void\nID_LIKE="void"\n', "xbps-install", "-S chromium"),
        ('ID=gentoo\nID_LIKE="gentoo"\n', "emerge", "--ask --oneshot www-client/chromium"),
        ('ID=solus\nID_LIKE="solus"\n', "eopkg", "install chromium"),
    ],
)
def test_linux_package_adapters_install_native_chromium(tmp_path, os_release, manager, expected_call):
    env = _env(tmp_path)
    Path(env["RAVENEYE_OS_RELEASE_FILE"]).write_text(os_release, encoding="utf-8")
    fake_bin = Path(env["PATH"].split(os.pathsep)[0])
    _configure_fake_system_chromium(tmp_path, env)
    manager_log = tmp_path / f"{manager}.log"
    command = fake_bin / manager
    command.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$MANAGER_LOG"\n'
        'cp "$CHROMIUM_STUB" "$SYSTEM_CHROMIUM_PATH"\n'
        'chmod +x "$SYSTEM_CHROMIUM_PATH"\nexit 0\n',
        encoding="utf-8",
    )
    command.chmod(0o755)
    env["MANAGER_LOG"] = str(manager_log)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    assert manager_log.read_text(encoding="utf-8").splitlines() == [expected_call]
    assert Path(env["SYSTEM_CHROMIUM_PATH"]).is_file()
    assert "-m playwright install chromium\n" not in Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")


def test_native_browser_package_failure_falls_back_to_playwright(tmp_path):
    env = _env(tmp_path)
    Path(env["RAVENEYE_OS_RELEASE_FILE"]).write_text('ID=archcraft\nID_LIKE=arch\n', encoding="utf-8")
    pacman = Path(env["PATH"].split(os.pathsep)[0]) / "pacman"
    pacman.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
    pacman.chmod(0o755)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    assert "tentando o Chromium do Playwright" in result.stderr
    assert "-m playwright install chromium\n" in Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")


def test_browserless_unix_installs_static_runtime_when_headless_is_unavailable(tmp_path):
    env = _env(tmp_path)
    env["FAIL_BROWSER_SMOKE"] = "1"

    result = _run("install.sh", env)

    lib_dir = Path(env["RAVENEYE_LIB_DIR"])
    assert result.returncode == 0, result.stderr
    assert (lib_dir / ".raveneye-install").is_file()
    assert (lib_dir / "RavenEye.py").is_file()
    assert not (lib_dir / ".playwright-browsers").exists()
    assert "estático, scanner e outros módulos continuam disponíveis" in result.stderr
    assert "Renderização headless não disponível" in result.stdout


def test_package_manager_and_browser_failures_leave_core_install_available(tmp_path):
    env = _env(tmp_path)
    Path(env["RAVENEYE_OS_RELEASE_FILE"]).write_text('ID=archcraft\nID_LIKE=arch\n', encoding="utf-8")
    lib_dir = Path(env["RAVENEYE_LIB_DIR"])
    vendor = lib_dir / "_vendor"
    vendor.mkdir(parents=True)
    vendor_sentinel = vendor / "previous-vendor.txt"
    vendor_sentinel.write_text("previous vendor\n", encoding="utf-8")
    source = lib_dir / "RavenEye.py"
    source.write_text("previous source\n", encoding="utf-8")
    marker = lib_dir / ".raveneye-install"
    marker.write_text("RavenEye previous\n", encoding="utf-8")
    browser_dir = lib_dir / ".playwright-browsers"
    browser_dir.mkdir()
    browser_sentinel = browser_dir / "previous-browser.txt"
    browser_sentinel.write_text("previous browser\n", encoding="utf-8")
    fake_bin = Path(env["PATH"].split(os.pathsep)[0])
    pacman = fake_bin / "pacman"
    pacman.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
    pacman.chmod(0o755)
    env["FAIL_BROWSER_SMOKE"] = "1"

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    assert "instalação seguirá sem renderização JS" in result.stderr
    assert "-m playwright install chromium\n" in Path(env["PYTHON_LOG"]).read_text(encoding="utf-8")
    assert not vendor_sentinel.exists()
    assert source.read_text(encoding="utf-8") != "previous source\n"
    assert marker.read_text(encoding="utf-8") == "RavenEye 6.6.6\n"
    assert browser_sentinel.read_text(encoding="utf-8") == "previous browser\n"


def test_installer_retries_safe_empty_vendor_directory_after_failed_attempt(tmp_path):
    env = _env(tmp_path)
    vendor = Path(env["RAVENEYE_LIB_DIR"]) / "_vendor"
    vendor.mkdir(parents=True)

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    assert (Path(env["RAVENEYE_LIB_DIR"]) / ".raveneye-install").is_file()
    assert (Path(env["RAVENEYE_LIB_DIR"]) / "_vendor").is_dir()


def test_install_handles_spaces_and_apostrophes_without_shell_interpolation(tmp_path):
    env = _env(tmp_path)
    special = tmp_path / "with spaces and ' quote"
    env["RAVENEYE_BIN_DIR"] = str(special / "bin")
    env["RAVENEYE_LIB_DIR"] = str(special / "share" / "raveneye")
    env["RAVENEYE_SYSTEM_BIN_DIR"] = str(special / "system-bin")
    result = _run("install.sh", env)
    assert result.returncode == 0, result.stderr
    assert (special / "bin" / "raven.home").read_text(encoding="utf-8").strip() == str(special / "share" / "raveneye")


def test_failed_pip_keeps_previously_active_vendor_tree(tmp_path):
    env = _env(tmp_path)
    lib_dir = Path(env["RAVENEYE_LIB_DIR"])
    vendor = lib_dir / "_vendor"
    vendor.mkdir(parents=True)
    (lib_dir / ".raveneye-install").write_text("RavenEye 6.6.6\n", encoding="utf-8")
    sentinel = vendor / "previous-install.txt"
    sentinel.write_text("previous", encoding="utf-8")
    old_source = lib_dir / "RavenEye.py"
    old_source.write_text("previous source revision\n", encoding="utf-8")
    fake_python = tmp_path / "python-fail-pip"
    fake_python.write_text(
        '#!/bin/sh\nif [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then exit 42; fi\nexec "$REAL_PYTHON" "$@"\n',
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    env["PYTHON"] = str(fake_python)
    env["REAL_PYTHON"] = sys.executable
    result = _run("install.sh", env)
    assert result.returncode != 0
    assert sentinel.read_text(encoding="utf-8") == "previous"
    assert old_source.read_text(encoding="utf-8") == "previous source revision\n"


def test_failed_playwright_install_keeps_core_install_and_preserves_old_browser(tmp_path):
    env = _env(tmp_path)
    lib_dir = Path(env["RAVENEYE_LIB_DIR"])
    vendor = lib_dir / "_vendor"
    vendor.mkdir(parents=True)
    vendor_sentinel = vendor / "previous-install.txt"
    vendor_sentinel.write_text("previous vendor\n", encoding="utf-8")
    old_source = lib_dir / "RavenEye.py"
    old_source.write_text("previous source revision\n", encoding="utf-8")
    marker = lib_dir / ".raveneye-install"
    marker.write_text("RavenEye previous\n", encoding="utf-8")
    browser_dir = lib_dir / ".playwright-browsers"
    browser_dir.mkdir()
    browser_sentinel = browser_dir / "previous-browser.txt"
    browser_sentinel.write_text("previous browsers\n", encoding="utf-8")
    fake_python = tmp_path / "python-fail-playwright"
    fake_python.write_text(
        '#!/bin/sh\n'
        'if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then exit 0; fi\n'
        'if [ "${1:-}" = "-m" ] && [ "${2:-}" = "playwright" ]; then exit 42; fi\n'
        'if [ "${1:-}" = "-c" ]; then case "${2:-}" in *"chromium_runtime_smoke"*) exit 47 ;; esac; exit 0; fi\n'
        'exec "$REAL_PYTHON" "$@"\n',
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    env["PYTHON"] = str(fake_python)
    env["REAL_PYTHON"] = sys.executable

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    assert "renderização JS" in result.stderr
    assert old_source.read_text(encoding="utf-8") != "previous source revision\n"
    assert marker.read_text(encoding="utf-8") == "RavenEye 6.6.6\n"
    assert not vendor_sentinel.exists()
    assert browser_sentinel.read_text(encoding="utf-8") == "previous browsers\n"


def test_browser_launch_smoke_failure_keeps_core_install_and_old_browser(tmp_path):
    env = _env(tmp_path)
    lib_dir = Path(env["RAVENEYE_LIB_DIR"])
    vendor = lib_dir / "_vendor"
    vendor.mkdir(parents=True)
    vendor_sentinel = vendor / "previous-install.txt"
    vendor_sentinel.write_text("previous vendor\n", encoding="utf-8")
    old_source = lib_dir / "RavenEye.py"
    old_source.write_text("previous source revision\n", encoding="utf-8")
    marker = lib_dir / ".raveneye-install"
    marker.write_text("RavenEye previous\n", encoding="utf-8")
    browser_dir = lib_dir / ".playwright-browsers"
    browser_dir.mkdir()
    browser_sentinel = browser_dir / "previous-browser.txt"
    browser_sentinel.write_text("previous browsers\n", encoding="utf-8")
    fake_python = tmp_path / "python-fail-browser-launch"
    fake_python.write_text(
        '#!/bin/sh\n'
        'if [ "${1:-}" = "-m" ] && { [ "${2:-}" = "pip" ] || [ "${2:-}" = "playwright" ]; }; then exit 0; fi\n'
        'if [ "${1:-}" = "-c" ]; then case "${2:-}" in *"chromium_runtime_smoke"*) exit 47 ;; esac; exit 0; fi\n'
        'case "${1:-}" in "$RAVENEYE_LIB_DIR"/.raveneye-source.*/RavenEye.py) if [ "${2:-}" = "--version" ]; then echo "RavenEye 6.6.6"; exit 0; fi ;; esac\n'
        'exec "$REAL_PYTHON" "$@"\n',
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    env["PYTHON"] = str(fake_python)
    env["REAL_PYTHON"] = sys.executable

    result = _run("install.sh", env)

    assert result.returncode == 0, result.stderr
    assert "renderização JS" in result.stderr
    assert old_source.read_text(encoding="utf-8") != "previous source revision\n"
    assert marker.read_text(encoding="utf-8") == "RavenEye 6.6.6\n"
    assert not vendor_sentinel.exists()
    assert browser_sentinel.read_text(encoding="utf-8") == "previous browsers\n"


def test_failed_final_launcher_smoke_rolls_back_entire_install(tmp_path):
    env = _env(tmp_path)
    lib_dir = Path(env["RAVENEYE_LIB_DIR"])
    bin_dir = Path(env["RAVENEYE_BIN_DIR"])
    vendor = lib_dir / "_vendor"
    vendor.mkdir(parents=True)
    vendor_sentinel = vendor / "previous-install.txt"
    vendor_sentinel.write_text("previous vendor\n", encoding="utf-8")
    old_source = lib_dir / "RavenEye.py"
    old_source.write_text("previous source revision\n", encoding="utf-8")
    marker = lib_dir / ".raveneye-install"
    marker.write_text("RavenEye previous\n", encoding="utf-8")
    browser_dir = lib_dir / ".playwright-browsers"
    browser_dir.mkdir()
    browser_sentinel = browser_dir / "previous-browser.txt"
    browser_sentinel.write_text("previous browsers\n", encoding="utf-8")
    bin_dir.mkdir(parents=True)
    old_launcher = bin_dir / "raven"
    old_launcher.write_text("#!/bin/sh\nRAVENEYE_LAUNCHER=1\necho previous launcher\n", encoding="utf-8")
    old_launcher.chmod(0o755)
    old_sidecar = bin_dir / "raven.home"
    old_sidecar.write_text("previous launcher home\n", encoding="utf-8")
    fake_python = tmp_path / "python-fail-final-smoke"
    fake_python.write_text(
        '#!/bin/sh\n'
        'if [ "${1:-}" = "-m" ] && { [ "${2:-}" = "pip" ] || [ "${2:-}" = "playwright" ]; }; then exit 0; fi\n'
        'if [ "${1:-}" = "-c" ]; then exit 0; fi\n'
        'case "${1:-}" in "$RAVENEYE_LIB_DIR"/.raveneye-source.*/RavenEye.py) if [ "${2:-}" = "--version" ]; then exit 0; fi ;; esac\n'
        'case "${1:-}" in "$RAVENEYE_LIB_DIR/RavenEye.py") if [ "${2:-}" = "--version" ]; then exit 43; fi ;; esac\n'
        'exec "$REAL_PYTHON" "$@"\n',
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    env["PYTHON"] = str(fake_python)
    env["REAL_PYTHON"] = sys.executable

    result = _run("install.sh", env)

    assert result.returncode != 0
    assert "teste local de inicialização" in result.stderr
    assert old_source.read_text(encoding="utf-8") == "previous source revision\n"
    assert marker.read_text(encoding="utf-8") == "RavenEye previous\n"
    assert vendor_sentinel.read_text(encoding="utf-8") == "previous vendor\n"
    assert browser_sentinel.read_text(encoding="utf-8") == "previous browsers\n"
    assert old_launcher.read_text(encoding="utf-8") == "#!/bin/sh\nRAVENEYE_LAUNCHER=1\necho previous launcher\n"
    assert old_sidecar.read_text(encoding="utf-8") == "previous launcher home\n"


def test_install_refuses_foreign_launcher_and_protected_library_path(tmp_path):
    env = _env(tmp_path)
    bin_dir = Path(env["RAVENEYE_BIN_DIR"])
    bin_dir.mkdir(parents=True)
    foreign = bin_dir / "raven"
    foreign.write_text("#!/bin/sh\necho foreign\n", encoding="utf-8")
    result = _run("install.sh", env)
    assert result.returncode != 0
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho foreign\n"
    assert not Path(env["RAVENEYE_LIB_DIR"]).exists()

    env = _env(tmp_path / "unsafe")
    env["RAVENEYE_LIB_DIR"] = "/"
    result = _run("install.sh", env, "--dry-run")
    assert result.returncode != 0
    assert "protegido" in result.stderr


def test_installer_archive_excludes_runtime_secrets_and_dork_files():
    script = (ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    for excluded in (
        "--exclude='.env'",
        "--exclude='./raven_eye_config.json'",
        "--exclude='*.log'",
        "--exclude='./RavenEye_dorks_*.txt'",
        "--exclude='./RavenEye_dorks_resultados_*.txt'",
    ):
        assert script.count(excluded) == 2


def test_installer_includes_every_declared_dependency_and_chromium_smoke():
    script = (ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared: set[str] = set()
    for section_name in (
        "tool.poetry.dependencies", "tool.poetry.group.dev.dependencies",
    ):
        start = project.index(f"[{section_name}]")
        section = project[start:].split("\n[", 1)[0]
        declared.update(
            name.lower().replace("-", "").replace("_", "").replace(".", "")
            for name in re.findall(r"(?m)^([A-Za-z0-9_.-]+)\s*=\s*['\"]", section)
            if name.lower() != "python"
        )
    installer_names = {
        name.lower().replace("-", "").replace("_", "").replace(".", "")
        for name in re.findall(
            r"(?m)^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:>=|==|~=|<=|!=)",
            script,
        )
    }

    assert declared <= installer_names
    assert 'playwright = ">=1.48,<2"' in project
    assert "playwright>=1.48,<2" in script
    for required in (
        "pydantic", "pyyaml", "lxml", "sqlalchemy", "reportlab", "pillow",
        "playwright", "asyncssh", "aioftp", "aiosmtplib", "motor", "asyncpg",
        "aiomysql", "smbprotocol", "uvloop",
    ):
        assert required in installer_names
    assert "run_chromium_smoke_test \"$SOURCE_STAGE\"" in script
    browser_runtime = (ROOT / "raveneye" / "core" / "browser.py").read_text(encoding="utf-8")
    assert "chromium_runtime_smoke" in browser_runtime
    assert "RavenEye local smoke" in browser_runtime
    assert "-m playwright install chromium" in script


def test_doctor_maps_every_runtime_distribution_to_an_import_module():
    import tomllib

    from raveneye_pkg.doctor import RUNTIME_IMPORTS_BY_DISTRIBUTION

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    canonical = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    runtime = {
        canonical(name)
        for name in project["tool"]["poetry"]["dependencies"]
        if name != "python"
    }
    mapped = {canonical(name) for name in RUNTIME_IMPORTS_BY_DISTRIBUTION}

    assert runtime == mapped
    assert all(modules and all(isinstance(module, str) for module in modules)
               for modules in RUNTIME_IMPORTS_BY_DISTRIBUTION.values())


def test_uninstall_dry_run_and_foreign_destination_are_non_destructive(tmp_path):
    env = _env(tmp_path)
    assert _run("install.sh", env).returncode == 0
    bin_dir = Path(env["RAVENEYE_BIN_DIR"])
    lib_dir = Path(env["RAVENEYE_LIB_DIR"])
    launcher_hash = (bin_dir / "raven").read_bytes()
    marker_hash = (lib_dir / ".raveneye-install").read_bytes()

    result = _run("uninstall.sh", env, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert (bin_dir / "raven").read_bytes() == launcher_hash
    assert (lib_dir / ".raveneye-install").read_bytes() == marker_hash

    env["RAVENEYE_LIB_DIR"] = str(tmp_path / "foreign")
    foreign = Path(env["RAVENEYE_LIB_DIR"])
    foreign.mkdir()
    (foreign / "keep.txt").write_text("keep", encoding="utf-8")
    result = _run("uninstall.sh", env, "-y")
    assert result.returncode != 0
    assert (foreign / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_uninstall_is_repeatable_and_refuses_symlinked_library(tmp_path):
    env = _env(tmp_path)
    assert _run("install.sh", env).returncode == 0
    result = _run("uninstall.sh", env, "-y")
    assert result.returncode == 0, result.stderr
    assert not Path(env["RAVENEYE_BIN_DIR"], "raven").exists()
    assert not Path(env["RAVENEYE_BIN_DIR"], "raven.home").exists()
    assert not Path(env["RAVENEYE_LIB_DIR"]).exists()
    repeated = _run("uninstall.sh", env, "-y")
    assert repeated.returncode == 0, repeated.stderr

    other = tmp_path / "outside"
    other.mkdir()
    (other / ".raveneye-install").write_text("RavenEye 6.6.6\n", encoding="utf-8")
    (other / "keep.txt").write_text("keep", encoding="utf-8")
    link_home = tmp_path / "linked-home"
    (link_home / ".local" / "share").mkdir(parents=True)
    linked_lib = link_home / ".local" / "share" / "raveneye"
    linked_lib.symlink_to(other, target_is_directory=True)
    env["HOME"] = str(link_home)
    env["RAVENEYE_BIN_DIR"] = str(link_home / ".local" / "bin")
    env["RAVENEYE_LIB_DIR"] = str(linked_lib)
    blocked = _run("uninstall.sh", env, "-y")
    assert blocked.returncode != 0
    assert (other / "keep.txt").read_text(encoding="utf-8") == "keep"
