from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path


class CheckpointError(RuntimeError):
    """Checkpoint is invalid, tampered with, or cannot be safely stored."""


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CheckpointStore:
    """Authenticated, atomic progress storage that contains no credentials."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser()
        self.key_path = self.root / ".checkpoint-key"

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            info = self.root.lstat()
        except OSError as exc:
            raise CheckpointError("Diretorio do checkpoint indisponivel.") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise CheckpointError("Diretorio do checkpoint nao pode ser link simbolico.")
        try:
            os.chmod(self.root, 0o700)
        except (AttributeError, NotImplementedError, OSError):
            pass
        if os.name == "posix" and stat.S_IMODE(self.root.stat().st_mode) & 0o077:
            raise CheckpointError("Diretorio do checkpoint nao esta privado; execucao bloqueada.")

    def _key(self, *, create: bool) -> bytes:
        self._ensure_root()
        try:
            info = self.key_path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise CheckpointError("Chave do checkpoint nao e um arquivo regular.")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
                raise CheckpointError("Permissoes da chave do checkpoint estao abertas; retomada bloqueada.")
            fd = os.open(self.key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_size != 32:
                    raise CheckpointError("Chave do checkpoint invalida.")
                value = stream.read(33)
            if len(value) != 32:
                raise CheckpointError("Chave do checkpoint invalida.")
            return value
        except FileNotFoundError:
            if not create:
                raise CheckpointError("Chave local do checkpoint ausente.") from None
        try:
            fd = os.open(
                self.key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            return self._key(create=False)
        value = secrets.token_bytes(32)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(self.key_path, 0o600)
        except (AttributeError, NotImplementedError, OSError):
            pass
        return value

    def identity(self, target: str, source_fingerprint: str) -> str:
        key = self._key(create=True)
        message = _canonical({"target": target, "source": source_fingerprint})
        return hmac.new(key, message, hashlib.sha256).hexdigest()[:32]

    def path_for(self, identity: str) -> Path:
        if len(identity) != 32 or any(char not in "0123456789abcdef" for char in identity):
            raise CheckpointError("ID do checkpoint invalido.")
        return self.root / f"run-{identity}.json"

    def save(self, identity: str, record: dict) -> Path:
        key = self._key(create=True)
        path = self.path_for(identity)
        body = dict(record)
        body.setdefault("schema_version", 1)
        body["updated_at"] = _utc_now()
        signature = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
        envelope = _canonical({"record": body, "hmac_sha256": signature})
        fd, tmp_name = tempfile.mkstemp(prefix=".checkpoint-", suffix=".tmp", dir=self.root)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(envelope)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(tmp, 0o600)
            except (AttributeError, NotImplementedError, OSError):
                pass
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except (AttributeError, NotImplementedError, OSError):
                pass
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        return path

    def load(self, identity: str) -> dict | None:
        path = self.path_for(identity)
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
                raise CheckpointError("Checkpoint nao e um arquivo regular ou excede o limite.")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
                raise CheckpointError("Permissoes do checkpoint estao abertas; retomada bloqueada.")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_size > 64 * 1024:
                    raise CheckpointError("Checkpoint mudou durante a leitura.")
                raw = stream.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise CheckpointError("Checkpoint excede o limite; retomada bloqueada.")
            envelope = json.loads(raw.decode("utf-8", errors="strict"))
        except FileNotFoundError:
            return None
        except CheckpointError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CheckpointError("Checkpoint ilegivel; retomada bloqueada.") from exc
        if not isinstance(envelope, dict):
            raise CheckpointError("Formato de checkpoint invalido.")
        record = envelope.get("record")
        signature = envelope.get("hmac_sha256")
        if not isinstance(record, dict) or not isinstance(signature, str):
            raise CheckpointError("Formato de checkpoint invalido.")
        key = self._key(create=False)
        expected = hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise CheckpointError("Integridade do checkpoint invalida; retomada bloqueada.")
        if record.get("schema_version") != 1:
            raise CheckpointError("Versao de checkpoint nao suportada.")
        return record
