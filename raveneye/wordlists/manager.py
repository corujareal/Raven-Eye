from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


CATEGORIES = (
    "directories",
    "subdomains",
    "users",
    "passwords",
    "combos",
    "params",
    "sensitive_files",
    "endpoints_api",
)
_CUSTOM_FIELD = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,47}$")
_SAFE_ID = re.compile(r"^[a-z0-9_-]{1,80}$")
_MANIFEST_SCHEMA = 1
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024


class WordlistError(ValueError):
    """Invalid, missing, oversized, or unsupported wordlist input."""


class WordlistIntegrityError(WordlistError):
    """A stored wordlist no longer matches its registered digest."""


@dataclass(frozen=True, slots=True)
class WordlistInfo:
    id: str
    category: str
    label: str
    sha256: str
    entries: int
    source: str
    integrity: str = "verified"


def normalize_category(category: str) -> str:
    value = str(category or "").strip()
    if value in CATEGORIES:
        return value
    if value.startswith("custom:"):
        field = value.partition(":")[2].strip()
        if _CUSTOM_FIELD.fullmatch(field):
            return f"custom:{field.lower()}"
    raise WordlistError("Categoria invalida. Use uma categoria conhecida ou custom:<campo>.")


def _category_dir(category: str) -> str:
    if category.startswith("custom:"):
        field = category.partition(":")[2]
        return "custom_" + re.sub(r"[^a-z0-9_-]", "_", field)
    return category


def _safe_label(value: str) -> str:
    name = Path(value).name
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", name).strip("._-")
    return (safe or "wordlist")[:80]


def _private_mode(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except (AttributeError, NotImplementedError, OSError):
        # Windows and some Termux-mounted filesystems may not implement POSIX
        # modes. The owner-only data directory is still used where available.
        pass


class WordlistManager:
    """Manage categorized local wordlists without displaying their contents.

    Imported lists are copied into a private user-data directory. The manifest
    stores only a display name, category, digest, count, and relative path.
    Password values are never placed in logs or metadata.
    """

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        builtins: Mapping[str, tuple[str, str, Sequence[str]]] | None = None,
        max_bytes: int = 25 * 1024 * 1024,
        max_entries: int = 500_000,
    ) -> None:
        if root is None:
            env_root = os.environ.get("RAVENEYE_DATA_DIR")
            xdg_root = os.environ.get("XDG_DATA_HOME")
            base = Path(env_root) if env_root else Path(xdg_root) if xdg_root else Path.home() / ".local" / "share" / "raveneye"
            root = base / "wordlists"
        self.root = Path(root).expanduser()
        self.manifest_path = self.root / "manifest.json"
        self.max_bytes = max(1024, int(max_bytes))
        self.max_entries = max(1, int(max_entries))
        self.builtins = dict(builtins or {})

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            info = self.root.lstat()
        except OSError as exc:
            raise WordlistIntegrityError("Armazenamento de wordlists indisponivel.") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise WordlistIntegrityError("Armazenamento de wordlists nao pode ser link simbolico.")
        _private_mode(self.root, 0o700)

    def _manifest(self) -> dict[str, dict]:
        try:
            info = self.manifest_path.lstat()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise WordlistIntegrityError("Manifest de wordlists indisponivel.") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_MANIFEST_BYTES:
            raise WordlistIntegrityError("Manifest de wordlists nao e regular ou excede o limite.")
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.manifest_path, flags)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_MANIFEST_BYTES:
                    raise WordlistIntegrityError("Manifest de wordlists nao e regular ou excede o limite.")
                data = stream.read(_MAX_MANIFEST_BYTES + 1)
            if len(data) > _MAX_MANIFEST_BYTES:
                raise WordlistIntegrityError("Manifest de wordlists excede o limite.")
            raw = json.loads(data.decode("utf-8", errors="strict"))
        except WordlistIntegrityError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise WordlistIntegrityError("Manifest de wordlists ilegivel; nenhuma lista sera usada.") from exc
        except OSError as exc:
            raise WordlistIntegrityError("Manifest de wordlists nao pode ser aberto com seguranca.") from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != _MANIFEST_SCHEMA or not isinstance(raw.get("wordlists"), dict):
            raise WordlistIntegrityError("Schema do manifest de wordlists nao suportado.")
        records = raw["wordlists"]
        if any(not isinstance(key, str) or not isinstance(value, dict) for key, value in records.items()):
            raise WordlistIntegrityError("Manifest de wordlists possui registros invalidos.")
        return records

    def _write_manifest(self, records: dict[str, dict]) -> None:
        self._ensure_root()
        payload = json.dumps(
            {"schema_version": _MANIFEST_SCHEMA, "wordlists": records},
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(prefix=".manifest-", suffix=".tmp", dir=self.root)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _private_mode(tmp, 0o600)
            os.replace(tmp, self.manifest_path)
            _private_mode(self.manifest_path, 0o600)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    def _builtin_info(self, item_id: str, item: tuple[str, str, Sequence[str]]) -> WordlistInfo:
        category, label, values = item
        category = normalize_category(category)
        content = "\n".join(str(value).rstrip("\r\n") for value in values if str(value).rstrip("\r\n"))
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return WordlistInfo(item_id, category, label, digest, len(content.splitlines()), "builtin")

    def list_builtins(self, category: str | None = None) -> list[WordlistInfo]:
        """List trusted bundled lists without consulting the user manifest.

        This fallback keeps essential built-in choices available when a local
        imported-list catalog is damaged. It never makes imported entries
        visible or usable without validating their manifest and file hashes.
        """
        wanted = normalize_category(category) if category else None
        results: list[WordlistInfo] = []
        for item_id, item in self.builtins.items():
            if not _SAFE_ID.fullmatch(item_id) or not isinstance(item, tuple) or len(item) != 3:
                continue
            info = self._builtin_info(item_id, item)
            if wanted is None or info.category == wanted:
                results.append(info)
        return sorted(results, key=lambda info: (info.category, info.label.casefold(), info.id))

    def list(self, category: str | None = None) -> list[WordlistInfo]:
        wanted = normalize_category(category) if category else None
        results = self.list_builtins(wanted)
        records = self._manifest()
        for item_id, record in records.items():
            if not _SAFE_ID.fullmatch(item_id):
                continue
            try:
                record_category = normalize_category(record.get("category", ""))
                if wanted is not None and record_category != wanted:
                    continue
                words = self.read(item_id)
                results.append(
                    WordlistInfo(
                        id=item_id,
                        category=record_category,
                        label=_safe_label(str(record.get("label", "wordlist"))),
                        sha256=str(record.get("sha256", "")),
                        entries=len(words),
                        source="imported",
                        integrity="verified",
                    )
                )
            except (WordlistError, OSError):
                results.append(
                    WordlistInfo(
                        id=item_id,
                        category=str(record.get("category", "invalid")),
                        label=_safe_label(str(record.get("label", "wordlist"))),
                        sha256=str(record.get("sha256", "")),
                        entries=0,
                        source="imported",
                        integrity="invalid",
                    )
                )
        return sorted(results, key=lambda info: (info.category, info.label.casefold(), info.id))

    def add(self, source: str | Path, category: str) -> WordlistInfo:
        selected_category = normalize_category(category)
        source_path = Path(source).expanduser()
        try:
            source_stat = source_path.lstat()
        except OSError as exc:
            raise WordlistError("Arquivo de wordlist nao pode ser lido.") from exc
        if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISREG(source_stat.st_mode):
            raise WordlistError("A origem deve ser um arquivo regular, nao um link simbolico.")
        if source_stat.st_size <= 0 or source_stat.st_size > self.max_bytes:
            raise WordlistError(f"Tamanho invalido; limite: {self.max_bytes} bytes.")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(source_path, flags)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_size <= 0 or opened.st_size > self.max_bytes:
                    raise WordlistError(f"Tamanho invalido; limite: {self.max_bytes} bytes.")
                data = stream.read(self.max_bytes + 1)
        except WordlistError:
            raise
        except OSError as exc:
            raise WordlistError("Arquivo de wordlist nao pode ser aberto com seguranca.") from exc
        if len(data) > self.max_bytes:
            raise WordlistError(f"Tamanho invalido; limite: {self.max_bytes} bytes.")
        try:
            text = data.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            raise WordlistError("A wordlist precisa ser texto UTF-8.") from exc

        # Preserve spaces inside credentials while removing blank lines and
        # exact duplicates. Values themselves are never included in errors.
        unique: list[str] = []
        seen: set[str] = set()
        for line in text.splitlines():
            value = line.rstrip("\r")
            if value and value not in seen:
                unique.append(value)
                seen.add(value)
                if len(unique) > self.max_entries:
                    raise WordlistError(f"Numero de entradas excede o limite de {self.max_entries}.")
        if not unique:
            raise WordlistError("Wordlist vazia.")

        normalized = ("\n".join(unique) + "\n").encode("utf-8")
        digest = hashlib.sha256(normalized).hexdigest()
        category_folder = _category_dir(selected_category)
        item_id = f"{category_folder}_{digest[:16]}"
        if not _SAFE_ID.fullmatch(item_id):
            raise WordlistError("Categoria invalida para armazenamento.")
        relative_path = Path(category_folder) / f"{digest}.txt"
        # Validate the catalog before writing any imported bytes. A corrupt
        # manifest must fail closed without leaving an orphaned wordlist file.
        records = self._manifest()
        self._ensure_root()
        destination = self.root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_info = destination.parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise WordlistIntegrityError("Diretorio da wordlist nao pode ser link simbolico.")
        _private_mode(destination.parent, 0o700)
        try:
            destination_info = destination.lstat()
        except FileNotFoundError:
            destination_info = None
        if destination_info is not None:
            if stat.S_ISLNK(destination_info.st_mode) or not stat.S_ISREG(destination_info.st_mode):
                raise WordlistIntegrityError("Arquivo de wordlist armazenado nao e regular.")
            try:
                fd = os.open(destination, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as stream:
                    existing = stream.read(self.max_bytes + 1)
            except OSError as exc:
                raise WordlistIntegrityError("Arquivo de wordlist armazenado nao pode ser validado.") from exc
            if len(existing) > self.max_bytes or hashlib.sha256(existing).hexdigest() != digest:
                raise WordlistIntegrityError("Arquivo existente diverge do hash esperado; importacao bloqueada.")
        else:
            fd, tmp_name = tempfile.mkstemp(prefix=".wordlist-", suffix=".tmp", dir=destination.parent)
            tmp = Path(tmp_name)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(normalized)
                    stream.flush()
                    os.fsync(stream.fileno())
                _private_mode(tmp, 0o600)
                os.replace(tmp, destination)
                _private_mode(destination, 0o600)
            finally:
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass

        label = _safe_label(source_path.name)
        records[item_id] = {
            "category": selected_category,
            "label": label,
            "sha256": digest,
            "entries": len(unique),
            "path": relative_path.as_posix(),
        }
        self._write_manifest(records)
        return WordlistInfo(item_id, selected_category, label, digest, len(unique), "imported")

    def read(self, item_id: str) -> list[str]:
        if not isinstance(item_id, str) or not _SAFE_ID.fullmatch(item_id):
            raise WordlistError("ID de wordlist invalido.")
        if item_id in self.builtins:
            category, _label, values = self.builtins[item_id]
            normalize_category(category)
            return [str(value).rstrip("\r\n") for value in values if str(value).rstrip("\r\n")]
        record = self._manifest().get(item_id)
        if not record:
            raise WordlistError("Wordlist nao encontrada.")
        relative = Path(str(record.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise WordlistIntegrityError("Caminho do manifest nao e valido.")
        candidate = self.root / relative
        try:
            if not candidate.resolve().is_relative_to(self.root.resolve()):
                raise WordlistIntegrityError("Arquivo de wordlist escapou do armazenamento privado.")
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > self.max_bytes:
                raise WordlistIntegrityError("Arquivo de wordlist nao e regular ou excede o limite.")
            fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_size > self.max_bytes:
                    raise WordlistIntegrityError("Arquivo de wordlist mudou durante a leitura.")
                data = stream.read(self.max_bytes + 1)
            if len(data) > self.max_bytes:
                raise WordlistIntegrityError("Arquivo de wordlist excede o limite.")
        except WordlistIntegrityError:
            raise
        except OSError as exc:
            raise WordlistIntegrityError("Arquivo de wordlist ausente ou ilegivel.") from exc
        digest = hashlib.sha256(data).hexdigest()
        if digest != record.get("sha256"):
            raise WordlistIntegrityError("Hash da wordlist mudou; a lista foi bloqueada.")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise WordlistIntegrityError("Wordlist armazenada nao e texto UTF-8.") from exc
        words = text.splitlines()
        if not words or len(words) > self.max_entries:
            raise WordlistIntegrityError("Quantidade de entradas invalida.")
        return words

    def path_for(self, item_id: str) -> Path:
        """Resolve a private path for an imported list or materializes a builtin."""
        if item_id in self.builtins:
            return self.materialize_builtin(item_id)
        record = self._manifest().get(item_id)
        if not record:
            raise WordlistError("Wordlist nao encontrada.")
        relative = Path(str(record.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts:
            raise WordlistIntegrityError("Caminho do manifest nao e valido.")
        path = self.root / relative
        self.read(item_id)
        return path

    def materialize_builtin(self, item_id: str) -> Path:
        """Return a private stable file path for the legacy string-path API."""
        if item_id not in self.builtins:
            raise WordlistError("Wordlist embutida nao encontrada.")
        info = self._builtin_info(item_id, self.builtins[item_id])
        words = self.read(item_id)
        folder = self.root / _category_dir(info.category)
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder_info = folder.lstat()
        if stat.S_ISLNK(folder_info.st_mode) or not stat.S_ISDIR(folder_info.st_mode):
            raise WordlistIntegrityError("Diretorio da wordlist embutida nao e seguro.")
        _private_mode(folder, 0o700)
        path = folder / f"{item_id}_{info.sha256}.txt"
        content = ("\n".join(words) + "\n").encode("utf-8")
        try:
            path_info = path.lstat()
        except FileNotFoundError:
            path_info = None
        if path_info is not None:
            try:
                if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISREG(path_info.st_mode):
                    raise WordlistIntegrityError("Wordlist embutida nao e arquivo regular.")
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as stream:
                    existing = stream.read(self.max_bytes + 1)
            except OSError as exc:
                raise WordlistIntegrityError("Wordlist embutida nao pode ser validada.") from exc
            if len(existing) > self.max_bytes or hashlib.sha256(existing.rstrip(b"\n")).hexdigest() != info.sha256:
                raise WordlistIntegrityError("Wordlist embutida mudou; lista bloqueada.")
        if path_info is None:
            fd, tmp_name = tempfile.mkstemp(prefix=".builtin-", suffix=".tmp", dir=folder)
            tmp = Path(tmp_name)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                _private_mode(tmp, 0o600)
                os.replace(tmp, path)
                _private_mode(path, 0o600)
            finally:
                try:
                    tmp.unlink()
                except FileNotFoundError:
                    pass
        return path
