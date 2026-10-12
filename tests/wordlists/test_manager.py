from __future__ import annotations

import os

import pytest

from raveneye.wordlists import CATEGORIES, WordlistError, WordlistIntegrityError, WordlistManager, normalize_category


def test_taxonomy_and_custom_fields_are_validated():
    assert CATEGORIES == (
        "directories", "subdomains", "users", "passwords", "combos",
        "params", "sensitive_files", "endpoints_api",
    )
    assert normalize_category("custom:graphql") == "custom:graphql"
    with pytest.raises(WordlistError):
        normalize_category("custom:../secrets")


def test_builtins_are_classified_without_crossing_wordlist_categories():
    from raveneye_pkg.bruteforce import get_wordlist_manager
    from raveneye_pkg.constants import SUBDOMAIN_WORDLIST

    manager = get_wordlist_manager()
    assert [item.id for item in manager.list("passwords")] == ["builtin_passwords"]
    subdomain_lists = manager.list("subdomains")
    assert [item.id for item in subdomain_lists] == ["builtin_subdomains"]
    assert subdomain_lists[0].entries == len(SUBDOMAIN_WORDLIST)
    assert manager.read("builtin_subdomains") == SUBDOMAIN_WORDLIST
    assert manager.list("params") == []


def test_bundled_wordlists_remain_listable_without_a_valid_import_manifest(tmp_path):
    from raveneye_pkg.bruteforce import get_wordlist_manager

    manager = get_wordlist_manager(tmp_path / "wordlists")
    manager.root.mkdir(parents=True)
    manager.manifest_path.write_text("{broken", encoding="utf-8")

    assert [item.id for item in manager.list_builtins("subdomains")] == ["builtin_subdomains"]
    with pytest.raises(WordlistIntegrityError):
        manager.list("subdomains")
    assert manager.read("builtin_subdomains")


def test_corrupt_manifest_fails_before_import_writes_wordlist_bytes(tmp_path):
    source = tmp_path / "candidate.txt"
    source.write_text("portal\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "store")
    manager.root.mkdir(parents=True)
    manager.manifest_path.write_text("{broken", encoding="utf-8")

    with pytest.raises(WordlistIntegrityError):
        manager.add(source, "subdomains")

    assert list(manager.root.iterdir()) == [manager.manifest_path]


def test_import_is_deduplicated_private_and_never_listed_as_content(tmp_path):
    source = tmp_path / "candidate-list.txt"
    source.write_text(" pass with spaces \npass2\npass2\n\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "store")

    item = manager.add(source, "passwords")

    assert item.category == "passwords"
    assert manager.read(item.id) == [" pass with spaces ", "pass2"]
    assert item.entries == 2
    assert "pass2" not in manager.manifest_path.read_text(encoding="utf-8")
    listed = manager.list("passwords")
    assert len(listed) == 1
    assert listed[0].integrity == "verified"
    if os.name == "posix":
        assert manager.root.stat().st_mode & 0o077 == 0
        assert manager.path_for(item.id).stat().st_mode & 0o077 == 0


def test_tampered_wordlist_is_blocked_and_marked_invalid(tmp_path):
    source = tmp_path / "params.txt"
    source.write_text("page\nlimit\n", encoding="utf-8")
    manager = WordlistManager(tmp_path / "store")
    item = manager.add(source, "params")
    manager.path_for(item.id).write_text("changed\n", encoding="utf-8")

    assert manager.list("params")[0].integrity == "invalid"
    with pytest.raises(WordlistIntegrityError):
        manager.read(item.id)


def test_rejects_symlinks_binary_and_oversized_files(tmp_path):
    manager = WordlistManager(tmp_path / "store", max_bytes=1024)
    text = tmp_path / "words.txt"
    text.write_text("word\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(text)
    with pytest.raises(WordlistError):
        manager.add(link, "passwords")

    binary = tmp_path / "binary.txt"
    binary.write_bytes(b"\xff\xfe\xfa")
    with pytest.raises(WordlistError):
        manager.add(binary, "passwords")

    large = tmp_path / "large.txt"
    large.write_bytes(b"x" * 1025)
    with pytest.raises(WordlistError):
        manager.add(large, "passwords")


def test_rejects_symlinked_storage_and_reuses_only_matching_content(tmp_path):
    source = tmp_path / "candidate.txt"
    source.write_text("candidate-one\ncandidate-two\n", encoding="utf-8")
    linked_target = tmp_path / "external-store"
    linked_target.mkdir()
    linked_root = tmp_path / "wordlists-link"
    linked_root.symlink_to(linked_target, target_is_directory=True)
    linked_manager = WordlistManager(linked_root)
    with pytest.raises(WordlistIntegrityError):
        linked_manager.add(source, "passwords")
    assert list(linked_target.iterdir()) == []

    manager = WordlistManager(tmp_path / "store")
    item = manager.add(source, "passwords")
    assert manager.add(source, "passwords").id == item.id
    manager.path_for(item.id).write_text("different-data\n", encoding="utf-8")
    with pytest.raises(WordlistIntegrityError):
        manager.add(source, "passwords")
