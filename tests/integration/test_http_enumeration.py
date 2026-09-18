from raveneye_pkg import menus, bruteforce


def test_http_enumeration_menu_dependencies_are_bound():
    assert callable(menus.enumerate_paths)
    assert callable(menus.enumerate_endpoints)
    assert callable(menus.enumerate_parameters)
    assert callable(menus.normalize_url)
    assert callable(menus.is_safe_url)
    assert callable(menus.request_url)


def test_endpoint_and_parameter_enumerators_are_non_authenticating(monkeypatch):
    monkeypatch.setattr(menus, "is_safe_url", lambda url: True)
    monkeypatch.setattr(menus, "normalize_url", lambda url: url)
    monkeypatch.setattr(menus, "request_url", lambda url, **kwargs: ("<html>ok</html>", None))
    monkeypatch.setattr(bruteforce, "is_safe_url", lambda url: True)
    monkeypatch.setattr(bruteforce, "normalize_url", lambda url: url)
    monkeypatch.setattr(bruteforce, "request_url", lambda url, **kwargs: ("<html>ok</html>", None))
    monkeypatch.setattr(menus, "_sleep", lambda *_args, **_kwargs: None)

    endpoints = menus.enumerate_endpoints("https://example.test", limit=3)
    params = menus.enumerate_parameters("https://example.test/?id=1", limit=3)

    assert len(endpoints) == 3
    assert all(item["kind"] == "path" for item in endpoints)
    assert len(params) == 3
    assert all(item["kind"] == "parameter" for item in params)
