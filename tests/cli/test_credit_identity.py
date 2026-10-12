from raveneye_pkg.credits import show_credits


def test_credits_show_only_thiago_and_stylized_tandai_sec(capsys):
    show_credits()

    output = capsys.readouterr().out
    assert output.count("Thiago") == 1
    assert "TΛNDΛI SΞC" in output
    assert "Pedro" not in output
    assert "Thiagofatal" not in output
    assert "nickname" not in output.casefold()
