import inspect
import logging
import stat
from pathlib import Path

from lastrites.core import pepper as pepper_mod
from lastrites.core.pepper import load_or_create_pepper


def test_pepper_file_created_0600(tmp_path):
    path = tmp_path / "sub" / "pepper"
    load_or_create_pepper(path)

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_pepper_create_once_is_idempotent(tmp_path):
    path = tmp_path / "pepper"

    first = load_or_create_pepper(path)
    second = load_or_create_pepper(path)

    assert first == second
    assert len(first) == 32


def test_pepper_value_is_random_per_path(tmp_path):
    a = load_or_create_pepper(tmp_path / "a" / "pepper")
    b = load_or_create_pepper(tmp_path / "b" / "pepper")

    assert a != b


def test_pepper_never_appears_in_logs_or_stdout(tmp_path, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    path = tmp_path / "pepper"

    created = load_or_create_pepper(path)
    loaded = load_or_create_pepper(path)

    captured = capsys.readouterr()
    combined = caplog.text + captured.out + captured.err

    assert created.hex() not in combined
    assert loaded.hex() not in combined


def test_default_pepper_path_is_outside_repo_and_home_scoped():
    repo_root = Path(__file__).resolve().parents[2]

    assert repo_root not in pepper_mod.DEFAULT_PEPPER_PATH.parents
    assert Path.home() in pepper_mod.DEFAULT_PEPPER_PATH.parents


def test_pepper_module_never_references_graph_store():
    source = inspect.getsource(pepper_mod)
    assert "store" not in source.lower()
