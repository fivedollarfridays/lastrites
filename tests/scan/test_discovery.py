"""Discovery is a surface-enumeration step, so §5 binds it too.

The parsers are careful to count what they could not read; the layer that
decides which files to hand them must be equally careful about the
directories it could not walk. A `--root` typo that silently finds nothing
is the same false "no copies here" one level up.
"""

import pytest

from lastrites.scan.discovery import discover


def test_finds_each_surface_class_under_a_root(estate):
    found, skips = discover(estate)
    assert len(found["crontabs"]) == 1
    assert len(found["plists"]) == 3
    assert len(found["env_files"]) == 1
    assert skips == []


def test_a_nonexistent_root_is_a_counted_skip_not_an_empty_result(tmp_path):
    found, skips = discover(tmp_path / "typo")
    assert not any(found.values())
    assert len(skips) == 1
    assert "not a directory" in skips[0].reason or "does not exist" in skips[0].reason


def test_a_file_passed_as_a_root_is_a_counted_skip(estate):
    _, skips = discover(estate / "app.env")
    assert len(skips) == 1


def test_noise_directories_are_excluded(tmp_path):
    junk = tmp_path / "node_modules" / "pkg"
    junk.mkdir(parents=True)
    (junk / ".env").write_text("MOCK_TOKEN=mock-1a9c4e77b2d05f63\n")
    found, _ = discover(tmp_path)
    assert found["env_files"] == []


def test_noise_names_above_the_root_do_not_hide_the_root(tmp_path):
    """`--root ~/venv/estate` must scan the estate, not skip it because an
    ancestor happens to be named `venv`."""
    root = tmp_path / "venv" / "estate"
    root.mkdir(parents=True)
    (root / "app.env").write_text("MOCK_TOKEN=mock-1a9c4e77b2d05f63\n")
    found, skips = discover(root)
    assert len(found["env_files"]) == 1
    assert skips == []


@pytest.mark.parametrize(
    "name,bucket",
    [
        (".env", "env_files"),
        (".env.production", "env_files"),
        ("app.env", "env_files"),
        ("com.mock.thing.plist", "plists"),
        ("crontab.txt", "crontabs"),
        ("user-crontab", "crontabs"),
    ],
)
def test_filename_routing(tmp_path, name, bucket):
    (tmp_path / name).write_text("")
    found, _ = discover(tmp_path)
    assert [p.name for p in found[bucket]] == [name]


def test_a_symlinked_directory_is_reported_rather_than_passed_over(tmp_path):
    """os.walk does not follow them; not reporting them is a silent blind spot."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "hidden.env").write_text("MOCK_TOKEN=mock-1a9c4e77b2d05f63\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / "linkdir").symlink_to(outside, target_is_directory=True)

    found, skips = discover(root)
    assert found["env_files"] == []
    assert len(skips) == 1
    assert "symlink" in skips[0].reason


def test_plist_matching_is_case_insensitive(tmp_path):
    (tmp_path / "COM.MOCK.B.PLIST").write_text("")
    found, _ = discover(tmp_path)
    assert len(found["plists"]) == 1


def test_a_dangling_symlink_is_reported_rather_than_ignored(tmp_path):
    link = tmp_path / ".env"
    link.symlink_to(tmp_path / "gone")
    found, skips = discover(tmp_path)
    assert found["env_files"] == []
    assert len(skips) == 1
