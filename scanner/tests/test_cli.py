from __future__ import annotations

import pytest

from nodeprobe import __version__
from nodeprobe.cli import main


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"nodeprobe {__version__}"
