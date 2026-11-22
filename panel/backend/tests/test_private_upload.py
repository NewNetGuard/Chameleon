# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_panel.stealth.context import _upload_private_text  # noqa: E402


def test_upload_sets_permissions_before_writing():
    sftp = MagicMock()
    sftp.stat.return_value = SimpleNamespace(st_mode=0o40700)
    temporary = _upload_private_text(sftp, "/opt/chameleon/server_config.json", "test fixture")
    directory = temporary.rsplit("/", 1)[0]
    assert sftp.mock_calls == [
        call.mkdir(directory, 0o700), call.stat(directory), call.file(temporary, "xw"),
        call.file().__enter__(), call.file().__enter__().chmod(0o600),
        call.file().__enter__().write("test fixture"),
        call.file().__exit__(None, None, None),
    ]


def test_upload_never_opens_file_in_an_accessible_directory():
    sftp = MagicMock()
    sftp.stat.return_value = SimpleNamespace(st_mode=0o40755)
    with pytest.raises(OSError, match="private staging directory"):
        _upload_private_text(sftp, "/opt/chameleon/server_config.json", "test fixture")
    sftp.file.assert_not_called()
    sftp.rmdir.assert_called_once()
