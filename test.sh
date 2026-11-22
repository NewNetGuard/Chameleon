#!/usr/bin/env bash
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Run every Chameleon Go test with the repository-pinned toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_BIN="$(bash "${ROOT}/ensure-go.sh")"
cd "${ROOT}"
exec "${GO_BIN}" test ./...
