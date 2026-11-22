#!/bin/bash
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Print SOURCE.txt for a release package: where the source code of exactly this
# version is available, as MPL-2.0 section 3.2(a) requires for the programs and
# the built web panel in the package.
#
#   panel/source-notice.sh <version>
#
# CHAMELEON_SOURCE_URL overrides the repository address.
set -euo pipefail

VERSION="${1:?version required}"
URL="${CHAMELEON_SOURCE_URL:-https://github.com/NewNetGuard/Chameleon}"

cat <<EOF
Chameleon $VERSION — source code

The programs and the web panel in this package are built from the Chameleon
source code of version $VERSION, licensed under the Mozilla Public License 2.0
(LICENSE). That source code is available at:

    $URL/tree/v$VERSION

and as a source archive with the release:

    $URL/releases/tag/v$VERSION

Licenses in this package:
    LICENSE                   Mozilla Public License 2.0 (Chameleon's own code)
    NOTICE                    exceptions: WireGuard files (MIT), nginx patch
                              context (BSD-2-Clause), images, names
    THIRD_PARTY_LICENSES.txt  every third-party component and its license text
EOF
