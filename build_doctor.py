#!/usr/bin/env python3
"""ソース一式から直接起動するためのエントリポイント。"""

import sys

from build_doctor.cli import main

if __name__ == "__main__":
    sys.exit(main())
