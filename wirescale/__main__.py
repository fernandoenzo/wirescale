#!/usr/bin/env python3
# encoding:utf-8


import sys
from pathlib import Path

GLOBAL_PARENT = Path(__file__).parent.resolve()
SCRIPT_PATH = GLOBAL_PARENT.joinpath('scripts')
sys.path.insert(0, str(GLOBAL_PARENT))

if __name__ == '__main__':
    from wirescale.wirescale import main

    main()
