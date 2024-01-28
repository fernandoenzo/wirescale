#!/usr/bin/env python3
# encoding:utf-8


import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

if __name__ == '__main__':
    from wirescale.main import main

    main()
