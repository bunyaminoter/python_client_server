#!/usr/bin/env python3
"""
Server launcher script
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from server.server import main

if __name__ == "__main__":
    main()

