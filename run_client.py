#!/usr/bin/env python3
"""
Client launcher script
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from client.client import main

if __name__ == "__main__":
    main()

