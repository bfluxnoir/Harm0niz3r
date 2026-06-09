"""
Make the Harm0nyz3r_client folder importable for tests regardless of where
pytest is invoked from.  Lets the test files do
    from parsers.android_parser import ...
    from commands.android.app_scan import ...
without an editable install.
"""

import os
import sys

_CLIENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _CLIENT_ROOT not in sys.path:
    sys.path.insert(0, _CLIENT_ROOT)
