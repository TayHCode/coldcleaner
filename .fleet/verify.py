"""Run the project suite and reject empty discovery."""
from pathlib import Path
import os
import pwd
import sys
import tempfile
import unittest

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
with tempfile.TemporaryDirectory(prefix='.coldcleaner-verify-home-',
                                 dir=pwd.getpwuid(os.getuid()).pw_dir) as home:
    os.environ['HOME'] = home
    suite = unittest.TestSuite()
    for directory in ('tests',):
        discovered = unittest.TestLoader().discover(str(root / directory))
        if discovered.countTestCases() == 0:
            raise SystemExit('FAIL: no tests discovered in ' + directory)
        suite.addTests(discovered)
    raise SystemExit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
