import os
import tempfile
from pathlib import Path

FALLBACKS = ('/dev/shm', '/var/tmp', '/tmp')


def usable(base):
    base = Path(base)
    if not (base.is_dir() and os.access(base, os.W_OK | os.X_OK)):
        return False
    return not any((folder / '.git').exists() for start in (base, base.resolve()) for folder in (start, *start.parents))


def choose(current, fallbacks=FALLBACKS):
    return next((base for base in (current, *fallbacks) if usable(base)), current)


def use():
    tempfile.tempdir = str(choose(tempfile.gettempdir()))
