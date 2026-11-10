import sys

if sys.version_info < (3, 14):
    sys.stderr.write('coldcleaner needs Python 3.14+ (found %d.%d)\n' % tuple(sys.version_info[:2]))
    raise SystemExit(2)
