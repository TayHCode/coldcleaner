"""Run the project suite on every CPU and reject empty or partial runs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import contextlib
import itertools
import json
import os
import pwd
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / 'tests'
CHUNK = 20
SHARD_TIMEOUT = 1800
MARK = 'COLDCLEANER-SHARD '
JUNIT_ENV = ('COLD_VERIFY_JUNIT_DIR', 'COLD_VERIFY_JUNIT_KEY')
CHILD = '''
import importlib.util, json, os, sys, unittest
sys.path.insert(0, sys.argv[1])
base = unittest.TextTestResult
if os.environ.get('COLD_VERIFY_UNITTEST'):
    spec = importlib.util.spec_from_file_location('cold_verify_unittest', os.environ['COLD_VERIFY_UNITTEST'])
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    base = adapter.JUnitResult
    base.junit_dir, base.junit_key = adapter.take_junit_environment()
ran = []
class Result(base):
    def startTest(self, test):
        ran.append(test.id())
        super().startTest(test)
result = Result(unittest.runner._WritelnDecorator(sys.stderr), True, 2)
unittest.registerResult(result)
result.startTestRun()
unittest.defaultTestLoader.loadTestsFromNames(sys.argv[2:])(result)
result.stopTestRun()
result.printErrors()
held = []
for test, _ in result.skipped:
    if not isinstance(test, unittest.TestCase):
        scope = test.description.split(' (', 1)[-1].rstrip(')') + '.'
        held += [name for name in sys.argv[2:] if name.startswith(scope) and name not in ran + held]
print(%r + json.dumps(dict(ran=ran, held=held, ok=result.wasSuccessful(), skipped=len(result.skipped),
                           failures=len(result.failures) + len(result.unexpectedSuccesses),
                           errors=len(result.errors))), file=sys.stderr)
''' % MARK


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def scope(test):
    cls = type(test)
    module = sys.modules[cls.__module__]
    if hasattr(module, 'setUpModule') or hasattr(module, 'tearDownModule'):
        return cls.__module__, True
    return cls, (cls.setUpClass.__func__ is not unittest.TestCase.setUpClass.__func__
                 or cls.tearDownClass.__func__ is not unittest.TestCase.tearDownClass.__func__)


def shards(tests):
    for (_, whole), group in itertools.groupby(tests, key=scope):
        group = list(group)
        size = len(group) if whole else CHUNK
        for start in range(0, len(group), size):
            yield [test.id() for test in group[start:start + size]]


def run_shard(ids, home, junit):
    env = dict(os.environ, HOME=tempfile.mkdtemp(dir=home), **junit)
    shard = subprocess.Popen([sys.executable, '-B', '-c', CHILD, str(TESTS), *ids], cwd=ROOT, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             start_new_session=True)
    try:
        output, _ = shard.communicate(timeout=SHARD_TIMEOUT)
        code = shard.returncode
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(shard.pid, signal.SIGKILL)
        output, _ = shard.communicate()
        code = 'timeout after %ss' % SHARD_TIMEOUT
    head, _, tail = output.rpartition(MARK)
    try:
        summary = json.loads(tail)
    except ValueError:
        return output, None, code
    return head, summary, code


def main():
    junit = {name: os.environ.pop(name) for name in JUNIT_ENV if name in os.environ}
    sys.path.insert(0, str(ROOT))
    started = time.monotonic()
    discovered = unittest.TestLoader().discover(str(TESTS))
    tests = list(flatten(discovered))
    if not tests:
        raise SystemExit('FAIL: no tests discovered in tests')
    broken = [test for test in tests if test.id().startswith('unittest.loader.')]
    for test in broken:
        print('ERROR: %s\n%s' % (test.id(), test._exception), file=sys.stderr)
    with tempfile.TemporaryDirectory(prefix='.coldcleaner-verify-home-',
                                     dir=pwd.getpwuid(os.getuid()).pw_dir) as home:
        work = list(shards([test for test in tests if test not in broken]))
        with ThreadPoolExecutor(os.process_cpu_count() or 1) as pool:
            results = list(pool.map(lambda ids: run_shard(ids, home, junit), work))
    ran, held, totals, problems = [], [], dict(failures=0, errors=len(broken), skipped=0), []
    for ids, (output, summary, code) in zip(work, results):
        sys.stderr.write(output)
        if summary is None:
            problems.append('shard %s..%s ended without a result (exit %s)' % (ids[0], ids[-1], code))
            continue
        ran += summary['ran']
        held += summary['held']
        for key in totals:
            totals[key] += summary[key]
        if not summary['ok'] or code != 0:
            problems.append('shard %s..%s failed (exit %s)' % (ids[0], ids[-1], code))
    expected = [test.id() for test in tests]
    accounted = ran + held
    missing, extra = sorted(set(expected) - set(accounted)), sorted(set(accounted) - set(expected))
    match = not (missing or extra or len(accounted) != len(set(accounted)))
    print('Discovered %d ids; ran %d + skipped by a class or module fixture %d; ids match: %s'
          % (len(expected), len(ran), len(held), match), file=sys.stderr)
    if not match:
        problems.append('not run: %s; unexpected: %s' % (missing, extra))
    print('-' * 70, file=sys.stderr)
    print('Ran %d tests in %.3fs\n' % (len(ran), time.monotonic() - started), file=sys.stderr)
    for problem in problems:
        print('FAIL: ' + problem, file=sys.stderr)
    if problems or broken:
        print('FAILED (failures=%(failures)d, errors=%(errors)d, skipped=%(skipped)d)' % totals,
              file=sys.stderr)
        return 1
    print('OK (skipped=%(skipped)d)' % totals if totals['skipped'] else 'OK', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
