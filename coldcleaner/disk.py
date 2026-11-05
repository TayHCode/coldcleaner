import json
import shlex
import subprocess
from dataclasses import dataclass

from . import hosts


@dataclass(frozen=True)
class Usage:
    total: int
    used: int
    percent: float


def python(host, source, *args, timeout=300, stdin_bytes=None, progress=False):
    command = '-c ' + shlex.quote(source) if stdin_bytes is not None else '-'
    script = 'python3 ' + command + ' ' + ' '.join(shlex.quote(json.dumps(arg)) for arg in args)
    if stdin_bytes is None:
        script += " <<'COLD_PY'\n" + source + '\nCOLD_PY\n'
    try:
        result = hosts.run(host, script, timeout=timeout, stdin_bytes=stdin_bytes, progress=progress)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f'remote probe exceeded {timeout} seconds') from None
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors='replace').strip() if exc.stderr else 'no diagnostic output'
        raise RuntimeError(f'remote probe failed: {detail[-1000:]}') from None
    return json.loads(result.stdout)


def powershell(host, script, **kwargs):
    wrapped = "$ErrorActionPreference='Stop'\ntry {\n" + script + "\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n\n"
    return hosts.run(host, wrapped, **kwargs)


def measure(host):
    target = hosts.Host(host.name, 'powershell', host.ssh) if host.kind == 'wsl' else host
    if target.kind == 'powershell':
        script = "$ErrorActionPreference='Stop'; $d=Get-PSDrive C; @{total=($d.Used+$d.Free);used=$d.Used} | ConvertTo-Json -Compress"
        result = json.loads(powershell(target, script, timeout=60).stdout)
        total, used = int(result['total']), int(result['used'])
        percent = used * 100 / total if total else 0
    else:
        result = hosts.run(target, 'if [ "$(uname -s)" = Darwin ]; then df -Pk /System/Volumes/Data; else df -Pk /; fi', timeout=60)
        columns = result.stdout.decode().splitlines()[-1].split()
        total, used = int(columns[1]) * 1024, int(columns[2]) * 1024
        percent = float(columns[4].rstrip('%'))
    if total <= 0 or not 0 <= used <= total or not 0 <= percent <= 100:
        raise ValueError('invalid disk usage')
    return Usage(total, used, percent)
