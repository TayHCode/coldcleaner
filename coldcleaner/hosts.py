import base64
import gzip
import json
import os
import re
import shlex
import subprocess
import sys
import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class Host:
    name: str
    kind: str
    ssh: str | None = None
    distro: str | None = None


LOCAL = Host("local", "posix")
HOSTS: dict[str, Host] = {}

SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]


def argv(host: Host, script: str) -> list[str]:
    if host.kind == "posix":
        return ["bash", "-c", script] if host.ssh is None else [*SSH, host.ssh, "bash -c " + shlex.quote(script)]
    if host.kind == "wsl":
        encoded = base64.b64encode(gzip.compress(script.encode("utf-8", "surrogateescape"), mtime=0)).decode()
        launcher = f"import base64,gzip,os;os.execvp('bash',['bash','-c',gzip.decompress(base64.b64decode('{encoded}')).decode('utf-8','surrogateescape')])"
        return [*SSH, host.ssh, f'wsl.exe -e python3 -c "{launcher}"']
    if host.ssh is None:
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"]
    return [*SSH, host.ssh, "powershell -NoProfile -NonInteractive -Command -"]


def run(host: Host, script: str, *, check: bool = True, timeout: float = 3600,
        stdout=subprocess.PIPE, stdin_bytes: bytes | None = None, progress: bool = False) -> subprocess.CompletedProcess:
    if host.kind in ("wsl", "wsl-maintenance"):
        raise ValueError("Windows WSL execution is retired; use an explicitly approved execution host")
    cmd = argv(host, script)
    if host.kind == "powershell":
        stdin_bytes = script.encode()
    if not progress:
        return subprocess.run(cmd, input=stdin_bytes, stdout=stdout, stderr=subprocess.PIPE,
                              check=check, timeout=timeout)
    chunks = []
    finished = threading.Event()
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    with os.fdopen(read_fd, 'rb') as reader, os.fdopen(write_fd, 'wb') as writer:
        def forward():
            while True:
                data = reader.read(65536)
                if data:
                    chunks.append(data)
                    sys.stderr.write(data.decode(errors='replace'))
                    sys.stderr.flush()
                elif finished.is_set():
                    return
                else:
                    finished.wait(0.1)
        worker = threading.Thread(target=forward)
        worker.start()
        try:
            result = subprocess.run(cmd, input=stdin_bytes, stdout=stdout, stderr=writer,
                                    check=False, timeout=timeout)
        finally:
            finished.set()
            worker.join()
    result.stderr = b''.join(chunks)
    if check:
        result.check_returncode()
    return result


def popen(host: Host, script: str, **kwargs) -> subprocess.Popen:
    if host.kind in ("wsl", "wsl-maintenance"):
        raise ValueError("Windows WSL execution is retired; use an explicitly approved execution host")
    if host.kind == "powershell":
        raise ValueError("streaming is only supported on posix and wsl hosts")
    return subprocess.Popen(argv(host, script), **kwargs)


def python_argv(host):
    if host.kind == 'wsl':
        raise ValueError('Windows WSL execution is retired')
    code = 'import sys,json;exec(json.loads(sys.stdin.buffer.readline()))'
    if host.kind == 'wsl-maintenance':
        if not host.ssh or not host.distro or not re.fullmatch(r'[A-Za-z0-9._-]+', host.distro):
            raise ValueError('explicit WSL bridge and distro required')
        return [*SSH, host.ssh, 'wsl.exe -d ' + host.distro + ' -u root -e python3 -c "' + code + '"']
    if host.kind == 'powershell':
        if host.ssh is None:
            return ['python.exe', '-c', code]
        return [*SSH, host.ssh, 'python.exe -c "' + code + '"']
    return argv(host, 'python3 -c ' + shlex.quote(code))


def python_payload(source, request):
    return json.dumps(source).encode() + b'\n' + json.dumps(request).encode() + b'\n'


def python_run(host, source, request, *, timeout=900):
    return subprocess.run(python_argv(host), input=python_payload(source, request),
                          capture_output=True, check=True, timeout=timeout)


def python_stream(host, source, request, *, stderr):
    process = subprocess.Popen(python_argv(host), stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=stderr)
    process.stdin.write(python_payload(source, request))
    process.stdin.close()
    return process


def python_sink(host, *, stdin, stderr):
    return subprocess.Popen(python_argv(host), stdin=stdin,
                            stdout=subprocess.PIPE, stderr=stderr)
