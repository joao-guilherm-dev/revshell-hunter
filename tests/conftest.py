import pytest

from revshell_hunter.analyzer import Analyzer
from revshell_hunter.config import load_config
from revshell_hunter.models import Connection, ProcessInfo

SYS32 = r"c:\windows\system32"


def make_conn(ip="8.8.8.8", port=443, name="cmd.exe", exe=None, parent="explorer.exe",
              cmdline="", pid=100, lport=50000, user="CORP\\u"):
    if exe is None:
        exe = rf"{SYS32}\{name}"
    proc = ProcessInfo(pid=pid, name=name, exe=exe, cmdline=cmdline, parent=parent, user=user)
    return Connection(remote_ip=ip, remote_port=port, local_ip="10.0.0.5", local_port=lport,
                      pid=pid, process=proc)


@pytest.fixture
def cfg():
    return load_config()


@pytest.fixture
def analyzer(cfg):
    return Analyzer(cfg)
