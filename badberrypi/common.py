from dataclasses import dataclass, field
from subprocess import DEVNULL, PIPE, Popen

from badberrypi.log import info


def run_code(code: str, sync: bool = True) -> str:
    """
    Run bash code through subproccess
    """
    info(code)
    P = Popen(code, shell=True, stdout=PIPE, stderr=DEVNULL)
    return P.communicate()[0] if sync else P


@dataclass
class Device:
    bssid: str
    frames: dict

    def __eq__(self, other):
        return self.bssid == other.bssid

    def __hash__(self):
        return hash(self.bssid)


@dataclass
class AP(Device):
    essid: str
    rssi: str


@dataclass
class STA(Device):
    pass
