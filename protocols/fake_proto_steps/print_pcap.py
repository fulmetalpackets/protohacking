from scapy.all import *
from proto2 import *

pcapFile = sys.argv[1]
packets = rdpcap(pcapFile)

for p in packets:
    if secondpacket in p:
        p.show()
