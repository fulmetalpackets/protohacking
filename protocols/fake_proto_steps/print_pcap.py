from scapy.all import *
from proto1 import *

pcapFile = sys.argv[1]
packets = rdpcap(pcapFile)

for p in packets:
    if firstpacket in p:
        p.show()
