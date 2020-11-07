from scapy.all import *
from fake_proto import *

pcapFile = sys.argv[1]
packets = rdpcap(pcapFile)

for p in packets:
    if Header in p:
        print(p.summary())
        #p.show()

