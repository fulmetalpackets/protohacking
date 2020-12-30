from scapy.all import *

class firstpacket(Packet):
    name = "first"
    fields_desc = [ IPField("ipaddress", "127.0.0.1"), 
                    ShortField("unknown1",0),
                    FieldLenField("next_len",None, length_of="unknown2"), 
                    XStrLenField("unknown2", "", length_from=lambda x:x.next_len)

    ]

bind_layers(TCP,firstpacket,dport=1234)