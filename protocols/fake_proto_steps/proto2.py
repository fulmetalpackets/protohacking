from scapy.all import *

class firstpacket(Packet):
    name = "first"
    fields_desc = [ IPField("ipaddress", "127.0.0.1"), 
                    ShortField("unknown1",0),
                    FieldLenField("session_len",None, length_of="session_id"), 
                    XStrLenField("session", "", length_from=lambda x:x.session_len)

    ]

class secondpacket(Packet):
    name = "second"
    fields_desc = [ IPField("ipaddress", "127.0.0.1"), 
                    ShortField("unknown1",0),
                    FieldLenField("session_len",None, length_of="session_id"), 
                    XStrLenField("session", "", length_from=lambda x:x.session_len),
                    ShortField("tcp_count",0),

    ]

bind_layers(TCP,firstpacket,dport=1234)