from scapy.all import *

class Header(Packet):
    name = "Header"
    fields_desc = [ IPField("ipaddress", "127.0.0.1"), #consider using SourceIPField type?
                    ShortField("unknown_field",1),

    ]

class firstpacket(Packet):
    name = "first"
    fields_desc = [ 
                    FieldLenField("session_len",None, length_of="session_id"), 
                    XStrLenField("session", "", length_from=lambda x:x.session_len)

    ]

class secondpacket(Packet):
    name = "second"
    fields_desc = [ 
                    FieldLenField("session_len",None, length_of="session_id"), 
                    XStrLenField("session", "", length_from=lambda x:x.session_len),
                    ShortField("tcp_count",0),
    ]

bind_layers(TCP,Header,dport=1234)
bind_layers(Header,firstpacket,unknown_field=1)
bind_layers(Header,secondpacket,unknown_field=2)