from scapy.all import *

class Header(Packet):
    name = "Header"
    fields_desc = [ IPField("ipaddress", "127.0.0.1"), 
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
class thirdpacket(Packet):
    name = "udp packet"
    fields_desc = [ 
        XShortField("unknown1",0),
        FieldLenField("session_len",None, length_of="sessionId"), 
        XStrLenField("sessionId", "", length_from=lambda x:x.session_len),
        #Decimal degrees (DD): 41.40338, 2.17403
        FieldLenField("geo_len",None, length_of="geo"), 
        StrLenField("geo", "41.40338,2.17403", length_from=lambda x:x.geo_len),
        StrFixedLenField("unknown2","",3)
    ]

class fourthpacket(Packet):
    name = "fourth packet"
    fields_desc = [
        XShortField("counter",0), 
        FieldLenField("random_data_len",None, length_of="random_data"), 
        XStrLenField("random_data","",length_from=lambda x:x.random_data_len), 
        XShortField("unknown1",0)  
    ]
bind_layers(TCP,Header,dport=1234)
bind_layers(UDP,Header,dport=4321)
bind_layers(Header,firstpacket,unknown_field=1)
bind_layers(Header,secondpacket,unknown_field=2)
bind_layers(Header,thirdpacket,unknown_field=3)
bind_layers(Header,fourthpacket,unknown_field=4)

