from scapy.all import *

#Probably need to come up with a name for this type of packet? 
#header layer which is the same for all packet types
class Header(Packet):
    name = "Header"
    fields_desc = [ IPField("ipaddress", "127.0.0.1"), #consider using SourceIPField type?
                    ShortEnumField("message_type",1,{1:"request",2:"respond",3:"heartbeat",4:"data"}),
                    XShortField("checksum",0x1111) 

    ]

class Request(Packet):
    name = "Request packet"
    fields_desc = [
        FieldLenField("session_len",None, length_of="sessionId"), 
        XStrLenField("sessionId", "", length_from=lambda x:x.session_len)
    ]

class Respond(Packet): 
    name = "Respond packet"
    fields_desc = [
        FieldLenField("session_len",None, length_of="sessionId"), 
        XStrLenField("sessionId", "", length_from=lambda x:x.session_len),
        XShortField("heartbeat_interval",0) #how many packets allowed between heartbeats
    ]

class Heartbeat(Packet):
    name = "Heartbeat packet"
    fields_desc = [ 
        XShortField("count",0),
        FieldLenField("session_len",None, length_of="sessionId"), 
        XStrLenField("sessionId", "", length_from=lambda x:x.session_len)
    ]

class Data(Packet):
    name = "Data transfer packet"
    fields_desc = [
        XShortField("remaining",0), #packets remaining in stream
        FieldLenField("data_len",None, length_of="data"), 
        XStrLenField("data","",length_from=lambda x:x.data_len) #compressed
    ]

bind_layers(Header,Request,message_type=1)
bind_layers(Header,Respond,message_type=2)
bind_layers(Header,Heartbeat,message_type=3)
bind_layers(Header,Data,message_type=4)
bind_layers(TCP,Header,dport=1234)
bind_layers(TCP,Header,sport=1234)
