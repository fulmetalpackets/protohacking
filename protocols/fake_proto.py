from scapy.all import *
import crc16


class chksumField(XShortField):
#    __slots__ = ["chksm"]

    def __init__(self,name):
#        self.chksm = 0xffff
        XShortField.__init__(self,name,0xffff)

    def calc(self,b):
        return crc16.crc16xmodem(b)

#    def i2h(self,pkt,val):
        # val is a byte array
#       return self.chksm

    def addfield(self,pkt,s,val):
        #self.chksm = self.calc(s)
        return XShortField.addfield(self,pkt,s,self.calc(s))



#Probably need to come up with a name for this type of packet? 
#header layer which is the same for all packet types
class Header(Packet):
    name = "Header"
    fields_desc = [ IPField("ipaddress", "127.0.0.1"), #consider using SourceIPField type?
                    ShortEnumField("message_type",1,{1:"request",2:"respond",3:"heartbeat",4:"data"}),

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
        XStrLenField("sessionId", "", length_from=lambda x:x.session_len),
        #Decimal degrees (DD): 41.40338, 2.17403
        FieldLenField("geo_len",None, length_of="geo"), 
        StrLenField("geo", "41.40338,2.17403", length_from=lambda x:x.geo_len),
        XByteField("Motion",0x0),
        chksumField("checksum") 
    ]

class Data(Packet):
    name = "Data transfer packet"
    fields_desc = [
        XShortField("remaining",0), #packets remaining in stream
        FieldLenField("data_len",None, length_of="data"), 
        XStrLenField("data","",length_from=lambda x:x.data_len), #compressed
        chksumField("checksum")  
    ]

bind_layers(Header,Request,message_type=1)
bind_layers(Header,Respond,message_type=2)
bind_layers(Header,Heartbeat,message_type=3)
bind_layers(Header,Data,message_type=4)
bind_layers(TCP,Header,dport=1234)
bind_layers(TCP,Header,sport=1234)
bind_layers(UDP,Header,dport=4321)
bind_layers(UDP,Header,dport=4321)
