from scapy.all import *
from fake_proto import *
import socket
import sys 
import time

compressed_file = "stuff.gz"
session_id = b'\x12\x34\x11\x21\x90'
server_ip = "192.168.7.135"
local_ip = "192.168.7.140"
hb_int = 0
pkt_sent = 0
gcount = 0
hb = IP(dst=server_ip)/UDP(sport=4321,dport=4321)/Header(ipaddress="192.168.7.140",message_type=3)/Heartbeat(count=gcount,sessionId=session_id)

#Create UDP/IP Socket
#Only so can remove ICMP
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#Bind the udp socket to the port
udp_server_address = (local_ip,4321)
print('starting up udp port on: ',udp_server_address)
udp_socket.bind(udp_server_address)

#Create TCP StreamSocket
s=socket.socket()
s.connect((server_ip,1234))
ss=StreamSocket(s,Raw) #generates connected message
time.sleep(1) #wait for waiting for data message

#first packet - request
request=Header(ipaddress="192.168.7.140")/Request(sessionId=session_id)
request.show()
x = ss.sr1(request)
x.show()
if x.load[4:6] == b'\x00\x02': #reponds packet
    hb_int = int.from_bytes(x.load[-2:], byteorder='big')
else:
    print("wrong packet type sent")
    sys.exit()

#send hb packet
send(hb)
time.sleep(.2)
gcount = gcount +1 
#build/send data packet
#stuff = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbcccccccccccccccdddddddddddddddddeeeeeeeeeeeeeeeeeeffffffffffffffffffffggggggggggg"
with open(compressed_file, mode='rb') as file: 
    stuff = file.read()

chunks, chunk_size = len(stuff), 100
list_stuff = [ stuff[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
data_remaining = len(list_stuff)-1 #account for 0 math
for item in list_stuff:
    d = Header(ipaddress="192.168.7.140",message_type=4)/Data(remaining=data_remaining,data=item)
    #check if we need to send hb
    if pkt_sent != 0 and pkt_sent % hb_int == 0:
        hb[Heartbeat].count=gcount
        gcount = gcount + 1
        send(hb)
        pkt_sent = 0
    #send data
    d.show()
    ss.send(d)
    time.sleep(.2)
    data_remaining = data_remaining -1
    pkt_sent = pkt_sent + 1
time.sleep(1)#wait for last packet
s.close()


#data=Packet()/IP(dst="192.168.5.25")/TCP(dport=1234)
#data[TCP].payload = x
#print(Header(data))
#data.show()
