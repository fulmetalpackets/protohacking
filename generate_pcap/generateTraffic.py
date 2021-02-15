from scapy.all import *
from fake_proto import *
import socket
import sys 
import time
import os
import requests

compressed_file = "stuff.gz"
session_id = os.urandom(5) 
server_ip = "192.168.7.135"
local_ip = "192.168.7.140"
hb_int = 0
pkt_sent = 0
gcount = 0
#get random coordinates for hb packet
resp = requests.get("https://api.3geonames.org/?randomland=yes&json=1")
resp_json = resp.json()
geo_coordinates = resp_json['major']['latt'] + ',' + resp_json['major']['longt']
hb = IP(dst=server_ip)/UDP(sport=4321,dport=4321)/Header(ipaddress="192.168.7.140",message_type=3)/Heartbeat(count=gcount,sessionId=session_id,geo=geo_coordinates)

#Create UDP/IP Socket
#Only so can remove ICMP responses
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#Bind the udp socket to the port
udp_server_address = (local_ip,4321)
print('starting up udp port on: ',udp_server_address)
udp_socket.bind(udp_server_address)

#Create TCP StreamSocket
s=socket.socket()
s.connect((server_ip,1234))
ss=StreamSocket(s,Raw) #generates connected message
time.sleep(1) #wait for "waiting for data...." message

#first packet - request
request=Header(ipaddress="192.168.7.140")/Request(sessionId=session_id)
request.show()
response_pkt = ss.sr1(request)
response_pkt.show()
if response_pkt.load[4:6] == b'\x00\x02': #reponds packet identifier
    hb_int = int.from_bytes(x.load[-2:], byteorder='big')
else:
    print("wrong packet type sent")
    sys.exit()

#send hb packet
send(hb)
#allow for sockets to settle
time.sleep(.2)
gcount = gcount +1 
#build/send data packet
with open(compressed_file, mode='rb') as file: 
    stuff = file.read()

#break datastream into chunks
chunks, chunk_size = len(stuff), 100
list_stuff = [ stuff[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
data_remaining = len(list_stuff)-1 #account for 0 math
for item in list_stuff:
    data_pk = Header(ipaddress="192.168.7.140",message_type=4)/Data(remaining=data_remaining,data=item)
    #check if we need to send hb
    if pkt_sent != 0 and pkt_sent % hb_int == 0:
        hb[Heartbeat].count=gcount
        gcount = gcount + 1
        send(hb)
        pkt_sent = 0
    #send data
    data_pk.show()
    ss.send(data_pk)
    time.sleep(.2)
    data_remaining = data_remaining -1
    pkt_sent = pkt_sent + 1
time.sleep(1)#wait for last packet
s.close()