from scapy.all import *
from fake_proto import *
import socket
import sys

server_ip='192.168.7.135'
gcount = 0
session = b''
def parse_data(pkt):
    global gcount
    global session
    if Request in pkt:
        pkt.show()
        session = pkt[TCP][Request].sessionId
        p = Header(ipaddress="192.168.7.135",message_type=2)/Respond(sessionId=session,heartbeat_interval=3)
        #p.show()
        tcp_connection.sendall(bytes(p))
    if Data in pkt:
        pkt.show()
        gcount= gcount +1
        if pkt[TCP][Data].remaining == 0:
            p = IP(dst=pkt[IP].src)/UDP(sport=4321,dport=4321)/Header(ipaddress="192.168.7.135",message_type=3)/Heartbeat(count=gcount,sessionId=session)
            #p.show()
            send(p)
    if Heartbeat in pkt:
        pkt.show()
        print("HB recieved")
        
    # return True

#Create UDP/IP Socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#Bind the udp socket to the port
udp_server_address = (server_ip,4321)
print('starting up udp port on: ',udp_server_address)
udp_socket.bind(udp_server_address)

# Create a TCP/IP socket
tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the tcp socket to the port
tcp_server_address = (server_ip, 1234)
print('starting up tcp port on: ',tcp_server_address)
tcp_sock.bind(tcp_server_address)
tcp_sock.listen(1)
tcp_connection, tcp_client_address = tcp_sock.accept()



traffic_filter = "(tcp and port 1234) or (udp and port 4321)"
print("sniffing...")
sniff(stop_filter=parse_data,filter=traffic_filter,iface="ens160")


