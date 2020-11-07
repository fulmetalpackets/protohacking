from scapy.all import *
from fake_proto import *
import socket
import sys


gcount = 0
session = b'';
def parse_data(pkt):
    global gcount
    global session
    pkt.show()
    if Request in pkt:
        session = pkt[TCP][Request].sessionId
        #p = IP(dst=pkt[IP].src)/TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport)/Header(message_type=2)/Respond(sessionId=pkt[TCP][Request].sessionId,heartbeat_interval=5)
        p = Header(ipaddress="192.168.7.135",checksum=0x1212,message_type=2)/Respond(sessionId=session,heartbeat_interval=3)
        p.show()
        connection.sendall(bytes(p))
    if Data in pkt:
        gcount= gcount +1
        if pkt[TCP][Data].remaining == 0:
            p = Header(ipaddress="192.168.7.135",checksum=0x1212,message_type=3)/Heartbeat(count=gcount,sessionId=session)
            p.show()
            connection.sendall(bytes(p))
    if Heartbeat in pkt:
        print("HB recieved")
        
    # return True

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('192.168.7.135', 1234)
print('starting up on: ',server_address)
sock.bind(server_address)
sock.listen(1)
connection, client_address = sock.accept()
traffic_filter = "tcp and port 1234"
print("sniffing...")
sniff(stop_filter=parse_data,filter=traffic_filter,iface="ens160")


'''
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('172.24.173.126', 1234)
print('starting up on: ',server_address)
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for a connection...')
    connection, client_address = sock.accept()
    try:
        print('connection from: ', client_address)

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(16)
            print('received: ' , data)
            if data:
                print('sending data back to the client')
                connection.sendall(data)
            else:
                print('no more data from', client_address)
                break
            
    finally:
        # Clean up the connection
        connection.close()
'''
