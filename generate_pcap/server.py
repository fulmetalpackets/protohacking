import os
import socket
import sys
import time

# Add repo's root directory to path so we can import from protocols/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generate_pcap.generateTraffic import TCP_PORT, UDP_PORT, LONG_SLEEP_DUR
from protocols.fake_proto import *
from scapy.all import *

# Global variables.
server_ip = get_if_addr(conf.iface)
gcount = 0
session = b''
tcp_connection = None

# Used by the server to parse incoming packets via TCP/UDP and respond.
def parse_data(receive_pkt):
    global gcount
    global session
    if Request in receive_pkt:
        print('Received the following request packet via TCP:')
        receive_pkt.show()
        session = receive_pkt[TCP][Request].sessionId
        send_pkt = (Header(ipaddress=server_ip, message_type=2)
                    /Respond(sessionId=session, heartbeat_interval=random.randint(1, 7)))
        print('Sending the following response packet via TCP:')
        send_pkt.show()
        tcp_connection.sendall(bytes(send_pkt))
    elif Data in receive_pkt:
        print('Received the following data packet via TCP:')
        receive_pkt.show()
        gcount += 1
        if receive_pkt[TCP][Data].remaining == 0:
            send_pkt = (IP(dst=receive_pkt[IP].src)
                        /UDP(sport=UDP_PORT, dport=UDP_PORT)
                        /Header(ipaddress=server_ip, message_type=3)
                        /Heartbeat(count=gcount, sessionId=session))
            print('Sending the following heartbeat packet via UDP:')
            send_pkt.show()
            send(send_pkt)
    elif Heartbeat in receive_pkt:
        print('Received the following heartbeat packet via UDP:')
        receive_pkt.show()
    elif TCP in receive_pkt and receive_pkt[TCP].flags.F:
        print('Received TCP FIN from client.')
        return True

#Create a UDP socket.
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_udp_address = (server_ip, UDP_PORT)
print(f'Starting up UDP port on: {server_udp_address}')
udp_socket.bind(server_udp_address)

# Create a TCP socket.
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_tcp_address = (server_ip, TCP_PORT)
print(f'Starting up TCP port on: {server_tcp_address}')
tcp_socket.bind(server_tcp_address)
tcp_socket.listen(1)

# Continue to accept TCP connections and respond to traffic via parse_data().
while True:
    print('Waiting for connection from client...')
    tcp_connection, _ = tcp_socket.accept()
    traffic_filter = f'(tcp and port {TCP_PORT}) or (udp and port {UDP_PORT})'
    print(f'Sniffing traffic using the filter "{traffic_filter}"...')
    sniff(stop_filter=parse_data, filter=traffic_filter, iface=conf.iface)
    time.sleep(LONG_SLEEP_DUR)
    tcp_connection.close()
    time.sleep(LONG_SLEEP_DUR)
