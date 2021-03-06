#By Douglas McKee @fulmetalpackets

from scapy.all import *
import socket, struct
import argparse 

#expects a long to convert to an ip address using socket
def long2ip(ip):
    return socket.inet_ntoa(ip)

#expects list of tuples where the first value is compared with the passed in value
def compare(in_list,in_value):
    for t in in_list:
        if in_value == t[0]:
            return True
    return False

# don't save duplicates
# only searches startin at the first byte of the payload and moves every 4 bytes.  Does not consider every possible 4 byte combination.
def searchPayload(payload):
    x = 0
    while True:
        temp = payload[x:x+4]
        if len(temp) % 4  == 0 and temp != b'':
            ip = long2ip(temp)
            if not compare(payloadIps,ip):
                payloadIps.append((ip,packetNumber))
            if compare(packetIps,ip) and not compare(matchIps,ip):
                matchIps.append((ip,packetNumber))
        else:
            break
        x = x + 4

# main
parser = argparse.ArgumentParser()
parser.add_argument("pcapFile", help="pcap file to search for IPs in payload")
parser.add_argument("-a",'--all', dest='all', default=False, action='store_true',help="Display all matches. Default only displays IPs found also in IP header")
args = parser.parse_args()
packets = rdpcap(args.pcapFile)
#list of IPs found in the IP layer of the packets
packetIps = []
#list of valid IP addresses found in the payloads of the packets
payloadIps = []
# IPs found in the payload that match any IPs in the IP layers
matchIps = []

packetNumber = 1
payload = None

for p in packets:
    if p[IP].src not in packetIps:
        packetIps.append((p[IP].src,packetNumber))
    if p[IP].dst not in packetIps:
        packetIps.append((p[IP].dst,packetNumber))

    if TCP in p and type(p[TCP].payload) != scapy.packet.NoPayload:
        payload = bytes(p[TCP].payload)
    if UDP in p and type(p[UDP].payload) != scapy.packet.NoPayload:
        payload = bytes(p[UDP].payload)
    if payload is not None:
        searchPayload(payload)
    packetNumber = packetNumber + 1

print("\n*** Only reporting first packet IP is discovered in ***")
if args.all:
    print("\n########## Possible IPs found in payloads ##############")
    for i in payloadIps:
        print("Packet Number:" + str(i[1]) + " IP: " + i[0])

print("\n########## Possible IPs found in payload that match packets source or destination IPs ##############")
for m in matchIps:
    print("Packet Number:" + str(m[1]) + " IP: " + m[0])