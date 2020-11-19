from scapy.all import *
import socket, struct

def long2ip(ip):
    return socket.inet_ntoa(ip)

    # Convert an IP string to long
def ip2long(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

#expects list of tuples where the first value is compared with the passed in value
def compare(in_list,in_value):
    for t in in_list:
        if in_value == t[0]:
            return True
    return False

# don't save duplicates
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

pcapFile = sys.argv[1]
packets = rdpcap(pcapFile)
packetIps = []
payloadIps = []
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

print("\n########## Possible IPs found in payloads ##############")
for i in payloadIps:
    print("Packet Number:" + str(i[1]) + " IP: " + i[0])

print("\n########## Possible IPs found in payload that match packets source or destination IPs ##############")
for m in matchIps:
    print("Packet Number:" + str(m[1]) + " IP: " + m[0])