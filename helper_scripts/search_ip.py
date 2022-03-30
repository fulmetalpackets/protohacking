# By Douglas McKee @fulmetalpackets

import socket

# Global constants.
IP_SIZE = 4
MAC_SIZE = 6
JSON_FILE = 'search_results.json'

# Converts a byte string to an IPv4 address in human-readable string format.
def bytes_to_ip(ip):
    return socket.inet_ntoa(ip)

# Converts a byte string to a MAC address in human-readable string format.
def bytes_to_mac(mac):
    if len(mac) != MAC_SIZE:
        raise ValueError('MAC address should be exactly six bytes')
    return ':'.join('%02x' % b for b in mac)

# Searches for IPv4 and MAC addresses in a packet payload.
def find_addresses(payload, align):
    ips = set()
    macs = set()
    for i in range(0, len(payload), align):
        ip_chunk = payload[i:i+IP_SIZE]
        if len(ip_chunk) != IP_SIZE:
            break
        ip = bytes_to_ip(ip_chunk)
        ips.add(ip)
        mac_chunk = payload[i:i+MAC_SIZE]
        if len(mac_chunk) == MAC_SIZE:
            mac = bytes_to_mac(mac_chunk)
        macs.add(mac)
    return ips, macs

if __name__ == '__main__':
    import argparse
    import json

    from scapy.all import *

    parser = argparse.ArgumentParser('Find potential IPv4 and MAC addresses in '
                                     'the packet payloads of a PCAP file.')
    parser.add_argument('pcap',
                        help=('The PCAP file that will be searched for IP/MAC '
                              'addresses.'))
    parser.add_argument('-a', '--all', action='store_true',
                        help=('Display all matches. Default only displays '
                              'addresses also found in Ethernet/IP headers'))
    parser.add_argument('-b', '--byte-align', type=int, choices=[1, 2, 4, 6, 8],
                        default=4,
                        help=('Assumes a byte alignment when searching for '
                              'addresses in packet payloads. Default assumes '
                              'addresses are 4-byte aligned.'))
    args = parser.parse_args()

    packets = rdpcap(args.pcap)
    header_ips = []     # IPs found in the IP layer of the packets.
    header_macs = []    # MACs found in the Ethernet layer of the packets.
    payload_ips = []    # IPs found in the payloads of the packets.
    payload_macs = []   # MACs found in the payloads of the packets.

    for pkt_num, pkt in enumerate(packets, 1):
        header_ips.extend([pkt[IP].src, pkt[IP].dst])
        header_macs.extend([pkt[Ether].src, pkt[Ether].dst])

        for proto in [TCP, UDP]:
            if proto in pkt and not isinstance(pkt[proto].payload, NoPayload):
                payload = bytes(pkt[proto].payload)
                ips, macs = find_addresses(payload, args.byte_align)
                payload_ips.extend([(x, pkt_num) for x in ips
                                    if x not in [x[0] for x in payload_ips]])
                payload_macs.extend([(x, pkt_num) for x in macs
                                     if x not in [x[0] for x in payload_macs]])

    matching_ips = [x for x in payload_ips if x[0] in header_ips]
    matching_macs = [x for x in payload_macs if x[0] in header_macs]

    # Print the results to the screen.
    print('\n********* Only reporting first packet IP/MAC address is '
          'discovered in  *********')
    if args.all:
        if payload_ips:
            print('\n################### Possible IP addresses found in '
                  'payloads  ###################')
            for ip in payload_ips:
                print(f'Packet Number: {ip[1]:03} -> IP: {ip[0]}')
        else:
            print('\n################### No IP addresses found in packet '
                  'payloads ###################')
        if payload_macs:
            print('\n################### Possible MAC addresses found in '
                  'payloads ###################')
            for mac in payload_macs:
                print(f'Packet Number: {mac[1]:03} -> MAC: {mac[0]}')
        else:
            print('\n################## No MAC addresses found in packet '
                  'payloads  ##################')

    if matching_ips:
        print('\n############## IPs found in payloads that match IPs in IP '
              'headers ##############')
        for ip in matching_ips:
            print(f'Packet Number: {ip[1]:03} -> IP: {ip[0]}')
    else:
        print('\n############ No IPs found in payloads that match IPs in IP '
              'headers  ############')
    if matching_macs:
        print('\n########## MACs found in payloads that match MACs in Ethernet '
            'headers ##########')
        for mac in matching_macs:
            print(f'Packet Number: {mac[1]:03} -> MAC: {mac[0]}')
    else:
        print('\n######## No MACs found in payloads that match MACs in '
              'Ethernet headers  ########')

    # Save the results to a JSON file.
    results = {}
    if args.all:
        results['All IPs in Payloads'] = [{'Packet Number': y, 'IP': x}
                                          for x, y in payload_ips]
        results['All MACs in Payloads'] = [{'Packet Number': y, 'MAC': x}
                                           for x, y in payload_macs]
    results['IPs Matching IP Headers'] = [{'Packet Number': y, 'IP': x}
                                          for x, y in matching_ips]
    results['MACs Matching Ethernet Headers'] = [{'Packet Number': y, 'MAC': x}
                                                 for x, y in matching_macs]
    with open(JSON_FILE, 'w') as f:
        json.dump(results, f, indent=4)
    print(f'\nResults saved to {JSON_FILE}.')