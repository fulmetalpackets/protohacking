# Hacking Proprietary Protocols
This repository contains the code and PCAPS used for the SANS webinar, "Hacking Proprietary Protocols" given on February 23, 2021.  All code was written with Python 3.

## Authors
Douglas McKee [@fulmetalpackets](https://twitter.com/fulmetalpackets)

Ismael Valenzuela [@aboutsecurity](https://twitter.com/aboutsecurity)

## Presentation Recording
Presentation link: [YouTube](https://www.youtube.com/watch?v=-69E86PnJHM)

## Visual Packet Analysis with Panda
A Jupyter notebook can be found under "packet analysis" and the code can be interacted with by using Binder

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/aboutsecurity/jupyter-notebooks/HEAD)

## Pcaps
These PCAPS contain generated packets of a fake protocol created for this specific webinar.  The protocol was designed to have features commonly seen in proprietary protocols.   Each PCAP is one conversation or stream between a client and a server.  To see the code used to generate these PCAPS please look at the “generate_pcap” folder.

## Procotols
The fake_proto.py contains the scapy layers defining a fake proprietary protocol used for this webinar.  This file was generated from the perspective of a developer not from someone trying to reverse engineer the protocol.  The “fake_proto_steps” folder shows an example of steps a researcher may have taken when trying to reverse engineer this protocol and follows along with the given presentation.   This code can be seen in the “Documentation by Scapy” slides. 

## Helper Scripts
These scripts are designed to be used in general analysis of PCAP files.

### search_ip
This script is designed to search the payload of each packet inside of a PCAP searching for valid IP addresses.  This information is the most useful when compared against the IP addresses present in the IP layer of each packet.  By default, the results displayed will only be of IP address that appear in the payload of a packet and also appear in an IP layer of a packet.  The “-a” flag can be used to display all valid IP addresses found in the payloads; however this will produce a very large amount of results.

```bash

usage: search_ip.py [-h] [-a] pcapFile

positional arguments:
  pcapFile    pcap file to search for IPs in payload

optional arguments:
  -h, --help  show this help message and exit
  -a, --all   Display all matches. Default only displays IPs found also in IP
              header
```

### data_test
This script is designed to automate very simple tests on a byte stream pulled from a PCAP.  This leverages the Linux commands, file, readelf, and strings along with [Binwalk](https://github.com/ReFirmLabs/binwalk) to provide basic analysis of the byte stream.  Results are stored by default in “data_test_out”.  In order to extract the byte stream from a PCAP file, the user is required to define the “getData” function for there specific protocol.   The code has an example using the fake protocol created for this presentation. 

```bash
usage: data_test.py [-h] [-d DATAFILE] [-o OUTDIR] pcapFile

positional arguments:
  pcapFile              pcap file containing the data string to parse

optional arguments:
  -h, --help            show this help message and exit
  -d DATAFILE, --datafile DATAFILE
                        The name of the file to save the data stream too
  -o OUTDIR, --outdir OUTDIR
                        The name of the directory to save results to
```

### read_proto
The simple script is to serve as an example on how to apply a newly created Scapy layer to a PCAP and print each packet with the layer applied.  Provide the PCAP file as the only argument.

## Generate Pcaps
This code was used to generate the traffic seen in the Pcap files.  It is not part of the webinar and is not intended to be reused, however is provided here to give context and more examples using Scapy.  This code will produce one conversation per execution.   To run, replace the “server_ip” and “local_ip” variables.  First run server.py on one virtual machine and then run generateTraffic on another within the same network.  

## Helpful Links
[Scapy](https://scapy.net/)

[Pandas](https://pandas.pydata.org/)

