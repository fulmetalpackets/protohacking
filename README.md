# Hacking Proprietary Protocols

This repository contains the code and PCAPS used for the SANS webinar, "Hacking Proprietary Protocols" given on February 23, 2021.  All code was written with Python 3.

## Presentation Recording
Presentation link: <TBD>

## Visual Packet Analysis with Panda
A Jupyter notebook can be found under "packet analysis" and the code can be interacted with using Binder
[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/aboutsecurity/jupyter-notebooks/HEAD)

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
This script is designed to automate very simple test on a byte stream pulled from a PCAP.  This leverages the Linux commands, file, readelf, and strings along with [Binwalk](https://github.com/ReFirmLabs/binwalk) to provide basic analysis of the byte stream.  Results are stored by default in “data_test_out”.  In order to extract the byte stream from a PCAP file, the user is required to define the “getData” function for there specific protocol.   The code has an example using the fake protocol created for this presentation. 

