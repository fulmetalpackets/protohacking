FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    tcpdump && apt-get clean

COPY . /

RUN pip3 install crc16==0.1.1 scapy==2.4.4

ENTRYPOINT python3 /generate_pcap/server.py