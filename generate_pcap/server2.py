from scapy.all import *
import struct
import socket
from fake_proto import *

class Server:
    SEND_CNT = 1
    VERBOSE = True
    ss = None
    def __init__(self):
        # Create Socket "Spoofing" the teacher
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', 1234))
        s.listen(1)
        conn, addr = s.accept()
        self.ss = StreamSocket(conn, Raw)

    def send_recv(self, pkt):
        data = None
        if self.VERBOSE: print('Send pkt %s Size [%s]' % (self.SEND_CNT, len(pkt)))
        self.ss.send(pkt)
        data = self.ss.recv(2048)
        if self.VERBOSE:
            print('Recvd [%s] bytes' % len(data))
            data.show()
        self.SEND_CNT += 1
        return data

    def send_only(self, pkt):
        if self.VERBOSE: print('Send pkt %s Size [%s]' % (self.SEND_CNT, len(pkt)))
        self.ss.send(pkt)
        time.sleep(.2) # Don't want the packets to join
        self.SEND_CNT += 1

    def recv_only(self):
        return self.ss.recv(2048)

    def save_bytes_to_file(self, pkt):
        if self.save_file:
            with open(self.save_file, 'ab') as f:
                f.write(raw(pkt))

####main####

session = Server()
print('Connected')
recv_data = session.recv_only()
print(type(recv_data))
recv_data.show()
print(recv_data.command())

