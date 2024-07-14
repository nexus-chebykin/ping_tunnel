import pcap

sniffer = pcap.pcap(name=r'\Device\NPF_{47806658-5463-4F2B-B525-BE39352A80FD}', promisc=True, timeout_ms=50,
                    immediate=True)

import socket
import struct
import random
import time

ICMP_CODE = socket.getprotobyname('icmp')

udp_listen = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
def incoming_udp_listen():
    while 1:
        d, a = udp_listen.recvfrom(9999)
        print('[CLIENT] UDP received:', d)
        ovpn_listener.sendto(d, client_ovpn_address)

p = threading.Thread(target=incoming_udp_listen)
p.start()


# while True:
#     print('sending')
#     udp_listen.sendto(b"hello_from_client", (server_address, 3366))
#     time.sleep(1)

