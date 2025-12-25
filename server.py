import time

from common import *
from typing import Dict
import threading

class Connection:
    clientAddr = ""
    vpnPseudoclient = None
    id_ = 0

    def icmp_receive_from_vpn(self):
        while 1:
            data, who = self.vpnPseudoclient.recvfrom(9999)
            icmp_send(self.clientAddr, data, self.id_, True)

    def __init__(self, clientAddr, id_):
        self.clientAddr = clientAddr
        self.id_ = id_
        self.vpnPseudoclient = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.vpnPseudoclient.bind(("127.0.0.1", 0))
        t = threading.Thread(target=self.icmp_receive_from_vpn)
        t.start()


clients: Dict[int, Connection] = dict()
icmp_receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

vpnServerPort = 51820
data_m = b"abcdefghijklmnopqrstuvwabcdefghi"


def incoming_icmp_listen():
    while True:
        p, addr = icmp_receiver.recvfrom(9999)
        id = int.from_bytes(p[24:26], 'little')
        data = p[28:].removesuffix(b"\x00\x11\x22")
        if id in clients:
            clients[id].vpnPseudoclient.sendto(data, ("localhost", vpnServerPort))
        elif data == b"HelloHello":
            clients[id] = Connection(addr[0], id)
            for i in range(3):
                icmp_send(addr[0], b"ReplyReply", id, True)
                time.sleep(1)
        elif data == data_m:
            icmp_send(addr[0], data_m, id, True)


print('Server is ready')

incoming_icmp_listen()
