import time


import socket
import struct
import random

ICMP_CODE = socket.getprotobyname('icmp')

icmpclient = "auto"
# icmpclient = "213.87.152.210"
me_in_local = "206.189.97.34"
icmp_receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('ICMP'))

vpn_pseudoclient_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
vpn_pseudoclient_port = 3335
vpn_pseudoclient_socket.bind(("127.0.0.1", vpn_pseudoclient_port))

vpn_port = 27005
# vpn_port = 51820

padding = b"\x00\x11\x22"
#
# udp_listen = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# udp_listen.bind(("0.0.0.0", 3366))


# def udp_send(dest_addr, pkt):
#     udp_listen.sendto(pkt, client_address)


icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)


def checksum(source_string):
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet(id, data):
    ICMP_ECHO_REQUEST = 0  # Код типа ICMP - в нашем случае ECHO
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 7)
    data = data + b"\x00\x11\x22" * (len(data) % 2)

    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 7)
    return header + data


def icmp_send(dest_addr, data):
    global id
    data = create_packet(id, data)
    while data:
        if dest_addr == 'auto':
            return
        sent = icmp_socket.sendto(data, (dest_addr, 1))
        data = data[sent:]
        if data:
            print('have to resend')


# def udp_receive_from_vpn(sock):
#     while 1:
#         global id
#         data, who = sock.recvfrom(9999)
#         udp_send(icmpclient, data)
def icmp_receive_from_vpn(sock):
    while 1:
        global id
        data, who = sock.recvfrom(9999)
        # print('Sending response from vpn')
        icmp_send(icmpclient, data)


id = 123
import threading

t = threading.Thread(target=icmp_receive_from_vpn, args=(vpn_pseudoclient_socket,))
t.start()

client_address = None


def incoming_icmp_listen():
    global id, max_got_back, icmpclient
    while True:
        p, addr = icmp_receiver.recvfrom(9999)
        if (
                # '213.87' in addr[0]
            '176' in addr[0]
            # True
        ):
            icmpclient = addr[0]
        else:
            continue
        # print(len(p), p.hex())
        # print('here')
        id = int.from_bytes(p[24:26], 'little')
        # print(id)
        p = p[28:].removesuffix(b"\x00\x11\x22")
        # print(p.decode())
        # icmp_send(icmpclient, b"Hello from server")
        vpn_pseudoclient_socket.sendto(p, ("127.0.0.1", vpn_port))


print('Server is ready')

incoming_icmp_listen()
