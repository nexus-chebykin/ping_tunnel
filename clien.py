import random
import struct
import time
import pcap
# On windows - pip install pcap-ct
import socket

# Компьютер\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards

sniffer = pcap.pcap(name=r'\Device\NPF_{5CA07E8D-B852-49DA-A335-F53FF0959121}', promisc=True, timeout_ms=50,
                    immediate=True)
ICMP_CODE = socket.getprotobyname('icmp')

server_address = "206.189.97.34"

# import netifaces
# gateways = netifaces.gateways()
# default_gateway = gateways['default'][netifaces.AF_INET][0]

default_gateway = "192.168.1.1"
print(f"The command is: route add {server_address} {default_gateway} metric 9999")
def get_me_in_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    t = s.getsockname()[0]
    s.close()
    return t

me_in_local = get_me_in_local()
print(f'Me in local: {me_in_local}')
ovpn_listener = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
vpn_port = 27005
ovpn_listener.bind(("", vpn_port))



client_ovpn_address = (None, None)

padding = b"\x00\x11\x22"
id_ = random.randint(0, (1 << 8) - 1)



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
    ICMP_ECHO_REQUEST = 8  # Код типа ICMP - в нашем случае ECHO
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 6)
    data = data + b"\x00\x11\x22" * (len(data) % 2)

    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 6)
    return header + data

icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
def icmp_send(dest_addr, data):
    data = create_packet(id_, data)
    while data:
        sent = icmp_socket.sendto(data, (dest_addr, 1))
        data = data[sent:]
        if data:
            print('have to resend')

def icmpvpn2tun(sock):
    global client_ovpn_address
    while 1:
        try:
            d, a = sock.recvfrom(9999)
            client_ovpn_address = a
            print(f"SENDING {d.hex()}")
            icmp_send(server_address, d)
        except ConnectionResetError as e:
            print(e)
            print(sock)

import threading

t = threading.Thread(target=icmpvpn2tun, args=(ovpn_listener,))
t.start()


def incoming_icmp_listen():
    for _, p in sniffer:
        if p[23] == 1 and p[34] == 0:
            if socket.inet_ntoa(p[30:34]) == me_in_local:
                p = p[42:].removesuffix(b"\x00\x11\x22")
                print(f'got packet: {p}')
                ovpn_listener.sendto(p, client_ovpn_address)

p = threading.Thread(target=incoming_icmp_listen)
p.start()

# icmp_send(server_address, (0).to_bytes(1200, "little", signed=False))


# while True:
    # По непонятным причинам сервер может забывать, что ему не нужно отвечать на ICMP echo. Вроде sysctl -p это лечит
    # print('sending hello')
    # icmp_send(server_address, b"hello_from_client")
    # time.sleep(1)

