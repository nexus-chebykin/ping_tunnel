import queue
import random
import subprocess
import time
import socket
import platform
import netifaces
from common import *


server_address = "vdsina.838384.xyz"


def get_me_in_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    t = s.getsockname()[0]
    s.close()
    return t


me_in_local = get_me_in_local()
print(f'Me in local: {me_in_local}')
gateways = netifaces.gateways()
default_gateway = gateways['default'][netifaces.AF_INET][0]
print(f'Default gateway: {default_gateway}')
ovpn_listener = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
vpn_port = 51820
ovpn_listener.bind(("", vpn_port))

client_ovpn_address = (None, None)

id_ = random.randint(0, 2 ** 16 - 1)


def vpnToServer(ovpn_listener):
    global client_ovpn_address
    while 1:
        try:
            d, a = ovpn_listener.recvfrom(9999)
            client_ovpn_address = a
            icmp_send(server_address, d, id_, False)
        except ConnectionResetError as e:
            print(e)
            print(ovpn_listener)


import threading

ovpn_listener_thread = threading.Thread(target=vpnToServer, args=(ovpn_listener,))
ovpn_listener_thread.start()

isWindows = platform.system().lower() == "windows"


def icmp_receiver():
    if isWindows:
        import pcap
        # On windows - pip install pcap-ct
        # Компьютер\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards
        usbRealtek = '{5CA07E8D-B852-49DA-A335-F53FF0959121}'
        wifi = '{A04EC865-F2A8-4A1A-A136-4C3FB04C7B0B}'
        sniffer = pcap.pcap(name=fr'\Device\NPF_{wifi}', promisc=True, timeout_ms=50,
                            immediate=True)
        for _, p in sniffer:
            if p[23] == 1 and p[34] == 0:
                if (socket.inet_ntoa(p[30:34]) == me_in_local
                        and int.from_bytes(p[38:40], 'little') == id_):
                    p = p[42:].removesuffix(b"\x00\x11\x22")
                    yield p
    else:
        icmp_receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('ICMP'))
        while True:
            p, addr = icmp_receiver.recvfrom(9999)
            if int.from_bytes(p[24:26], 'little') == id_:
                p = p[28:].removesuffix(b"\x00\x11\x22")
                yield p


incoming_packets = queue.Queue()

mode = "enqueue"


def incoming_icmp_listen():
    receiver = icmp_receiver()
    for packet in receiver:
        if mode == "enqueue":
            incoming_packets.put(packet)
        elif mode == "redirect":
            ovpn_listener.sendto(packet, client_ovpn_address)


incoming_icmp_listen_thread = threading.Thread(target=incoming_icmp_listen)
incoming_icmp_listen_thread.start()


def enableRouting():
    print(f"Preserving route to {server_address} via {default_gateway}")
    if isWindows:
        subprocess.check_output(f"route add {server_address} via {default_gateway}")
    else:
        try:
            subprocess.check_output(f"route add {server_address} {'gw' if platform.system() != 'Darwin' else ''} {default_gateway}", shell=True)
        except Exception as e:
            print("Hopefully the above error is 'Already exists'")


# Check ping is allowed
time.sleep(0.5)
data = b"abcdefghijklmnopqrstuvwabcdefghi"
print("Is ping google.com allowed?..", end=' ')
icmp_send("google.com", data, id_, False)
try:
    _ = incoming_packets.get(timeout=1)
except queue.Empty:
    print("Nope")
    os._exit(1)
print("Success")
print("Is server responding to pings?..", end=' ')
for i in range(3):
    icmp_send(server_address, b"HelloHello", id_, False)
    time.sleep(0.05)
while True:
    try:
        packet = incoming_packets.get(timeout=1)
        print(packet)
        if packet.startswith(b"ReplyReply"):
            break
    except queue.Empty:
        print("Nope")
        os._exit(1)
print("Success")
input("Turn on the VPN (it is expected not to connect), and then press any button...")
enableRouting()
print("Running")
mode = "redirect"
ovpn_listener_thread.join()

# add route delete automatic