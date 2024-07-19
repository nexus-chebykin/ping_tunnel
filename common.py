import socket
import struct

ICMP_CODE = socket.getprotobyname('icmp')

icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

padding = b"\x00\x11\x22"


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


def create_packet(id, data, reply):
    ICMP_ECHO_REQUEST = 0 if reply else 8
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 0)
    data = data + b"\x00\x11\x22" * (len(data) % 2)

    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 0)
    return header + data


def icmp_send(dest_addr, data, id, reply):
    data = create_packet(id, data, reply)
    while data:
        if dest_addr == 'auto':
            return
        sent = icmp_socket.sendto(data, (dest_addr, 1))
        data = data[sent:]
        if data:
            print('have to resend')
