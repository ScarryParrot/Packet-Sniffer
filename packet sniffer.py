import socket
import os
import struct
import binascii
import argparse

def analyse_ethernet(data):
    eth_hdr = struct.unpack("!6s6sH", data[:14])
    dest_mac = binascii.hexlify(eth_hdr[0]).decode('utf-8')
    src_mac = binascii.hexlify(eth_hdr[1]).decode('utf-8')
    proto = socket.ntohs(eth_hdr[2])
    print("Ethernet Header:")
    print("  Destination Addr: " + dest_mac)
    print("  Source Addr: " + src_mac)
    print("  Protocol: " + hex(proto))
    print("")

    return data[14:], proto

def analyse_ip(data):
    ip_hdr = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = ip_hdr[0]
    ihl = version_ihl & 0xF
    ip_len = ihl * 4
    ttl = ip_hdr[5]
    protocol = ip_hdr[6]
    src_ip = socket.inet_ntoa(ip_hdr[8])
    dest_ip = socket.inet_ntoa(ip_hdr[9])
    print("IP Header:")
    print("  Source IP: " + src_ip)
    print("  Destination IP: " + dest_ip)
    print("  Protocol: " + str(protocol))
    print("")

    return data[ip_len:], protocol

def analyse_tcp(data):
    tcp_hdr = struct.unpack("!HHLLBBHHH", data[:20])
    src_port = tcp_hdr[0]
    dest_port = tcp_hdr[1]
    seq_num = tcp_hdr[2]
    ack_num = tcp_hdr[3]
    data_offset = (tcp_hdr[4] >> 4) * 4
    print("TCP Header:")
    print("  Source Port: " + str(src_port))
    print("  Destination Port: " + str(dest_port))
    print("")

    return data[data_offset:]

def extract_http_site(data):
    try:
        http_data = data.decode('utf-8')
        site_name_start = http_data.find("Host: ") + len("Host: ")
        site_name_end = http_data.find("\r\n", site_name_start)
        site_name = http_data[site_name_start:site_name_end]
        print("HTTP Header:")
        print("  Site Name: " + site_name)
        print("")
    except UnicodeDecodeError:
        pass  # Ignore non-UTF-8 encoded data

def analyse(data):
    data, proto = analyse_ethernet(data)
    
    if proto == 8:  # IPv4 protocol number
        data, protocol = analyse_ip(data)
        
        if protocol == 6:  # TCP protocol number
            data = analyse_tcp(data)
            extract_http_site(data)

def main():
    parser = argparse.ArgumentParser(description='Packet Sniffer with Host and Port Specification')
    parser.add_argument('-i', '--interface', help='Network interface to sniff packets on')
    args = parser.parse_args()

    if args.interface:
        sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sniffer_socket.bind((args.interface, 0))
    else:
        sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    
    received_data = sniffer_socket.recv(2048)
    analyse(received_data)

while True:
    main()
