import struct
import logging

# note: qname is already converted name to query
def query_name(qname):
    packet = struct.pack(">H", 1234)        # arbitary chosen id
    packet += struct.pack(">H", 0)          # flags
    packet += struct.pack(">H", 1)          # queries
    packet += struct.pack(">H", 0)          # ans
    packet += struct.pack(">H", 0)          # auth
    packet += struct.pack(">H", 0)          # add
    for c in bytes(qname):                  # qname
        packet += struct.pack("c", c)
    packet += struct.pack("B", 0)           # end of qname
    packet += struct.pack(">H", 1)          # query type
    packet += struct.pack(">H", 1)          # query class

    # for simplification, blocking query
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        logging.debug("DNS query: {0}".format(packet))
        sent = dns_sock.sendto(packet, (dns_ip, dns_port))
        data, dns_server = dns_sock.recvfrom(4096)
        logging.debug("DNS response: {0}".format(data))
        ip_bytes = data[46:50]  # hack
        ans_ip = str(netaddr.IPAddress(int.from_bytes(ip_bytes, byteorder='big')))
        logging.debug("Get content server IP {0} from DNS".format(ans_ip))
    finally:
        logging.debug("Close dns socket")
        dns_sock.close()
    return ans_ip
