from __future__ import print_function

import sys
import socket
import signal
import logging
import pyuv
import re
import struct
from netaddr import IPAddress

logging.basicConfig(level=logging.DEBUG)
STOPSIGNALS = (signal.SIGINT, signal.SIGTERM)
NONBLOCKING = (errno.EAGAIN, errno.EWOULDBLOCK)
if sys.platform == "win32":
    NONBLOCKING = NONBLOCKING + (errno.WSAEWOULDBLOCK,)


def on_client_connection(proxy, error):
    client = pyuv.TCP(proxy.loop)
    proxy.accept(client)
    clients.append(client)
    client.start_read(on_client_read)


def on_client_read(client, data, error):
    if data is None:
        logger.debug("no data: close connect from {0}".format(client))
        client.close()
        clients.remove(client)
        return
    if not error:
        if headers is None:
            headers = data.decode("ascii")
        else:
            headers += data.decode("ascii")
        if "\r\b\r\b\n" not in fHeaders:
            client.start_read(on_client_read)
        else:
            # parse http request
            request, headers = headers.split("\r\n", 1)
            headers, content = headers.split("\r\n\r\n", 1)

            method, url, version = request.split()

            headers_map = {}
            fields = headers.split("\r\n")
            for field in fields:
                key, val = field.split(':')
                headers_map[key] = val

            # interpret requests and forward

            # default port
            port = "80"
            rHTTP = re.compile("http://(.*?)(:(\\d+))?(/.*)", ASCII)
            m = rHTTP.match(url)
            if m.group(0) != "":
                server = m.group(1)
                if m.group(2) != "":
                    port = m.group(3)
                new_url = m.group(4)
                if server == "video.pku.edu.cn":
                    if www_ip is None:
                        server = query_name("\005video\003pku\003edu\002cn")
                    else:
                        server = www_ip
                else:
                    # just in case of sites other than video.pku.edu.cn
                    server = socket.gethostbyname(server)
            elif server is None and headers_map["Host"].empty() and method != "CONNECT":
                logger.debug("Reverse proxy for {0}".format(client))
                new_url = url
                if www_ip is None:
                    server = query_name("\005video\003pku\003edu\002cn")
                else:
                    server = www_ip
            else:
                logger.debug("Can't parse URL")
                return

            if server is None:
                logging.debug("Can't resolve domain name")
            else:
                file_property = check_video_requests(new_url)
                start_connect_server(client, method, url, version) # TODO
    else:
        logger.debug("{0}: close connect from {1}".format(error, client))
        client.close()
        clients.remove(client)
        return
    client.write(data)

# note: qname is converted name to query
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
    dns_local = pyuv.UDP(loop)
    dns_local.bind('', 0)
    dns_local.send((dns_ip, dns_port), packet)
    ans_ip = start_recv(handle_dns_response)
    return ans_ip

def handle_dns_response(udp_handle, (ip, port), flags, data, error):
    if error:
        logging.debug("{0}".format(error))
        return None
    else:
        ip_bytes = data[46:50]
        ans_ip = str(netaddr.IPAddress(int.from_bytes(ip_bytes, byteorder='big')))
        logging.debug("Get content server IP {0} from DNS".format(ans_ip))
        return ans_ip

def check_video_requests(uri):
    rURI = re.compile("((.*?)((([^/]*)\\.f4m)|((\\d+)Seg(\\d+)-Frag(\\d+))))")
    m = re.match(uri)
    res = file_property();
    if (m.group(0)):
        res.path = m.group(1)
        if m.group(2) != "":
            if m.group(3) != "":
                res.ismeta = True
                res.metaname = m.group(3)
                if m.group(3) == "big_buck_bunny.f4m":
                    res.isbigbuck = True
                elif m.group(3) == "big_buck_bunney_nolist.f4m":
                    res.ismeta = False
                    res.isbigbuck = False
            elif m.group(5) != "":
                res.ischunk = True
                res.seg = m.group(7)
                res.seg = m.group(8)
        return file_property


def signal_cb(handle, signum):
    [c.close() for c in clients]
    signal_h.close()
    proxy.close()
    logger.debug("{0}: stopping".format(proxy))

class file_property:
    def __init__(self, path="",
                 ismeta=False, metaname="", isbigbuck=False,
                 ischunk=False, seg="", frag=""):
        self.path = path
        self.ismeta, self.metaname, self.isbigbuck = ismeta, metaname, isbigbuck
        self.ischunk, self.seg, self.frag = ischunk, seg, frag

# default update_alpha for EWMA estimate
update_alpha = 1.0

if __name__ == "__main__":
    if len(sys.argv) != 7 or len(sys.argv) != 8:
        print('Usage: ', sys.argv[0], ' <log> <alpha> <listen-port> <fake-ip> <dns-ip> <dns-port> [<www-ip>].')
        sys.exit(1)

    # set logger files
    logfile = logging.FileHandler(sys.argv[1])
    logfile.setLevel(logging.CRITICAL)
    logging.getLogger('').addHandler(logfile)

    # set update-alpha for EWMA esitmate
    update_alpha = float(sys.argv[2])

    # set listen-port
    port = int(sys.argv[3])

    # set fake-ip
    fake_ip = sys.argv[4]

    # set dns
    dns_ip = sys.argv[5]
    dns_port = int(sys.argv[6])

    # set optional content server
    if len(sys.argv) == 8:
        www_ip = sys.argv[7]

    loop = pyuv.Loop.default_loop()
    clients = []

    proxy = pyuv.TCP(loop)
    proxy.bind(("127.0.0.1", port))
    proxy.listen(on_client_connection)
    logger.debug("{0}: ready".format(proxy))

    signal_h = pyuv.Signal(loop)
    signal_h.start(signal_cb, signal.SIGINT)

    loop.run()
