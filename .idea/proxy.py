from __future__ import print_function

import sys
import socket
import signal
import logging
import pyuv
import re

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

            # just in case of sites other than video.pku.edu.cn
            # if resolved by query_name already, nothing changes
            check_video_requests(new_url)

            start_connect_server(client, method, url, version) # TODO
    else:
        logger.debug("{0}: close connect from {1}".format(error, client))
        client.close()
        clients.remove(client)
        return
    client.write(data)

# note: qname is converted name to query
def query_name(qname):
    packet = struct.pack(">H", 1234)   # arbitary chosen id
    packet += struct.pack(">H", 0)     # flags
    packet += struct.pack(">H", 1)     # queries
    packet += struct.pack(">H", 0)     # ans
    packet += struct.pack(">H", 0)     # auth
    packet += struct.pack(">H", 0)     # add
    packet += struct.pack(">s", qname) # qname
    packet += struct.pack("B", 0)      # end of qname
    packet += struct.pack(">H", 1)     # query type
    packet += struct.pack(">H", 1)     # query class
    dns_udp = pyuv.UDP(loop)

def signal_cb(handle, signum):
    [c.close() for c in clients]
    signal_h.close()
    proxy.close()
    logger.debug("{0}: stopping".format(proxy))

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
