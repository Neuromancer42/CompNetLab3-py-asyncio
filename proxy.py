from __future__ import print_function

import sys
import signal
import logging

logging.basicConfig(level=logging.DEBUG)
STOPSIGNALS = (signal.SIGINT, signal.SIGTERM)
NONBLOCKING = (errno.EAGAIN, errno.EWOULDBLOCK)
if sys.platform == "win32":
    NONBLOCKING = NONBLOCKING + (errno.WSAEWOULDBLOCK,)


def start_connect_server(client, method, version, server, new_url, headers, data, file_property):
    # TODO
    skip


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
    config['update_alpha'] = float(sys.argv[2])

    # set listen-port
    config['listen_port'] = sys.argv[3]
    config['listen_addr'] = "127.0.0.1"

    # set fake-ip
    config['fake_ip'] = sys.argv[4]

    # set dns
    config['dns_addr'] = sys.argv[5]
    config['dns_port'] = sys.argv[6]

    # set optional content server
    if len(sys.argv) == 8:
        config['www_ip'] = sys.argv[7]
