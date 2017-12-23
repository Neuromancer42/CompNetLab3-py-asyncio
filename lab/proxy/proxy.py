import sys
import logging
import asyncio
from lab.proxy.stat import Statistics
from lab.proxy.conn import Connection

logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    if len(sys.argv) != 7 and len(sys.argv) != 8:
        print('Usage: ', sys.argv[0], ' <log> <alpha> <listen-port> <fake-ip> <dns-ip> <dns-port> [<www-ip>].')
        sys.exit(1)

    # set logger files
    logfile = logging.FileHandler(sys.argv[1])
    logfile.setLevel(logging.CRITICAL)
    logging.getLogger('').addHandler(logfile)

    config = dict()

    # set update-alpha for EWMA esitmate
    config['update_alpha'] = float(sys.argv[2])

    # set listen-port
    config['listen_port'] = sys.argv[3]
    config['listen_addr'] = "0.0.0.0"

    # set fake-ip
    config['fake_ip'] = sys.argv[4]

    # set dns
    config['dns_addr'] = sys.argv[5]
    config['dns_port'] = sys.argv[6]

    # set optional content server
    if len(sys.argv) == 8:
        config['www_ip'] = sys.argv[7]

    loop = asyncio.get_event_loop()
    stat = Statistics(loop, config['update_alpha'])
    conn = Connection(loop, config, stat)
    addr = config['listen_addr']
    port = int(config['listen_port'])
    coro = asyncio.start_server(conn.forwarding, addr, port, loop)
    server = loop.run_until_complete(coro)

    logging.debug('Listening on {}'.format(server.sockets[0].getsockname()))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    logging.debug('Shutdown server')
    server.close()
    loop.run_until_complete(server.wait_closed())
