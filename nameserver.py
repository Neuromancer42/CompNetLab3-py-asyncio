import asyncio
import dns.message
import aioudp
import logging
import sys
import datetime

logging.basicConfig(level=logging.DEBUG)


class Server:
    def __init__(self, config):
        self.cur_server = 0
        self.servers = self.read_servers(config['server_file'])
        self.mode = config['mode']
        if self.mode == 'lsa':
            self.content_map = self.read_lsa(config['lsa_file'])
        else:
            self.content_map = dict()
        self.addr = config['listen_addr']
        self.port = int(config['listen_port'])
        self.servers = []

    async def run(self):
        local = await aioudp.open_remote_endpoint(host=self.addr,
                                                  port=self.port)
        while True:
            await self.process(local)

    async def process(self, local):
        data, addr = await local.read()
        request_packet = data.decode()
        request = dns.message.from_wire(request_packet)
        questions = request.get_rrset(section=request.question,
                                      name="video.pku.edu.cn",
                                      rdclass=dns.rdataclass.IN,
                                      rdtype=dns.rdatatype.A)
        if questions:
            for q in questions:
                qname = q.name
                if qname != "video.pku.edu.cn":
                    logging.error("Receiving wrong query")
                    break
                else:
                    if self.mode == 'roundrobin':
                        ans_ip = self.get_ip_rr(addr[0])
                    elif self.mode == 'lsa':
                        ans_ip = self.get_ip_lsa(addr[0])
                    else:
                        logging.error("Config is invalid")
                        break
                now = datetime.datetime.now() - datetime.datetime(year=1970, month=1, day=1,
                                                                  tzinfo=datetime.timezone.utc)
                logging.critical("{} {} {} {}".format(now.total_seconds(), addr[0], qname, ans_ip))
                response = dns.message.make_response(request, ans_ip)
                client = await aioudp.open_local_endpoint(*addr)
                client.write(response.to_wire())
                # just need one answer
                break
        else:
            logging.error("Receiving wrong query")

    @staticmethod
    def read_servers(self, filename):
        file = open(filename, 'r')
        lines = file.readlines()
        file.close()
        servers = []
        for l in lines:
            servers.append(l.strip().rstrip())
        return servers

    def read_lsa(self, filename):
        file = open(filename, 'r')
        lines = file.readlines()
        file.close()
        record = dict()
        for l in lines:
            sender, seq, neighbours = l.split()
            if sender in record:
                if seq > record[sender][0]:
                    record[sender] = (seq, neighbours)
            else:
                record[sender] = (seq, neighbours)
        for sender in record:
            record[sender] = record[sender][1].split(',').strip().rstrip()

        nearest = {}
        for content in self.servers:
            reverse_dist = dict()
            to_expand = list()
            to_expand.append((0, content))
            reverse_dist[content] = 0
            while len(to_expand) > 0:
                d, m = to_expand.pop(0)
                for n in record[m]:
                    if n not in reverse_dist:
                        reverse_dist[n] = d + 1
                        to_expand.append((d + 1, n))

            for p in reverse_dist:
                if p in nearest:
                    d, _ = nearest[p]
                    if reverse_dist[p] < d:
                        nearest[p] = (reverse_dist[p], content)
                else:
                    nearest[p] = (reverse_dist[p], content)

        for p in nearest:
            nearest[p] = nearest[p][1]

        return nearest

    def get_ip_rr(self, _):
        ans = self.servers[self.cur_server]
        self.cur_server += 1
        if self.cur_server == len(self.servers):
            self.cur_server = 0
        return ans

    def get_ip_lsa(self, ip):
        if ip in self.content_map:
            return self.content_map[ip]
        else:
            logging.error("Error: IP not recorded")
            for k in self.content_map:
                return self.content_map[k]


if __name__ == "__main__":
    argc = len(sys.argv)
    config = dict()
    if argc != 6 and argc != 7:
        print('Usage: ', sys.argv[0], ' [-r] <log> <ip> <port> <servers> <servers>.')
        sys.exit(1)
    if argc == 6:
        config['mode'] = 'lsa'
    else:
        if sys.argv[1] != '-r':
            print('Usage: ', sys.argv[0], ' [-r] <log> <ip> <port> <servers> <servers>.')
            sys.exit(1)
        else:
            config['mode'] = 'roundrobin'

    # set logger files
    logfile = logging.FileHandler(sys.argv[-5])
    logfile.setLevel(logging.CRITICAL)
    logging.getLogger('').addHandler(logfile)

    # set listener
    config['listen_addr'] = sys.argv[-4]
    config['listen_port'] = sys.argv[-3]

    # set files
    config['server_file'] = sys.argv[-2]
    config['lsa_file'] = sys.argv[-1]

    dns_server = Server(config)

    loop = asyncio.get_event_loop()
    # actually, it's blocking IO (shrug)
    try:
        loop.run_until_complete(dns_server.run())
    finally:
        loop.close()
