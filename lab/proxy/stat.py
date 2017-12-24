import aiorwlock
import logging
import xml.etree.ElementTree


class Statistics:
    def __init__(self, loop, alpha):
        self.rwlock = aiorwlock.RWLock(loop=loop)
        self.rates = []
        self.throughput_map = {}
        self.alpha = alpha

    async def adapt_bitrate(self, ip):
        logging.debug("Adapt bitrate: waiting for readlock")
        async with self.rwlock.reader:
            if ip in self.throughput_map:
                cur_throughput = self.throughput_map[ip]
                if len(self.rates) == 0:
                    logging.error("Error: no metadata recorded when adapting bitrates")
                    ans = None
                else:
                    available = [b for b in self.rates if cur_throughput >= b * 1.5]
                    if len(available) == 0:
                        ans = min(self.rates)
                    else:
                        ans = max(available)
            else:
                if len(self.rates) == 0:
                    logging.error("Error: no metadata recorded when adapting bitrates")
                    ans = None
                else:
                    ans = min(self.rates)
            if ans:
                logging.debug("Stat: adapt bitrate for ip {}: {}".format(ip, ans))
            else:
                logging.debug("Stat: cannot choose bitrate for ip {}".format(ip))

    async def parse_bitrates(self, xml_str):
        tree = xml.etree.ElementTree.fromstring(xml_str)
        root = tree.getroot()
        if root.tag != 'manifest':
            logging.error("Error: not a manifest file")
            return
        rates = []
        for child in root:
            if child.tag == 'media':
                if 'bitrate' not in child.attrib:
                    logging.error("Error: no bitrate attribution")
                else:
                    rates.append(int(child.attrib['bitrate']))
        logging.debug("Parse bitrates: waiting for writelock")
        async with self.rwlock.writer:
            self.rates = rates
            logging.debug("Stat: record available bitrates: ".format(rates))

    async def update_throughput(self, throuput, ip):
        logging.debug("Update throughput: waiting for writelock")
        async with self.rwlock.writer:
            if ip in self.throughput_map:
                self.throughput_map[ip] = self.alpha * throuput + (1 - self.alpha) * self.throughput_map[ip]
            else:
                self.throughput_map[ip] = throuput
            logging.debug("Stat: updaet throughput from {}: {}".format(ip, self.throughput_map[ip]))
