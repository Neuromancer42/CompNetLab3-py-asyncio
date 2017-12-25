import asyncio
import httplib

class Connection:
    def __init__(self, config, loop, stat):
        self.config = config
        self.loop = loop
        self.stat = stat
        self.headers = ''

    def handle_browser_read(self, breader, bwriter):
        requse_message = ''
        while '\r\n\r\n' not in self.headers:
            data = yield from breader.read(8192)
            logging.info("Receiving request from {} with size {}".format((breader.get_extra_info('peername'), len(data))))
            requse_message += data.decode()
        
