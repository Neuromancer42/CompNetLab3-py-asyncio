import asyncio
import logging
import re
import dns.message
import aiodns
from lab import aioudp
import datetime
import struct
import socket


class FileProperty:
    def __init__(self, path="",
                 is_meta=False, meta_name="", is_bigbuck=False,
                 is_chunk=False, rate="", seg="", frag=""):
        self.path = path
        self.is_meta, self.meta_name, self.is_bigbuck = is_meta, meta_name, is_bigbuck
        self.is_chunk, self.rate, self.seg, self.frag = is_chunk, rate, seg, frag


class Connection:
    def __init__(self, loop, config, stat):
        self.config = config
        self.loop = loop
        self.stat = stat

    async def forwarding(self, breader, bwriter):
        data = await breader.read(8192)
        request_message = data.decode()
        while len(data) != 0:
            data = await breader.read(8192)
            request_message += data.decode()
        logging.info(
            "Receiving request from {} with size {}".format(breader.get_extra_info('peername'), len(request_message)))

        request, rest = request_message.split('\r\n', 1)
        headers, content = rest.split('\r\n\r\n', 1)
        header_fields = headers.split('\r\n')
        header_map = {}
        for field in header_fields:
            key, value = field.split(':')
            header_map[key] = value.strip().rstrip()
        if "Host" in header_map:
            host = header_map["Host"]
        else:
            host = None

        method, url, version = request.split()
        remote_addr, remote_port, uri, file_property, chosen_rate = await self.modify_url(url, host)

        new_request = method + ' ' + uri + ' ' + version
        new_request += '\r\n'
        new_request += headers
        new_request += '\r\n\r\n'
        new_request += content

        sreader, swriter = await asyncio.open_connection(remote_addr, int(remote_port), loop=self.loop)
        logging.debug("Sending request of {} to server {}:{}".format(uri, remote_addr, remote_port))
        start_time = datetime.datetime.now()
        swriter.write(content.encode())
        data = await sreader.read(8192)
        response = ''
        while len(data) != 0:
            response += data.decode()
            bwriter.write(data)
            data = await sreader.read(8192)

        response_line, _ = response.split('\r\n', 1)
        finish_time = datetime.datetime.now()
        header, content = response.split('\r\n\r\n', 1)
        logging.debug("Receiving response of {} from server {}:{}".format(response_line, remote_addr, remote_port))

        # stat chunk fetching
        if file_property.is_chunk:
            now = finish_time - datetime.datetime(year=1970, month=1, day=1, tzinfo=datetime.timezone.utc)
            duration = finish_time - start_time
            size = len(content)
            # size in bytes, duration in sec
            cur_throughput = size * 8 / 1000 / duration.total_seconds()
            new_throughout = await self.stat.update_throughput(cur_throughput, remote_addr)
            # logging
            logging.critical("{} {} {} {} {} {} {}".format(now.total_seconds(),
                                                           duration.total_seconds(),
                                                           cur_throughput,
                                                           new_throughout,
                                                           chosen_rate,
                                                           remote_addr,
                                                           uri))
        # fetching metafile
        if file_property.is_bigbuck:
            uri = file_property.path + "big_buck_bunny.f4m"
            new_request = method + ' ' + uri + ' ' + version + '\r\n\r\n'
            swriter.write(new_request.encode())
            data = await sreader.read(8192)
            response = ''
            while len(data) != 0:
                response += data.decode()
                data = await sreader.read(8192)
            _, xml_str = response.split('\r\n\r\n', 1)
            self.stat.parse_bitrates(xml_str)

        # close sockets
        swriter.close()
        bwriter.close()
        logging.debug("Remote socket and Client socket closed")

    async def modify_url(self, url, host):

        # parse out server_name, port and uri
        server_name = "video.pku.edu.cn"
        port = "80"

        r_http = re.compile("(http://(.*?)(:(\\d+))?)?(/.*)")
        m_http = r_http.match(url)
        if m_http:
            if m_http.group(1):
                server_name = m_http.group(2)
                if m_http.group(3):
                    port = m_http.group(4)
            uri = m_http.group(5)
        else:
            if host:
                server_name = host
            # reverse proxy
            uri = url

        # find specific requests related to video files
        file_property = FileProperty()
        if server_name == "video.pku.edu.cn":
            r_uri = re.compile("(.*?)((([^/]*)\\.f4m)|((\\d+)Seg(\\d+)-Frag(\\d+)))")
            m_uri = r_uri.match(uri)
            if m_uri:
                file_property.path = m_uri.group(1)
                if m_uri.group(2) != '':
                    if m_uri.group(3) != '':
                        file_property.is_meta = True
                        file_property.meta_name = m_uri.group(3)
                        if file_property.meta_name == "big_buck_bunny.f4m":
                            file_property.is_bigbuck = True
                elif m_uri.group(5) != "":
                    file_property.is_chunk = True
                    file_property.rate = m_uri.group(6)
                    file_property.seg = m_uri.group(7)
                    file_property.frag = m_uri.group(8)
                else:
                    logging.debug("Error in parsing uri: {}".format(uri))
                    return None

        # get server address (Dangerous: using blocking queries)
        if server_name == "video.pku.edu.cn":
            if 'www_ip' in self.config:
                server_addr = self.config['www_ip']
            else:
                server_addr = await self.query_name("video.pku.edu.cn")
        else:
            resolver = aiodns.DNSResolver(loop=self.loop)
            try:
                result = await resolver.query(server_name, 'A')
                # just choose the first result
                server_addr = result[0].host
            except Exception as e:
                logging.error("Error when resolving: {}".format(e))
                return None

        # modify request uri
        new_uri = uri
        rate = None
        if file_property.is_meta:
            if file_property.is_bigbuck:
                new_uri = file_property.path + "big_buck_bunny_nolist.f4m"
            else:
                new_uri = file_property.path + file_property.meta_name
        elif file_property.is_chunk:
            rate = self.stat.adapt_bitrate(server_addr)
            if rate is None:
                rate = int(file_property.rate)
            new_uri = file_property.path + str(rate) + 'Seg' + file_property.seg + '-Frag' + file_property.frag

        return server_addr, port, new_uri, file_property, rate

    async def query_name(self, qname):
        dns_request = dns.message.make_query(qname, dns.rdatatype.A, rdclass=dns.rdataclass.IN)

        # Dangerous: using blocking I/O
        # try:
        #     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        #     sock.bind((self.config['fake_ip'], 0))
        #     dns_server = (self.config['dns_ip'], int(self.config['dns_port']))
        #     sock.sendto(bytes(dns_request.get_wire()), dns_server)
        #     data = sock.recv(1024)
        # except Exception as e:
        #     logging.error("Network Error when qeurying name: {}".format(e))
        #     return None

        # change to asyncio, need test
        local = await aioudp.open_local_endpoint(host=self.config["fake_ip"])
        remote = await aioudp.open_remote_endpoint(host=self.config["dns_ip"], port=int(self.config["dns_port"]))
        remote.write(dns_request.to_wire())

        data = await local.read()
        try:
            dns_response = dns.message.from_wire(data.decode())
            ans_ipset = dns_response.get_rrset(dns_response.answer,
                                               dns.name.from_text('video.pku.edu.cn'),
                                               rdtype=dns.rdatatype.A,
                                               rdclass=dns.rdataclass.IN)
            if ans_ipset:
                for ans_ip in ans_ipset:
                    return socket.inet_ntoa(struct.pack("!I", ans_ip))
            else:
                logging.error("Name query gets no answer")
                return None
        except Exception as e:
            logging.error("Error in pasrsing DNS response: {}".format(e))
            return None
