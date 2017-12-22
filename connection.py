import asyncio
import logging
import re
import socket
import struct
import dns
import aiodns


class FileProperty:
    def __init__(self, path="",
                 is_meta=False, meta_name="", is_bigbuck=False,
                 is_chunk=False, chunk_name="", seg="", frag=""):
        self.path = path
        self.is_meta, self.meta_name, self.is_bigbuck = is_meta, meta_name, is_bigbuck
        self.is_chunk, self.chunk_name, self.seg, self.frag = is_chunk, chunk_name, seg, frag


class Connection:
    def __init__(self, config, loop, stat):
        self.config = config
        self.loop = loop
        self.stat = stat

    async def handle_browser_read(self, breader, bwriter):
        data = await breader.read()
        request_message = data.decode()
        logging.info(
            "Receiving request from {} with size {}".format(breader.get_extra_info('peername'), len(request_message)))

        request, rest = request_message.split('\r\n', 1)
        headers, content = rest.split('\r\n\r\n', 1)
        header_fields = headers.split('\r\n')
        header_map = {}
        for field in header_fields:
            key, value = field.split(':')
            header_map[key] = value

        method, url, version = request.split()
        remote_addr, remote_port, uri, file_property = await self.modify_url(url)
        answer_data = self.contact_server()

    async def modify_url(self, url):

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
                    file_property.chunk_name = m_uri.group(5)
                    file_property.seg = m_uri.group(7)
                    file_property.seg = m_uri.group(8)
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
        if file_property.is_meta:
            if file_property.is_bigbuck:
                new_uri = file_property.path + "big_buck_bunny_nolist.f4m"
            else:
                new_uri = file_property.path + file_property.meta_name
        elif file_property.is_chunk:
            new_uri = self.choose_bitrate(server_addr)

        return server_addr, port, new_uri, file_property

    async def query_name(self, qname):
        dns_request = dns.renderer.Renderer(id=1, flags=0)
        dns_request.add_question(qname=qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN)
        # Dangerous: using blocking I/O
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.bind((self.config['fake_ip'], 0))
            dns_server = (self.config['dns_ip'], int(self.config['dns_port']))
            sock.sendto(bytes(dns_request.get_wire()), dns_server)
            data = sock.recv(1024)
        except Exception as e:
            logging.error("Network Error when qeurying name: {}".format(e))
            return None
        dns_response = dns.message.from_wire(data.decode())
        ans_ipset = dns_response.find_rrset(dns_response.answer,
                                            dns.name.from_text('video.pku.edu.cn'),
                                            rdtype=dns.rdatatype.A,
                                            rdclass=dns.rdataclass.IN)
        if len(ans_ipset) > 0:
            for ans_ip in ans_ipset:
                return ans_ip
        else:
            logging.error("Name query gets no answer")
            return None
