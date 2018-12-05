# -*- coding: utf8 -*-
from pyeth.discovery import EndPoint, Server, Node
import binascii

boot_key = "669f45b66acf3b804c26ce13cfdd1f7e3d0ff4ed85060841b9af3af6dbfbacd05181e1c9363161446a307f3ca24e707856a01e4bf1eed5e1aefc14011a5c1c1c"
# boot_endpoint = EndPoint(u'127.0.0.1', 30301, 30301)
boot_endpoint = EndPoint(u'52.74.57.123', 30303, 30303)
boot_node = Node(boot_endpoint, binascii.a2b_hex(boot_key))

server = Server([boot_node])
server.run()
