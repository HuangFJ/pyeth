# -*- coding: utf8 -*-
from pyeth.discovery import EndPoint, PingNode, Server, FindNeighbors, Node
import time
import binascii

bootnode_key = "1118980bf48b0a3640bdba04e0fe78b1add18e1cd99bf22d53daac1fd9972ad650df52176e7c7d89d1114cfef2bc23a2959aa54998a46afcf7d91809f0855082"

bootnode_endpoint = EndPoint(u'52.74.57.123',
                             30303,
                             30303)

bootnode = Node(bootnode_endpoint,
                binascii.a2b_hex(bootnode_key))

# this is a fake ip address used in packets.
my_endpoint = EndPoint(u'52.4.20.183', 30303, 30303)
server = Server(my_endpoint)

listen_thread = server.listen_thread()
listen_thread.start()

fn = FindNeighbors(bootnode.node, time.time() + 60)
ping = PingNode(my_endpoint, bootnode.endpoint, time.time() + 60)

# introduce self
server.send(ping, bootnode.endpoint)
# wait for pong-ping-pong
time.sleep(3)
# ask for neighbors
server.send(fn, bootnode.endpoint)
# wait for response
time.sleep(3)
