# -*- coding: utf8 -*-
from gevent import monkey; monkey.patch_all()
from pyeth.discovery import EndPoint, Server, Node
import binascii
from urlparse import urlparse


test_boots = [
    # "enode://561ab5a08c6f2e486059f2add5d08932e4f0ebbc6c2a2ba5e0f930a5441e65ec59f5b6684b3e75bed380109135d089e56380dad83357f5fda2122fdbdbe7d168@125.178.244.165:30303",
    "enode://f815b53feab9f68fb6035181029241729cf3ed4cd253f0b3a6a25d5b7a1912be1c4f12504d48fe54cb67b42bd00f6c6b88ab595fc8facd329b5e4ae76978f4f9@159.69.56.113:10934"
    # US-Azure geth
    # "enode://30b7ab30a01c124a6cceca36863ece12c4f5fa68e3ba9b0b51407ccc002eeed3b3102d20a88f1c1d3c3154e2449317b8ef95090e77b312d5cc39354f86d5d606@52.176.7.10:30303",
    # US-Azure parity
    # "enode://865a63255b3bb68023b6bffd5095118fcc13e79dcf014fe4e47e065c350c7cc72af2e53eff895f11ba1bbb6a2b33271c1116ee870f266618eadfc2e78aa7349c@52.176.100.77:30303",
    # Parity
    # "enode://6332792c4a00e3e4ee0926ed89e0d27ef985424d97b6a45bf0f23e51f0dcb5e66b875777506458aea7af6f9e4ffb69f43f3778ee73c81ed9d34c51c4b16b0b0f@52.232.243.152:30303",
    # @gpip
    # "enode://94c15d1b9e2fe7ce56e458b9a3b672ef11894ddedd0c6f247e0f1d3487f52b66208fb4aeb8179fce6e3a749ea93ed147c37976d67af557508d199d9594c35f09@192.81.208.223:30303",
]

main_boots = [
    # Ethereum Foundation Go Bootnodes
    # IE
    "enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@52.16.188.185:30303",
    # US-WEST
    "enode://3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99@13.93.211.84:30303",
    # BR
    "enode://78de8a0916848093c73790ead81d1928bec737d565119932b98c6b100d944b7a95e94f847f689fc723399d2e31129d182f7ef3863f2b4c820abbf3ab2722344d@191.235.84.50:30303",
    # AU
    "enode://158f8aab45f6d19c6cbf4a089c2670541a8da11978a2f90dbf6a502a4a3bab80d288afdbeb7ec0ef6d92de563767f3b1ea9e8e334ca711e9f8e2df5a0385e8e6@13.75.154.138:30303",
    # SG
    "enode://1118980bf48b0a3640bdba04e0fe78b1add18e1cd99bf22d53daac1fd9972ad650df52176e7c7d89d1114cfef2bc23a2959aa54998a46afcf7d91809f0855082@52.74.57.123:30303",

    # Ethereum Foundation C++ Bootnodes
    # DE
    "enode://979b7fa28feeb35a4741660a16076f1943202cb72b6af70d327f053e248bab9ba81760f39d0701ef1d8f89cc1fbd2cacba0710a12cd5314d5e0c9021aa3637f9@5.1.83.226:30303",

]

nodes = []
for n in main_boots:
    info = urlparse(n)
    nodes.append(Node(EndPoint(info.hostname, info.port, info.port), binascii.a2b_hex(info.username)))

server = Server(nodes)
server.run()
