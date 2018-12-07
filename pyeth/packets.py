# -*- coding: utf8 -*-
import struct
from crypto import keccak256
from ipaddress import ip_address
import binascii


class EndPoint(object):
    """
    Endpoint             <= 24 == [17,3,3]
    {
        unsigned address; // BE encoded 32-bit or 128-bit unsigned (layer3 address; size determins ipv4 vs ipv6)
        unsigned udpPort; // BE encoded 16-bit unsigned
        unsigned tcpPort; // BE encoded 16-bit unsigned
    }
    """

    def __init__(self, address, udpPort, tcpPort):
        """
        :param address: compatible with 
        (str bytes)'192.168.1.1',
        (unicode)u'192.168.1.1',
        (int bytes)'\xab\x23\x65\x23',
        (int) 1232345
        """
        if isinstance(address, bytes) and len(address) > 4:
            address = address.decode('utf8')

        self.address = ip_address(address)
        self.udpPort = udpPort
        self.tcpPort = tcpPort

    def pack(self):
        return [self.address.packed,
                struct.pack(">H", self.udpPort),
                struct.pack(">H", self.tcpPort)]

    def __str__(self):
        return "(EP " + self.address.exploded + " " + str(self.udpPort) + " " + str(self.tcpPort) + ")"

    @classmethod
    def unpack(cls, packed):
        udpPort = struct.unpack(">H", packed[1])[0]
        if packed[2] == '':
            tcpPort = udpPort
        else:
            tcpPort = struct.unpack(">H", packed[2])[0]
        return cls(packed[0], udpPort, tcpPort)


class PingNode(object):
    """
    ### Ping (type 0x01)

    Ping packets can be sent and received at any time. The receiver should
    reply with a Pong packet and update the IP/Port of the sender in its
    node table.

    PingNode packet-type: 0x01
    PingNode             <= 59 bytes
    {
        h256 version = 0x3;     <= 1
        Endpoint from;          <= 23
        Endpoint to;            <= 23
        unsigned expiration;    <= 9
    };
    """
    packet_type = '\x01'
    version = '\x04'

    def __init__(self, endpoint_from, endpoint_to, timestamp):
        self.endpoint_from = endpoint_from
        self.endpoint_to = endpoint_to
        self.timestamp = timestamp

    def __str__(self):
        return "(Ping " + str(ord(self.version)) + " " + str(self.endpoint_from) + " " + str(
            self.endpoint_to) + " " + str(self.timestamp) + ")"

    def pack(self):
        return [self.version,
                self.endpoint_from.pack(),
                self.endpoint_to.pack(),
                struct.pack(">I", self.timestamp)]

    @classmethod
    def unpack(cls, packed):
        # assert(packed[0] == cls.version)
        endpoint_from = EndPoint.unpack(packed[1])
        endpoint_to = EndPoint.unpack(packed[2])
        timestamp = struct.unpack(">I", packed[3])[0]
        return cls(endpoint_from, endpoint_to, timestamp)


class Pong(object):
    """
    ### Pong (type 0x02)

    Pong is the reply to a Ping packet.

    Pong packet-type: 0x02
    Pong                 <= 66 bytes
    {
        Endpoint to;
        h256 echo;
        unsigned expiration;
    };
    """
    packet_type = '\x02'

    def __init__(self, to, echo, timestamp):
        self.to = to
        self.echo = echo
        self.timestamp = timestamp

    def __str__(self):
        return "(Pong " + str(self.to) + " <echo hash=""> " + str(self.timestamp) + ")"

    def pack(self):
        return [
            self.to.pack(),
            self.echo,
            struct.pack(">I", self.timestamp)]

    @classmethod
    def unpack(cls, packed):
        to = EndPoint.unpack(packed[0])
        echo = packed[1]
        timestamp = struct.unpack(">I", packed[2])[0]
        return cls(to, echo, timestamp)


class FindNeighbors(object):
    """
    ### Find Node (type 0x03)

    Find Node packets are sent to locate nodes close to a given target ID.
    The receiver should reply with a Neighbors packet containing the `k`
    nodes closest to target that it knows about.

    FindNode packet-type: 0x03
    FindNode             <= 76 bytes
    {
        NodeId target; // Id of a node. The responding node will send back nodes closest to the target.
        unsigned expiration;
    };
    """
    packet_type = '\x03'

    def __init__(self, target, timestamp):
        self.target = target
        self.timestamp = timestamp

    def __str__(self):
        return "(FN " + binascii.b2a_hex(keccak256(self.target))[:8] + " " + str(self.timestamp) + ")"

    def pack(self):
        return [
            self.target,
            struct.pack(">I", self.timestamp)
        ]

    @classmethod
    def unpack(cls, packed):
        timestamp = struct.unpack(">I", packed[1])[0]
        return cls(packed[0], timestamp)


class Neighbors(object):
    """
    ### Neighbors (type 0x04)

    Neighbors is the reply to Find Node. It contains up to `k` nodes that
    the sender knows which are closest to the requested `Target`.

    Neighbors packet-type: 0x04
    Neighbours           <= 1423
    {
        list nodes: struct Neighbour    <= 88: 1411; 76: 1219
        {
            inline Endpoint endpoint;
            NodeId node;
        };

        unsigned expiration;
    };
    """
    packet_type = '\x04'

    def __init__(self, nodes, timestamp):
        self.nodes = nodes
        self.timestamp = timestamp

    def __str__(self):
        return "(Ns [" + ", ".join(map(str, self.nodes)) + "] " + str(self.timestamp) + ")"

    def pack(self):
        return [
            map(lambda x: x.pack(), self.nodes),
            struct.pack(">I", self.timestamp)
        ]

    @classmethod
    def unpack(cls, packed):
        nodes = map(lambda x: Node.unpack(x), packed[0])
        timestamp = struct.unpack(">I", packed[1])[0]
        return cls(nodes, timestamp)


class Node(object):
    def __init__(self, endpoint, node_key):
        self.endpoint = endpoint
        self.node_key = None
        self.node_id = None
        self.added_time = Node

        self.set_pubkey(node_key)

    def set_pubkey(self, pubkey):
        self.node_key = pubkey
        self.node_id = keccak256(self.node_key)

    def __str__(self):
        return "(N " + binascii.b2a_hex(self.node_id)[:8] + ")"

    def pack(self):
        packed = self.endpoint.pack()
        packed.append(self.node_key)
        return packed

    @classmethod
    def unpack(cls, packed):
        endpoint = EndPoint.unpack(packed[0:3])
        return cls(endpoint, packed[3])


PACKET_TYPES = {
    PingNode.packet_type: 'Ping',
    Pong.packet_type: 'Pong',
    FindNeighbors.packet_type: 'FN',
    Neighbors.packet_type: 'Ns',
}
