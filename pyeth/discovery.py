# -*- coding: utf8 -*-
import socket
import threading
import time
import struct
import rlp
from crypto import keccak256
from secp256k1 import PrivateKey, PublicKey
from ipaddress import ip_address
import binascii
import select


class EndPoint(object):
    """
    struct Endpoint             <= 24 == [17,3,3]
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

    PingNode packet-type: 0x01
    struct PingNode             <= 59 bytes
    {
        h256 version = 0x3;     <= 1
        Endpoint from;          <= 23
        Endpoint to;            <= 23
        unsigned expiration;    <= 9
    };
    """
    packet_type = '\x01'
    version = '\x03'

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
    struct Pong                 <= 66 bytes
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
    struct FindNode             <= 76 bytes
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
        return "(FN " + binascii.b2a_hex(self.target)[:7] + "... " + str(self.timestamp) + ")"

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
    struct Neighbours           <= 1423
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
    def __init__(self, endpoint, node):
        self.endpoint = endpoint
        self.node = node

    def __str__(self):
        return "(N " + binascii.b2a_hex(self.node)[:7] + "...)"

    def pack(self):
        packed = self.endpoint.pack()
        packed.append(self.node)
        return packed

    @classmethod
    def unpack(cls, packed):
        endpoint = EndPoint.unpack(packed[0:3])
        return cls(endpoint, packed[3])


class Server(object):
    def __init__(self, my_endpoint):
        self.endpoint = my_endpoint

        # 获取私钥
        priv_key_file = open('priv_key', 'r')
        priv_key_serialized = priv_key_file.read()
        priv_key_file.close()
        self.priv_key = PrivateKey()
        self.priv_key.deserialize(priv_key_serialized)

        # 初始化套接字
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', self.endpoint.udpPort))
        # set socket non-blocking mode
        self.sock.setblocking(0)

    def wrap_packet(self, packet):
        """
        UDP packets are structured as follows:

        hash || signature || packet-type || packet-data
        packet-type: single byte < 2**7 // valid values are [1,4]
        packet-data: RLP encoded list. Packet properties are serialized in the order in
                    which they're defined. See packet-data below.

        Offset  |
        0       | MDC       | Ensures integrity of packet,
        65      | signature | Ensures authenticity of sender, `SIGN(sender-privkey, MDC)`
        97      | type      | Single byte in range [1, 4] that determines the structure of Data
        98      | data      | RLP encoded, see section Packet Data

        The packets are signed and authenticated. The sender's Node ID is determined by
        recovering the public key from the signature.

            sender-pubkey = ECRECOVER(Signature)

        The integrity of the packet can then be verified by computing the
        expected MDC of the packet as:

            MDC = SHA3(sender-pubkey || type || data)

        As an optimization, implementations may look up the public key by
        the UDP sending address and compute MDC before recovering the sender ID.
        If the MDC values do not match, the packet can be dropped.
                """
        payload = packet.packet_type + rlp.encode(packet.pack())
        sig = self.priv_key.ecdsa_sign_recoverable(keccak256(payload),
                                                   raw=True)
        sig_serialized = self.priv_key.ecdsa_recoverable_serialize(sig)
        payload = sig_serialized[0] + chr(sig_serialized[1]) + payload

        payload_hash = keccak256(payload)
        return payload_hash + payload

    def listen(self):
        print "listening..."
        while True:
            ready = select.select([self.sock], [], [], 1.0)
            if ready[0]:
                data, addr = self.sock.recvfrom(2048)
                print "received message[", addr, "]:"
                self.receive(data, addr)

    def listen_thread(self):
        thread = threading.Thread(target=self.listen)
        thread.daemon = True
        return thread

    def receive(self, data, addr):
        """
        macSize  = 256 / 8 = 32
        sigSize  = 520 / 8 = 65
        headSize = macSize + sigSize = 97
        hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]
        shouldhash := crypto.Sha3(buf[macSize:])
        """
        # verify hash
        msg_hash = data[:32]
        if msg_hash != keccak256(data[32:]):
            print " First 32 bytes are not keccak256 hash of the rest."
            return
        else:
            print " Verified message hash."

        # verify signature
        signature = data[32:97]
        signed_data = data[97:]
        deserialized_sig = self.priv_key.ecdsa_recoverable_deserialize(signature[:64],
                                                                       ord(signature[64]))

        remote_pubkey = self.priv_key.ecdsa_recover(keccak256(signed_data),
                                                    deserialized_sig,
                                                    raw=True)

        pub = PublicKey()
        pub.public_key = remote_pubkey

        verified = pub.ecdsa_verify(keccak256(signed_data),
                                    pub.ecdsa_recoverable_convert(deserialized_sig),
                                    raw=True)

        if not verified:
            print " Signature invalid"
            return
        else:
            print " Verified signature."

        response_types = {
            PingNode.packet_type: self.receive_ping,
            Pong.packet_type: self.receive_pong,
            FindNeighbors.packet_type: self.receive_find_neighbors,
            Neighbors.packet_type: self.receive_neighbors
        }

        try:
            packet_type = data[97]
            dispatch = response_types[packet_type]
        except KeyError:
            print " Unknown message type: " + data[97]
            return

        payload = data[98:]
        dispatch(payload, msg_hash, addr)

    def receive_pong(self, payload, msg_hash, addr):
        print " received Pong"
        print "", Pong.unpack(rlp.decode(payload))

    def receive_ping(self, payload, msg_hash, addr):
        print " received Ping"
        ping = PingNode.unpack(rlp.decode(payload))
        endpoint_to = EndPoint(addr[0], ping.endpoint_from.udpPort, ping.endpoint_from.tcpPort)
        pong = Pong(endpoint_to, msg_hash, time.time() + 60)
        print "  sending Pong response: " + str(pong)
        self.send(pong, pong.to)

    def receive_find_neighbors(self, payload, msg_hash, addr):
        print " received FindNeighbors"
        print "", FindNeighbors.unpack(rlp.decode(payload))

    def receive_neighbors(self, payload, msg_hash, addr):
        print " received Neighbors"
        print "", Neighbors.unpack(rlp.decode(payload))

    def ping(self, endpoint):
        ping = PingNode(self.endpoint, endpoint, time.time() + 60)
        message = self.wrap_packet(ping)
        print "sending " + str(ping)
        self.sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))

    def send(self, packet, endpoint):
        message = self.wrap_packet(packet)
        print "sending " + str(packet)
        self.sock.sendto(message, (endpoint.address.exploded, endpoint.udpPort))
