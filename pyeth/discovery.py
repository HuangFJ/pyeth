# -*- coding: utf8 -*-
import socket
import gevent
from gevent.queue import Queue
from gevent.event import Event, AsyncResult
from gevent.select import select
import time
import struct
import rlp
from crypto import keccak256, pubkey_format
from table import RoutingTable
from secp256k1 import PrivateKey, PublicKey
from ipaddress import ip_address
import binascii
from constants import LOGGER, BUCKET_SIZE, K_BOND_EXPIRATION, K_EXPIRATION, K_MAX_NEIGHBORS, K_REQUEST_TIMEOUT,\
    RET_PENDING_OK, RET_PENDING_TIMEOUT


class Pending(object):
    def __init__(self, from_id, packet_type, callback, deadline=None):
        self.from_id = from_id
        self.packet_type = packet_type
        self.callback = callback
        self.deadline = deadline
        self.ret = AsyncResult()


class Reply(object):
    def __init__(self, from_id, packet_type, data, matcher=None):
        self.from_id = from_id
        self.packet_type = packet_type
        self.data = data
        self.matcher = matcher


class TimeBomb(object):
    pass


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
    def __init__(self, endpoint, node_key):
        self.endpoint = endpoint
        self.node_key = node_key
        self.node_id = keccak256(self.node_key)
        self.added_time = Node

    def __str__(self):
        return "(N " + binascii.b2a_hex(self.node_key)[:7] + "...)"

    def pack(self):
        packed = self.endpoint.pack()
        packed.append(self.node_key)
        return packed

    @classmethod
    def unpack(cls, packed):
        endpoint = EndPoint.unpack(packed[0:3])
        return cls(endpoint, packed[3])


class Server(object):
    def __init__(self, boot_nodes):
        # the endpoint of this server
        # this is a fake ip address used in packets.
        self.endpoint = EndPoint(u'127.0.0.1', 30303, 30303)
        # boot nodes
        self.boot_nodes = boot_nodes
        # event queue collecting Pending, Reply or TimeBomb
        self.events = Queue()
        # last pong received time of the special node id
        self.last_pong_received = {}
        # last ping received time of the special node id
        self.last_ping_received = {}

        # have the private key
        priv_key_file = open('priv_key', 'r')
        priv_key_serialized = priv_key_file.read()
        priv_key_file.close()
        self.priv_key = PrivateKey()
        self.priv_key.deserialize(priv_key_serialized)

        # routing table
        self.table = RoutingTable(Node(self.endpoint, pubkey_format(self.priv_key.pubkey)), self)

        # initialize UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', self.endpoint.udpPort))
        # set socket non-blocking mode
        self.sock.setblocking(0)

    def poll(self):
        """
        loop consuming the event queue
        
        """
        pending_list = []

        self.events.put(TimeBomb())
        while True:
            event = self.events.get()

            if isinstance(event, Reply):
                for pending in list(pending_list):
                    if pending.from_id == event.from_id and pending.packet_type == event.packet_type:
                        if event.matcher:
                            event.matcher()
                        if pending.callback(event.data):
                            pending_list.remove(pending)
                            pending.ret.set(RET_PENDING_OK)

            elif isinstance(event, Pending):
                event.deadline = time.time() + K_REQUEST_TIMEOUT
                pending_list.append(event)

            elif isinstance(event, TimeBomb):
                now = time.time()
                dist = K_REQUEST_TIMEOUT

                for pending in list(pending_list):
                    dist = pending.deadline - now
                    if dist > 0:
                        break
                    pending_list.remove(pending)
                    pending.ret.set(RET_PENDING_TIMEOUT)

                gevent.spawn_later(dist, lambda: self.events.put(TimeBomb()))

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
        LOGGER.info("listening...")
        while True:
            ready = select([self.sock], [], [], 1.0)
            if ready[0]:
                data, addr = self.sock.recvfrom(2048)
                LOGGER.debug("<<< message[{}]:".format(addr))
                try:
                    self.receive(data, addr)
                except Exception, e:
                    LOGGER.exception(e)

    def run(self):
        gevent.spawn(self.listen)
        gevent.spawn(self.poll)

        boot_node = self.boot_nodes[0]
        self.find_neighbors(boot_node, boot_node.node_key)

        # wait forever
        evt = Event()
        evt.wait()

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
        assert msg_hash == keccak256(data[32:]), "First 32 bytes are not keccak256 hash of the rest"

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

        assert verified, "Signature invalid"

        pubkey = pubkey_format(pub)[1:]
        LOGGER.debug(" remote PubKey {}".format(binascii.hexlify(pubkey)))

        packet_type = data[97]
        payload = rlp.decode(data[98:])
        if packet_type == PingNode.packet_type:
            # fake ip in packet
            payload[1][0] = addr[0]
            ping = PingNode.unpack(payload)
            if expired(ping):
                return
            LOGGER.debug(" received {}".format(ping))
            self.receive_ping(ping, msg_hash, addr, pubkey)
        elif packet_type == Pong.packet_type:
            pong = Pong.unpack(payload)
            if expired(pong):
                return
            LOGGER.debug(" received {}".format(pong))
            self.receive_pong(pong, pubkey)
        elif packet_type == FindNeighbors.packet_type:
            fn = FindNeighbors.unpack(payload)
            if expired(fn):
                return
            LOGGER.debug(" received {}".format(fn))
            self.receive_find_neighbors(fn, addr, pubkey)
        elif packet_type == Neighbors.packet_type:
            neighbours = Neighbors.unpack(payload)
            if expired(neighbours):
                return
            LOGGER.debug(" received {}".format(neighbours))
            self.receive_neighbors(neighbours, pubkey)
        else:
            assert False, " Unknown message type: {}".format(packet_type)

    def receive_pong(self, pong, pubkey):
        remote_id = keccak256(pubkey)
        # response to ping
        last_pong_received = self.last_pong_received

        def matcher():
            # solicited reply
            last_pong_received[remote_id] = time.time()

        self.events.put(Reply(remote_id, Pong.packet_type, pong, matcher))

    def receive_ping(self, ping, msg_hash, addr, pubkey):
        remote_id = keccak256(pubkey)
        endpoint_to = EndPoint(addr[0], ping.endpoint_from.udpPort, ping.endpoint_from.tcpPort)
        pong = Pong(endpoint_to, msg_hash, time.time() + K_EXPIRATION)
        # sending Pong response
        self.send(pong, pong.to)

        self.events.put(Reply(remote_id, PingNode.packet_type, ping))

        node = Node(endpoint_to, pubkey)
        if time.time() - self.last_pong_received.get(remote_id, 0) > K_BOND_EXPIRATION:
            self.ping(node, lambda: self.add_table(node))
        else:
            self.add_table(node)

        self.last_ping_received[remote_id] = time.time()

    def receive_find_neighbors(self, fn, addr, pubkey):
        remote_id = keccak256(pubkey)
        if time.time() - self.last_pong_received.get(remote_id, 0) > K_BOND_EXPIRATION:
            # lost origin or origin is off
            return

        target_id = keccak256(fn.target)
        closest = self.table.closest(target_id, BUCKET_SIZE)

        ns = Neighbors([], time.time() + K_EXPIRATION)
        sent = False
        for c in closest:
            ns.nodes.append(c)

            if len(ns.nodes) == K_MAX_NEIGHBORS:
                self.send(ns, EndPoint(addr[0], addr[1], addr[1]))
                ns.nodes = []
                sent = True

        if len(ns.nodes) > 0 or not sent:
            self.send(ns, EndPoint(addr[0], addr[1], addr[1]))

    def receive_neighbors(self, neighbours, pubkey):
        remote_id = keccak256(pubkey)
        # response to find neighbours
        self.events.put(Reply(remote_id, Neighbors.packet_type, neighbours))

    def ping(self, node, callback=None):
        ping = PingNode(self.endpoint, node.endpoint, time.time() + K_EXPIRATION)
        message = self.wrap_packet(ping)
        msg_hash = message[:32]

        def reply_call(pong):
            if pong.echo == msg_hash:
                if callback is not None:
                    callback()

                return True

        pending = Pending(node.node_id, Pong.packet_type, reply_call)
        self.events.put(pending)
        ep = (node.endpoint.address.exploded, node.endpoint.udpPort)
        LOGGER.debug(">>> message[{}]:".format(ep))
        LOGGER.debug(" sending {}".format(ping))
        self.sock.sendto(message, ep)

        return pending

    def find_neighbors(self, node, target_key, callback=None):
        node_id = node.node_id
        if time.time() - self.last_ping_received.get(node_id, 0) > K_BOND_EXPIRATION:
            self.ping(node)
            self.events.put(Pending(node_id, PingNode.packet_type, lambda _: True))

        fn = FindNeighbors(target_key, time.time() + K_EXPIRATION)

        def reply_call(neighbors):
            for neighbor_node in neighbors.nodes:
                reply_call.num_received += 1
                reply_call.nodes.append(neighbor_node)

            if reply_call.num_received >= BUCKET_SIZE:
                for n in reply_call.nodes:
                    self.add_table(n)
                if callback is not None:
                    callback(reply_call.nodes)

                return True

        # nonlocal variables
        reply_call.nodes = []
        reply_call.num_received = 0

        pending = Pending(node.node_id, Neighbors.packet_type, reply_call)
        self.events.put(pending)
        self.send(fn, node.endpoint)

        return pending

    def send(self, packet, endpoint):
        message = self.wrap_packet(packet)
        ep = (endpoint.address.exploded, endpoint.udpPort)
        LOGGER.debug(">>> message[{}]:".format(ep))
        LOGGER.debug(" sending {}".format(packet))
        self.sock.sendto(message, ep)

    def add_table(self, node):
        self.table.add_node(node)


def expired(packet):
    return packet.timestamp < time.time()
