# -*- coding: utf8 -*-
import socket
import gevent
from gevent import Greenlet
from gevent.queue import Queue, Empty
from gevent.event import Event
from gevent.select import select
import time
import rlp
from crypto import keccak256, pubkey_format
from table import RoutingTable
from secp256k1 import PrivateKey, PublicKey
import binascii
from constants import LOGGER, BUCKET_SIZE, K_BOND_EXPIRATION, K_EXPIRATION, K_MAX_NEIGHBORS, K_REQUEST_TIMEOUT
from packets import EndPoint, Node, PingNode, Pong, FindNeighbors, Neighbors, PACKET_TYPES


class Pending(Greenlet):
    """
    trigger while making a request like ping or find_neighbours, expecting a pong or neighbours response
    from_id: the remote node id
    packet_type: expecting response packet type
    callback: invoked while response correctly, request side define done to close pending: 
        callback(chunks:[packet, ...]) -> done:bool
    """

    def __init__(self, from_id, packet_type, callback):
        Greenlet.__init__(self)

        self._from_id = from_id
        self._packet_type = packet_type
        self._callback = callback

        self._box = Queue()

    def is_alive(self):
        return self._box is not None

    def match(self, from_id, packet_type, packet):
        if self._box is not None and from_id == self._from_id and packet_type == self._packet_type:
            self._box.put(packet)
            return True

    def _run(self):
        chunks = []
        while self._box is not None:
            try:
                packet = self._box.get(timeout=K_REQUEST_TIMEOUT)
                chunks.append(packet)
            except Empty:
                hex_id = binascii.hexlify(self._from_id)
                LOGGER.warning('<-//- {}... {} timeout'.format(hex_id[:7], PACKET_TYPES.get(self._packet_type)))
                # timeout
                self._box = None
                return None
            except:
                # die
                self._box = None
                raise

            try:
                if self._callback(chunks):
                    # job done
                    self._box = None
                    return chunks
            except:
                # die
                self._box = None
                raise


class Server(object):
    def __init__(self, boot_nodes):
        # the endpoint of this server
        # this is a fake ip address used in packets.
        self.endpoint = EndPoint(u'127.0.0.1', 30303, 30303)
        # boot nodes
        self.boot_nodes = boot_nodes
        # hold all of pending
        self.pending_hold = []
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
        self.table = RoutingTable(Node(self.endpoint, pubkey_format(self.priv_key.pubkey)[1:]), self)

        # initialize UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', self.endpoint.udpPort))
        # set socket non-blocking mode
        self.sock.setblocking(0)

    def add_table(self, node):
        self.table.add_node(node)

    def add_pending(self, pending):
        pending.start()
        self.pending_hold.append(pending)
        return pending

    def run(self):
        gevent.spawn(self.clean_pending)
        gevent.spawn(self.listen)
        # wait forever
        evt = Event()
        evt.wait()

    def clean_pending(self):
        while True:
            for pending in list(self.pending_hold):
                if not pending.is_alive():
                    self.pending_hold.remove(pending)
            time.sleep(K_REQUEST_TIMEOUT)

    def listen(self):
        LOGGER.info("listening...")
        while True:
            ready = select([self.sock], [], [], 1.0)
            if ready[0]:
                data, addr = self.sock.recvfrom(2048)
                # non-block data reading
                gevent.spawn(self.receive, data, addr)

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
        pubkey_hex = binascii.hexlify(pubkey)

        packet_type = data[97]
        payload = rlp.decode(data[98:])
        if packet_type == PingNode.packet_type:
            # fake ip in packet
            payload[1][0] = addr[0]
            ping = PingNode.unpack(payload)
            if expired(ping):
                return
            LOGGER.debug("<---- {}...@{}:{} {}".format(pubkey_hex[:7], addr[0], addr[1], ping))
            self.receive_ping(ping, msg_hash, addr, pubkey)
        elif packet_type == Pong.packet_type:
            pong = Pong.unpack(payload)
            if expired(pong):
                return
            LOGGER.debug("<---- {}...@{}:{} {}".format(pubkey_hex[:7], addr[0], addr[1], pong))
            self.receive_pong(pong, pubkey)
        elif packet_type == FindNeighbors.packet_type:
            fn = FindNeighbors.unpack(payload)
            if expired(fn):
                return
            LOGGER.debug("<---- {}...@{}:{} {}".format(pubkey_hex[:7], addr[0], addr[1], fn))
            self.receive_find_neighbors(fn, addr, pubkey)
        elif packet_type == Neighbors.packet_type:
            neighbours = Neighbors.unpack(payload)
            if expired(neighbours):
                return
            LOGGER.debug("<---- {}...@{}:{} {}".format(pubkey_hex[:7], addr[0], addr[1], neighbours))
            self.receive_neighbors(neighbours, pubkey)
        else:
            assert False, " Unknown message type: {}".format(packet_type)

    def receive_pong(self, pong, pubkey):
        remote_id = keccak256(pubkey)
        # response to ping
        last_pong_received = self.last_pong_received

        def match_callback():
            # solicited reply
            last_pong_received[remote_id] = time.time()

        self.handle_reply(remote_id, Pong.packet_type, pong, match_callback)

    def receive_ping(self, ping, msg_hash, addr, pubkey):
        remote_id = keccak256(pubkey)
        endpoint_to = EndPoint(addr[0], ping.endpoint_from.udpPort, ping.endpoint_from.tcpPort)
        pong = Pong(endpoint_to, msg_hash, time.time() + K_EXPIRATION)
        # sending Pong response
        self.send(pong, pong.to)

        self.handle_reply(remote_id, PingNode.packet_type, ping)

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

        # sent neighbours in chunks
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
        self.handle_reply(remote_id, Neighbors.packet_type, neighbours)

    def handle_reply(self, from_id, packet_type, packet, match_callback=None):
        for pending in self.pending_hold:
            if pending.match(from_id, packet_type, packet):
                if match_callback is not None:
                    match_callback()

    def ping(self, node, callback=None):
        """
        send a ping request to the given node and return instantly
        invoke callback while reply arrives
        """
        ping = PingNode(self.endpoint, node.endpoint, time.time() + K_EXPIRATION)
        message = self.wrap_packet(ping)
        msg_hash = message[:32]

        def reply_call(chunks):
            if chunks.pop().echo == msg_hash:
                if callback is not None:
                    callback()

                return True

        ep = (node.endpoint.address.exploded, node.endpoint.udpPort)
        self.sock.sendto(message, ep)
        LOGGER.debug("----> {}:{} {}".format(ep[0], ep[1], ping))

        return self.add_pending(Pending(node.node_id, Pong.packet_type, reply_call))

    def find_neighbors(self, node, target_key):
        """
        send a find neighbours request to the given node and 
        waits until the node has sent up to k neighbours
        """
        node_id = node.node_id
        if time.time() - self.last_ping_received.get(node_id, 0) > K_BOND_EXPIRATION:
            # send a ping and wait for a pong
            self.ping(node).join()
            # wait for a ping
            self.add_pending(Pending(node_id, PingNode.packet_type, lambda _: True)).join()

        fn = FindNeighbors(target_key, time.time() + K_EXPIRATION)

        def reply_call(chunks):
            num_received = 0
            for neighbors in chunks:
                num_received += len(neighbors.nodes)

            if num_received >= BUCKET_SIZE:
                return True

        self.send(fn, node.endpoint)
        # block to wait for neighbours
        ret = self.add_pending(Pending(node.node_id, Neighbors.packet_type, reply_call)).get()
        if ret:
            neighbor_nodes = []
            for chunk in ret:
                for n in chunk.nodes:
                    neighbor_nodes.append(n)

            return neighbor_nodes

    def send(self, packet, endpoint):
        message = self.wrap_packet(packet)
        ep = (endpoint.address.exploded, endpoint.udpPort)
        self.sock.sendto(message, ep)
        LOGGER.debug("----> {}:{} {}".format(ep[0], ep[1], packet))

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


def expired(packet):
    return packet.timestamp < time.time()
