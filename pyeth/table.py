import time
import gevent
from gevent import time
from gevent.queue import Queue
from crypto import keccak256, int_to_big_endian
import random
from constants import LOGGER, BUCKET_NUMBER, RE_VALIDATE_INTERVAL, \
    BUCKET_SIZE, BUCKET_MIN_DISTANCE, K_MAX_KEY_VALUE, KAD_ALPHA, REFRESH_INTERVAL, K_PUBKEY_SIZE


def push_node(collection, node, max_size):
    collection.insert(0, node)
    if len(collection) > max_size:
        return collection.pop()


def del_node(coll, node):
    for ele in list(coll):
        if ele.node_id == node.node_id:
            coll.remove(ele)
            return


def find_farther_to_target_than(arr, t, node):
    n_id = node.node_id
    for c in arr:
        c_id = c.node_id
        for i in range(len(t)):
            tc = ord(t[i]) ^ ord(c_id[i])
            tn = ord(t[i]) ^ ord(n_id[i])
            if tc > tn:
                return c
            elif tc < tn:
                break


class RoutingTable(object):
    def __init__(self, self_node, server):
        self.buckets = [Bucket() for _ in range(BUCKET_NUMBER)]
        self.self_node = self_node
        self.server = server

        # add seed nodes
        for bn in self.server.boot_nodes:
            self.add_node(bn)

        gevent.spawn(self.re_validate)
        gevent.spawn(self.refresh)

    def lookup(self, target_key):
        target_id = keccak256(target_key)
        closest = []
        while not closest:
            closest = self.closest(target_id, BUCKET_SIZE)

            if not closest:
                # add seed nodes
                for bn in self.server.boot_nodes:
                    self.add_node(bn)

        asked = [self.self_node.node_id]
        pending_queries = 0
        reply_queue = Queue()
        while True:
            for n in closest:
                if pending_queries >= KAD_ALPHA:
                    break

                if n.node_id not in asked:
                    asked.append(n.node_id)
                    pending_queries += 1
                    gevent.spawn(self.find_neighbours, n, target_key, reply_queue)

            if pending_queries == 0:
                break

            ns = reply_queue.get()
            pending_queries -= 1

            if ns:
                for node in ns:
                    farther = find_farther_to_target_than(closest, target_id, node)

                    if farther:
                        closest.remove(farther)

                    if len(closest) < BUCKET_SIZE:
                        closest.append(node)

    def refresh(self):
        assert self.server.boot_nodes, "no boot nodes"

        while True:
            # self lookup to discover neighbours
            self.lookup(self.self_node.node_key)

            for i in range(3):
                random_int = random.randint(0, K_MAX_KEY_VALUE)
                node_key = int_to_big_endian(random_int).rjust(K_PUBKEY_SIZE / 8, b'\x00')
                self.lookup(node_key)

            time.sleep(REFRESH_INTERVAL)

    def re_validate(self):
        """
        checks that the last node in a random bucket is still alive
        and replace or delete it if it isn't
        """
        while True:
            time.sleep(RE_VALIDATE_INTERVAL)

            # the last node in a random, non-empty bucket
            bi = 0
            last = None
            idx_arr = [i for i in range(len(self.buckets))]
            random.shuffle(idx_arr)
            for bi in idx_arr:
                bucket = self.buckets[bi]
                if len(bucket.nodes) > 0:
                    last = bucket.nodes.pop()
                    break
            if last is not None:
                LOGGER.debug('{:5} revalidate {}'.format('', last))
                # wait for a pong
                ret = self.server.ping(last).get()
                bucket = self.buckets[bi]
                if ret:
                    # bump node
                    bucket.nodes.insert(0, last)
                else:
                    # pick a replacement
                    if len(bucket.replace_cache) > 0:
                        r = bucket.replace_cache.pop(random.randint(0, len(bucket.replace_cache) - 1))
                        if r:
                            bucket.nodes.append(r)

    def add_node(self, node):
        bucket = self.get_bucket(node)

        # exclude self
        if self.self_node.node_id == node.node_id:
            return
        # bucket contains the node, remove the old one, push the new one
        for n in list(bucket.nodes):
            if n.node_id == node.node_id:
                bucket.nodes.remove(n)
                bucket.nodes.insert(0, node)
                LOGGER.debug('{:5} bump {} in bucket #{}'.format('', node, self.buckets.index(bucket)))
                return
        # bucket is full, push node to replace cache
        if len(bucket.nodes) >= BUCKET_SIZE:
            for rc in bucket.replace_cache:
                if rc.node_id == node.node_id:
                    return

            push_node(bucket.replace_cache, node, BUCKET_SIZE)
            LOGGER.debug('{:5} push {} to replacement #{}'.format('', node, self.buckets.index(bucket)))
            return
        # push node to bucket, delete node from replace cache
        push_node(bucket.nodes, node, BUCKET_SIZE)
        LOGGER.debug('{:5} push {} to bucket #{}'.format('', node, self.buckets.index(bucket)))
        del_node(bucket.replace_cache, node)
        node.added_time = time.time()

    def get_bucket(self, node):
        self_id = self.self_node.node_id
        node_id = node.node_id

        leading_zero = 0

        for i in range(len(self_id)):
            diff = ord(self_id[i]) ^ ord(node_id[i])
            if diff == 0:
                leading_zero += 8
            else:
                leading_zero += 8 - len('{:b}'.format(diff))
                break

        distance = len(self_id) * 8 - leading_zero

        if distance <= BUCKET_MIN_DISTANCE:
            return self.buckets[0]
        else:
            return self.buckets[distance - BUCKET_MIN_DISTANCE - 1]

    def closest(self, target_id, num):
        arr = []
        for bucket in self.buckets:
            for node in bucket.nodes:
                farther = find_farther_to_target_than(arr, target_id, node)
                if farther:
                    arr.remove(farther)

                if len(arr) < num:
                    arr.append(node)

        return arr

    def find_neighbours(self, node, target_key, reply_queue):
        ns = self.server.find_neighbors(node, target_key)

        if ns:
            for n in ns:
                self.add_node(n)

        reply_queue.put(ns)


class Bucket(object):
    def __init__(self):
        self.nodes = []
        self.replace_cache = []
