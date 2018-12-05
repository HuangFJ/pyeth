import time
import gevent
from gevent import time
import random
from constants import LOGGER, BUCKET_NUMBER, RE_VALIDATE_INTERVAL, RET_PENDING_OK,\
    BUCKET_SIZE, BUCKET_MIN_DISTANCE


def push_node(collection, node, max_size):
    collection.insert(0, node)
    if len(collection) > max_size:
        return collection.pop()


def del_node(coll, node):
    for ele in list(coll):
        if ele.node_id == node.node_id:
            coll.remove(ele)
            return


def find_farther_to_target_than(arr, t, n):
    for c in arr:
        for i in range(len(t)):
            tc = ord(t[i]) ^ ord(c[i])
            tn = ord(t[i]) ^ ord(n[i])
            if tc > tn:
                return c
            elif tc < tn:
                break


class RoutingTable(object):
    def __init__(self, self_node, server):
        self.buckets = [Bucket() for _ in range(BUCKET_NUMBER)]
        self.self_node = self_node
        self.server = server
        gevent.spawn(self.re_validate)

    def lookup(self, target_key):
        pass

    def re_validate(self):
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
                pending = self.server.ping(last)
                # block
                ret = pending.ret.get()
                bucket = self.buckets[bi]
                if ret == RET_PENDING_OK:
                    # bump node
                    bucket.nodes.insert(0, last)
                else:
                    # pick a replacement
                    if len(bucket.replace_cache) > 0:
                        r = bucket.replace_cache.pop(random.randint(0, len(bucket.replace_cache) - 1))
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
                return
        # bucket is full, push node to replace cache
        if len(bucket.nodes) >= BUCKET_SIZE:
            for rc in bucket.replace_cache:
                if rc.node_id == node.node_id:
                    return

            push_node(bucket.replace_cache, node, BUCKET_SIZE)
            return
        # push node to bucket, delete node from replace cache
        push_node(bucket.nodes, node, BUCKET_SIZE)
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


class Bucket(object):
    def __init__(self):
        self.nodes = []
        self.replace_cache = []
