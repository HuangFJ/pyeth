import time

KAD_ALPHA = 3
KAD_BUCKET_SIZE = 16
KAD_ID_SIZE = 256
BUCKET_NUMBER = 17
BUCKET_MIN_DISTANCE = KAD_ID_SIZE - BUCKET_NUMBER


def push_node(collection, node, max_size):
    collection.insert(0, node)
    if len(collection) > max_size:
        return collection.pop()


def del_node(coll, node):
    for ele in list(coll):
        if ele.node_id == node.node_id:
            coll.remove(ele)
            return


class RoutingTable(object):
    def __init__(self, self_node):
        self.buckets = [Bucket() for _ in range(BUCKET_NUMBER)]
        self.self_node = self_node

    def lookup(self, target_key):
        pass

    def find_neighbors(self, target_key):
        pass

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
        if len(bucket.nodes) >= KAD_BUCKET_SIZE:
            for rc in bucket.replace_cache:
                if rc.node_id == node.node_id:
                    return

            push_node(bucket.replace_cache, node, KAD_BUCKET_SIZE)
            return
        # push node to bucket, delete node from replace cache
        push_node(bucket.nodes, node, KAD_BUCKET_SIZE)
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


class Bucket(object):
    def __init__(self):
        self.nodes = []
        self.replace_cache = []
