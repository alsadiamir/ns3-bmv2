#!/usr/bin/env python

# ================
# Author: Sam Gao
# Year:   2021
# ================

import sys
sys.path.insert(0 , '/home/mininet/ns3-repos/ns-3-allinone/ns-3.29/src/bmv2-tools/util/')

import nnpy
import struct
import termcolor as T
import operator
import time
import threading
import argparse

# from config import SUBNET_COUNT, HOST_COUNT

from numpy import std, mean
from sswitch_API import SimpleSwitchAPI

THRIFT_PORT = 9091
DO_LOG = True
COUNTER_SIZE = 256

if DO_LOG:
    def log(s, col="green"):
        print(T.colored(s, col))
else:
    def log(s, col):
        pass

class Controller(object):
    def __init__(self, thrift_port):
        self.controller = SimpleSwitchAPI(thrift_port)
        # self.controller.reset_state()

        # self.is_refinement_running = False
        # self.is_refinement_first_pass = False
        # self.refinement_first_pass_result = None
        # self.current_refinement_handles = []
        # self.refinement_start = None

        # ports = self.controller.client.bm_dev_mgr_show_ports()
        # mc_grp_id = 1
        # rid = 0
        # for port in ports:
        #     other_ports = ports[:] # clone the port
        #     del(other_ports[other_ports.index(port)])
        #     self.controller.mc_mgrp_create(mc_grp_id)
        #     handle = self.controller.mc_node_create(rid, [p.port_num for p in other_ports])
        #     self.controller.mc_node_associate(mc_grp_id, handle)
        #     self.controller.table_add("multicast", "set_mcast_grp", [str(port.port_num)], [str(mc_grp_id)])
        #     rid += 1
        #     mc_grp_id += 1

    # def on_notify(self, msg):
    #     topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
    #                                                                 msg[:32])
    #     self.process_digest(msg, num)
    #     # Acknowledge
    #     self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    # # Clears the counter at counter_idx from the controller.
    # def clear_stat_counter(self, counter_idx):
    #     base = counter_idx * COUNTER_SIZE
    #     for i in range(COUNTER_SIZE):
    #         self.controller.register_write("stats_freq_internal", base + i, 0)
    #         self.controller.register_write("stats_last_clear", base + i, 0)
    #     base = counter_idx * 4
    #     for i in range(4):
    #         self.controller.register_write("stats_data", base + i, 0)

    # def process_digest(self, msg, num_samples):
    #     digest = []
    #     offset = 32
    #     for _ in range(num_samples):
    #         if msg[offset] == 0: # 1-byte digestType
    #             mac0, mac1, ingress_port = struct.unpack(">LHH", msg[offset+1:offset+9])
    #             mac_addr = hex((mac0 << 16) + mac1)
    #             log("learn {} on {}".format(mac_addr, ingress_port))
    #             self.controller.table_add("source", "NoAction", [str(mac_addr)], [])
    #             self.controller.table_add("dest", "forward", [str(mac_addr)], [str(ingress_port)])
    #             offset += 9

    #         elif msg[offset] == 1:
    #             # last bucket, N, mean, stdev
    #             last, n, mean, stdev = struct.unpack(">HHLL", msg[offset+1:offset+13])
    #             log("Traffic volume anomaly detected!")
    #             log("Last = {}, N = {}, NXbar = {}, stdNX = {}".format(last, n, mean, stdev), "red")
    #             if not self.is_refinement_running:
    #                 self.is_refinement_running = True
    #                 self.is_refinement_first_pass = True
    #                 self.refinement_start = time.monotonic()
    #                 log("Installing refinement rules...")
    #                 for i in range(SUBNET_COUNT):
    #                     # Allocate a single index within the refinement counter for subnet.
    #                     handle = self.controller.table_add("dest_prefix_track", "track", ["10.0.{}.0/24".format(i + 1)], [str(i)])
    #                     self.current_refinement_handles.append(handle)
    #             else:
    #                 # ?
    #                 log("A refinement is already in progress. Ignoring this anomaly for now...")
    #             offset += 13
    #         elif msg[offset] == 2:
    #             # Single bit<32> indicating anomalous bucket.
    #             index, = struct.unpack(">L", msg[offset+1:offset+5])
    #             log("Anomalous index found, index = {}".format(index))
    #             if not self.is_refinement_running:
    #                 offset += 5
    #                 continue
                
    #             # We have what we're looking for. Clear the current refinement.
    #             for handle in self.current_refinement_handles:
    #                 self.controller.table_delete("dest_prefix_track", handle)
    #             self.current_refinement_handles = []
                
    #             # Clear counter @ index 1.
    #             self.clear_stat_counter(1)

    #             if self.is_refinement_first_pass:
    #                 # Install a new set of rules.
    #                 for i in range(HOST_COUNT):
    #                     handle = self.controller.table_add("dest_prefix_track", "track", ["10.0.{}.{}/32".format(index + 1, i + 1)], [str(i + 1)])
    #                     self.current_refinement_handles.append(handle)
    #                 self.refinement_first_pass_result = index + 1
    #                 self.is_refinement_first_pass = False
    #             else:
    #                 # Identified source of problem. Cease refinement, and log the result.
    #                 log("Identified problematic destination address = 10.0.{}.{}".format(self.refinement_first_pass_result, index))
    #                 log("Refinement complete.")
    #                 log("Refinement took {}s.".format(time.monotonic() - self.refinement_start))
    #                 self.is_refinement_running = False
    #             offset += 5

    #         else:
    #             log("Unexpected digest type {}.".format(int(msg[offset])))

    #     return digest

    # def read_cluster_statistics_and_update_priorities(self):

    #     # We read the byte counter for each qid (i.e., each cluster)
    #     entries = self.core.get_entries("MyIngress.do_bytes_count", False)
    #     for entry in entries:
    #         key = entry[0]
    #         data = entry[1]
    #         qid = key['queue_id']['value']
    #         counter_value = data['$COUNTER_SPEC_BYTES']

    #         for cluster in self.cluster_list:
    #             if cluster.get_priority() == qid:
    #                 cluster.update_bytes_count(counter_value)

    #     # We compute the new priorities, sorting the clusters by throughput
    #     clusters_by_throughput = {}
    #     list_position = 0
    #     for current_cluster in self.cluster_list:
    #         clusters_by_throughput[list_position] = current_cluster.get_bytes()
    #         list_position = list_position + 1

    #     clusters_by_throughput = sorted(clusters_by_throughput.items(), key=lambda item: item[1])
    #     prio = self.num_clusters - 1
    #     for tuple in clusters_by_throughput:
    #         self.cluster_list[tuple[0]].set_priority(prio) # smaller throughput, bigger priority
    #         prio = prio - 1

    #     # We deploy the new priorities to the data plane
    #     for cluster in self.cluster_list:
    #         self.core.modify_table("MyIngress.cluster_to_prio", [
    #             ([("meta.rs.cluster_id", cluster.get_id())],
    #             "MyIngress.set_qid", [("qid", cluster.get_priority())])
    #         ])

    #     # We reset the packet counters
    #     for qid in range(self.num_clusters):
    #         self.core.clear_counter_bytes("MyIngress.do_bytes_count", "queue_id", qid, 'MyIngress.bytes_count')


    def update_clusters(self):
        bytes_counter = [0] * 4
        for i in range(4):
            bytes_counter[i] = self.controller.register_read("bytes_counter", i)

        for i in range(4):
            self.controller.register_write("bytes_counter", i, 0)

        # Create an array to hold the priorities
        priorities = [0] * 4

        # Sort indices of 'values' based on corresponding values in ascending order
        sorted_indices = sorted(range(4), key=lambda i: bytes_counter[i])

        # Assign priorities based on sorted order
        for priority, index in enumerate(sorted_indices):
            priorities[index] = priority

        # print("Priorities: {}".format(priorities))
        # print("Bytes Counter: {}".format(bytes_counter))

        self.controller.table_clear("cluster_to_prio")

        for priority, index in enumerate(priorities):
            self.controller.table_add("cluster_to_prio", "set_prio_egress", [str(index+1)], [str(priority)])

    def await_notifications(self):
        # sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        # sock = self.controller.client.bm_mgmt_get_info().notifications_socket
        # log("socket = {}".format(sock))
        # sub.connect(sock)
        # sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
        # log("connected to socket.")

        # self.controller.table_add("window_track", "track_time", ["10.0.0.0/8"], [])

        # while True:
        self.update_clusters()
        # self.read_cluster_statistics_and_update_priorities()
        # self.on_notify(sub.recv())
        # time.sleep(5)

parser = argparse.ArgumentParser(description='Cluster Update Controller')
parser.add_argument('--thrift-port', help='Thrift port', type=int, action="store", default=9090, required=False)

if __name__ == "__main__":
    args = parser.parse_args()
    ctrl = Controller(args.thrift_port)
    ctrl.await_notifications()
