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
    def __init__(self, thrift_port, log_file):
        self.controller = SimpleSwitchAPI(thrift_port)
        self.log = log_file


    def debug_stat4(self):
        registers = self.controller.register_read("stats_freq_internal")
        with open(self.log, "a") as file:
            file.write(f"{registers}\n")


    def await_notifications(self):
        self.debug_stat4()


parser = argparse.ArgumentParser(description='Stat4 Debug Controller')
parser.add_argument('--thrift-port', help='Thrift port', type=int, action="store", default=9090, required=False)
parser.add_argument('--log-file', help='Output log file', type=str, action="store", default="output.log", required=False)

if __name__ == "__main__":
    args = parser.parse_args()
    ctrl = Controller(args.thrift_port, args.log_file)
    ctrl.await_notifications()
