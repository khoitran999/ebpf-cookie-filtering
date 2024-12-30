#!/usr/bin/env python3

from bcc import BPF
from config import config
import utils.helper_functions as helpers
import requests
import time
import logging
import socket
import struct
import os
import ctypes
from socket import ntohl
import ctypes as ct


# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format="%(asctime)s [%(levelname)s] %(message)s")
def clear_terminal():
    os.system('clear')

class TCDropper:
    def __init__(self):
        self.interface = config["network_interface"]
        self.bpf = BPF(src_file="../ebpf_module/tc_filter.c")




    def attach(self):
        fn = self.bpf.load_func("tc_filter_src_ip", BPF.SCHED_CLS)
        # self.bpf.attach_xdp(self.interface, fn, 0)
        self.bpf.attach_kprobe()
        # self.bpf.attach_kprobe(event="ingress", fn)
        # self.bpf.attach_kprobe(event="__netif_receive_skb", f=fn)

    def cleanup(self):
        self.bpf.remove_xdp(self.interface, 0)
        self.bpf.cleanup()

def main():
    dropper = TCDropper()
    dropper.attach()
    try: 
        while True:
            continue
    except KeyboardInterrupt:
       logging.info("Stopping packet dropper daemon.")
    finally:
        dropper.cleanup()



if __name__ == "__main__":
    main()
