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

class PacketAnalyzer:
    def __init__(self):
        self.function_name = config["cookie_trace_function"]
        self.interface = config["network_interface"]
        self.total_packet_count = 0
        self.captured_packets = []
        self.latest_packet = None

        # Define the packet info structure using ctypes
        class PacketInfo(ctypes.Structure):
            _fields_ = [
                ("src_ip", ctypes.c_uint32),
                ("dst_ip", ctypes.c_uint32),
                ("src_port", ctypes.c_uint16),
                ("dst_port", ctypes.c_uint16),
                ("protocol", ctypes.c_uint8),
                ("packet_type", ctypes.c_uint8),
                ("packet_len", ctypes.c_uint32),
                ("seq_num", ctypes.c_uint32),
                ("ack_num", ctypes.c_uint32),
                ("tcp_flags", ctypes.c_uint8),
                ("http_data", ct.c_char * 256),  # MAX_HTTP_DATA = 256
                ("http_data_len", ct.c_uint32)
            ]

        self.PacketInfo = PacketInfo

        # Kernel headers discovery
        kernel_headers = f"/lib/modules/{os.uname().release}/build"
        cflags = [
            f"-I{kernel_headers}/include",
            f"-I{kernel_headers}/include/uapi",
            f"-I{kernel_headers}/arch/{os.uname().machine}/include",
            "-I/usr/include",
            "-I/usr/include/bcc",
            "-D__KERNEL__",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
        ]

        # Load BPF program
        self.bpf = BPF(src_file=config["cookie_trace_program"], cflags=cflags)

        # Attach the event type to the perf buffer
        self.bpf["packet_events"].event_type = self.PacketInfo

    def print_trace_log(self):
        try:
            trace_pipe = open("/sys/kernel/debug/tracing/trace_pipe", "rb")
            while True:
                line = trace_pipe.readline()
                if line:
                    print(f"[TRACE] {line.decode('utf-8', errors='ignore').strip()}")
        except KeyboardInterrupt:
            trace_pipe.close()
    def cleanup(self):
        self.bpf.remove_xdp(self.interface, 0)
        self.bpf.cleanup()
        
    def attach(self):
        function_name = str(self.function_name)
        fn = self.bpf.load_func(function_name, BPF.XDP)
        self.bpf.attach_xdp(self.interface, fn, 0)

        

        # Set up perf buffer callback, for when receiving a packet ==> print
        def print_packet_event(cpu, data, size):
            try:
                event = ctypes.cast(data, ctypes.POINTER(self.PacketInfo)).contents
                print("=== Full TCP/IP Packet ===")

                # Ethernet
                print("\n[Ethernet Header]")
                print(f"Packet Length: {event.packet_len} bytes")

                # IP 
                print("\n[IP Header]")
                src_ip = socket.inet_ntoa(struct.pack('!I', ntohl(event.src_ip)))  # Add ntohl()
                dst_ip = socket.inet_ntoa(struct.pack('!I', ntohl(event.dst_ip)))
                print(f"Source IP: {src_ip}")
                print(f"Dest IP: {dst_ip}")
                print(f"Protocol: {event.protocol}")

                # # TCP
                # print("\n[TCP Header]") 
                # print(f"Source Port: {event.src_port}")
                # print(f"Dest Port: {event.dst_port}")
                # print(f"Seq Number: {event.seq_num}")
                # print(f"Ack Number: {event.ack_num}")
                # print(f"TCP Flags: {event.tcp_flags:08b}")


                if event.http_data_len > 0:
                    http_data = event.http_data[:event.http_data_len].decode('utf-8', 'ignore')
                    print("\n[HTTP Data]")
                    print(f"HTTP Data Length: {event.http_data_len}")
                    print(f"HTTP Content:\n{http_data}")
                
                protocol_names = {0: "TCP", 1: "UDP", 2: "ICMP"}
                protocol_name = protocol_names.get(event.packet_type, "Unknown")
                
                self.latest_packet = {
                    "protocol": protocol_name,
                    "src_ip": src_ip,
                    "src_port": event.src_port,
                    "dst_ip": dst_ip,
                    "dst_port": event.dst_port,
                    "packet_len": event.packet_len,
                    "seq_num": event.seq_num,
                    "ack_num": event.ack_num,
                    "packet_type": event.packet_type,
                    "tcp_flags": event.tcp_flags,
                    "http_data": event.http_data[:event.http_data_len].decode('utf-8', 'ignore') if event.http_data_len > 0 else "",
                    "http_data_len": event.http_data_len
                }
                
                self.total_packet_count += 1
                self.captured_packets.append(self.latest_packet)
            except Exception as e:
                logging.error(f"Error processing packet event: {e}")

        # Open perf buffer with the callback
        self.bpf["packet_events"].open_perf_buffer(print_packet_event)


def main():
   analyzer = PacketAnalyzer()
   analyzer.attach()
   
   from threading import Thread
   trace_thread = Thread(target=analyzer.print_trace_log, daemon=True)
   trace_thread.start()

   try:
       while True:
           #polls performance buffer so that it will execute the callback function when receive data
           #wait 100 second before 
           analyzer.bpf.perf_buffer_poll(timeout=100) 

           
        #    if analyzer.latest_packet:
        #        p = analyzer.latest_packet
        #        logging.info("Packet Details:")
        #        logging.info(f"  Protocol: {p['protocol']}")
        #        logging.info(f"  Source IP: {p['src_ip']}")
        #        logging.info(f"  Destination IP: {p['dst_ip']}")
        #        logging.info(f"  Source Port: {p['src_port']}")
        #        logging.info(f"  Destination Port: {p['dst_port']}")
        #        logging.info(f"  Packet Length: {p['packet_len']} bytes")
        #        if p['packet_type'] == 0:
        #            logging.info(f"  Seq Num: {p['seq_num']}, Ack Num: {p['ack_num']}")
        #            logging.info(f"  TCP Flags: {p['tcp_flags']}")

        #        logging.info("\n[HTTP Data]")
        #        logging.info(f"HTTP Data Length: {p['http_data_len']}")
        #        logging.info(f"HTTP Content:{p['http_data']}")
        #        logging.info("---")

   except KeyboardInterrupt:
       logging.info("Stopping packet analyzer daemon.")
   finally:
       analyzer.cleanup()


if __name__ == "__main__":
    main()
