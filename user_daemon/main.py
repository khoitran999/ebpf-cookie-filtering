#!/usr/bin/env python3

from bcc import BPF
import bcc
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
import subprocess
import tempfile
import pyroute2

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format="%(asctime)s [%(levelname)s] %(message)s")
# def clear_terminal():
#     os.system('clear')

class PacketAnalyzer:
    def __init__(self):
        self.xdp_function = config["xdp_function"]
        self.tc_function = config["tc_function"]
        self.interface = config["network_interface"]
        self.packet_count_map = None
        self.local_packet_cache = {}  # Local cache for cumulative counts
        self.total_packet_count = 0
        self.captured_packets = []
        self.latest_packet = None


        # struct packet_info {
        #     __u32 src_ip;     // Source IP address
        #     __u32 dst_ip;     // Destination IP address
        #     __u16 src_port;   // Source port
        #     __u16 dst_port;   // Destination port
        #     __u8 protocol;    // IP protocol (TCP/UDP/ICMP etc)
        #     __u8 packet_type; // 0: TCP, 1: UDP, 2: ICMP, etc.
        #     __u32 packet_len; // Total packet length
        #     __u32 seq_num;    // Sequence number
        #     __u32 ack_num;    // Acknowledgment number
        #     __u8 tcp_flags;   // TCP flags
        # };

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
                ("http_data", ct.c_char * 2048),  # MAX_HTTP_DATA = 256
                ("http_data_len", ct.c_uint32),
                ("cookie_data", ct.c_char * 1024),  # MAX_COOKIE_DATA = 1024
                ("cookie_len", ct.c_uint32)
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
        common_code = """
        #define MAX_HTTP_DATA 2048
        #define MAX_COOKIE_DATA 1024

        struct flow_key {
            __u32 src_ip;
            __u32 dst_ip;
            __u16 src_port;
            __u16 dst_port;
            __u32 seq_num;
        };

        struct packet_info {
            __u32 src_ip;     
            __u32 dst_ip;     
            __u16 src_port;   
            __u16 dst_port;   
            __u8 protocol;    
            __u8 packet_type; 
            __u32 packet_len; 
            __u32 seq_num;    
            __u32 ack_num;    
            __u8 tcp_flags;   
            char http_data[MAX_HTTP_DATA];  
            __u32 http_data_len;
            char cookie_data[MAX_COOKIE_DATA];  
            __u32 cookie_len;
        };

        BPF_HASH(xdp_tc_shared, struct flow_key, struct packet_info, 10000);
        BPF_HASH(packet_count, __u32, __u64, 1024);
        BPF_PERF_OUTPUT(cookie_events);
        BPF_PERF_OUTPUT(packet_events);
        BPF_PERCPU_ARRAY(sample_counter, __u64, 1);
        BPF_PERCPU_ARRAY(tmp_packet, struct packet_info, 1);
        """

        # Read the XDP and TC programs
        with open(config["ebpf_program"]["xdp"], 'r') as f:
            xdp_code = f.read()
        with open(config["ebpf_program"]["tc"], 'r') as f:
            tc_code = f.read()

        # Combine all code
        combined_code = common_code + "\n" + xdp_code + "\n" + tc_code

        # Load the combined program
        self.bpf = BPF(text=combined_code, cflags=cflags)

        # Attach the event type to the perf buffer
        self.bpf["cookie_events"].event_type = self.PacketInfo
        for prog_name in self.bpf:
            logging.info("Loaded program: %s", prog_name)


    def attach(self):
        # XDP debug and attachment
        logging.info("Attaching XDP program...")
        xdp_fn = self.bpf.load_func(self.xdp_function, BPF.XDP)
        logging.info(f"XDP function loaded with fd: {xdp_fn.fd}")
        logging.info(f"XDP function name: {xdp_fn.name}")
        logging.info(f"XDP function type: {type(xdp_fn)}")
        
        self.bpf.attach_xdp(self.interface, xdp_fn, 0)
        logging.info("XDP program attached successfully")

        # TC setup with debug
        logging.info("Loading TC program...")
        tc_fn = self.bpf.load_func(self.tc_function, BPF.SCHED_CLS)
        prog_fd = tc_fn.fd
        
        logging.info(f"TC function loaded with fd: {prog_fd}")
        logging.info(f"TC function name: {tc_fn.name}")
        logging.info(f"TC function type: {type(tc_fn)}")

        try:
            ip = pyroute2.IPRoute()
            ipdb = pyroute2.IPDB(nl=ip)
            
            # Get interface index
            idx = ipdb.interfaces[self.interface].index
            logging.info(f"Interface index for {self.interface}: {idx}")
            
            # Remove existing qdisc if it exists
            try:
                ip.tc("del", "clsact", idx)
                logging.info("Removed existing clsact qdisc")
            except Exception as e:
                logging.info(f"No existing qdisc to remove: {e}")
            
            # Add clsact qdisc
            ip.tc("add", "clsact", idx)
            logging.info("Added clsact qdisc")
            
            # Attach the filter
            ip.tc("add-filter", "bpf", idx, ":1", fd=prog_fd,
                    name=tc_fn.name, parent="ffff:fff2", 
                    classid=1, direct_action=True)
            
            logging.info("TC program attached successfully using pyroute2")
            
        except Exception as e:
            logging.error(f"Failed to attach TC program: {e}")
            raise
        finally:
            try:
                ip.close()
                ipdb.release()
            except:
                pass

        # Verify filter attachment
        logging.info("Verifying TC filter attachment:")
        result = subprocess.run(
            ["tc", "filter", "show", "dev", self.interface, "ingress"],
            capture_output=True, text=True
        )
        logging.info(f"TC filters: {result.stdout}")

        # Set up perf buffer callback
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

                # TCP
                print("\n[TCP Header]") 
                print(f"Source Port: {event.src_port}")
                print(f"Dest Port: {event.dst_port}")
                print(f"Seq Number: {event.seq_num}")
                print(f"Ack Number: {event.ack_num}")
                print(f"TCP Flags: {event.tcp_flags:08b}")


                if event.http_data_len > 0:
                    http_data = event.http_data[:event.http_data_len].decode('utf-8', 'ignore')
                    print("\n[HTTP Data]")
                    print(f"HTTP Data Length: {event.http_data_len}")
                    print(f"HTTP Content:\n{http_data}")
                
                protocol_names = {0: "TCP", 1: "UDP", 2: "ICMP"}
                protocol_name = protocol_names.get(event.packet_type, "Unknown")
                
                cookie_data = event.cookie_data[:event.cookie_len].decode('utf-8', 'ignore')
                print("\n[Cookie Data]")
                print(f"Cookie Length: {event.cookie_len}")
                print(f"Cookie Content:\n{cookie_data}")
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
        self.bpf["cookie_events"].open_perf_buffer(print_packet_event)
        self.bpf["packet_events"].open_perf_buffer(print_packet_event)

    def get_packet_deltas(self):
        """
        Compute packet count deltas since the last poll.
        """
        if self.packet_count_map is None:
            logging.warning("Packet count map not initialized")
            return {}
        deltas = {}
        for key, value in self.packet_count_map.items():
            # src_ip = socket.inet_ntoa(struct.pack("!I", key.value))
            src_ip = socket.inet_ntoa(struct.pack('!I', ntohl(key.value)))  # Add ntohl()

            current_count = value.value
            logging.info(f"Current count for {src_ip}: {current_count}")

            # Compute delta
            previous_count = self.local_packet_cache.get(src_ip, 0)
            delta = current_count - previous_count
            deltas[src_ip] = delta

            # Update the local cache
            self.local_packet_cache[src_ip] = current_count

        return deltas

    def log_packet_statistics(self):
        """
        Log cumulative packet statistics.
        """
        logging.info("Cumulative Packet Counts:")
        for ip, count in self.local_packet_cache.items():
            logging.info(f"  {ip}: {count} packets")

    def cleanup(self):
        logging.info("Cleaning up...")
        self.bpf.remove_xdp(self.interface, 0)
        os.system(f"tc qdisc del dev {self.interface} clsact 2>/dev/null")
        os.system(f"rm -rf /sys/fs/bpf/tc/{self.tc_function}")
        self.bpf.cleanup()
    def print_trace_log(self):
        try:
            trace_pipe = open("/sys/kernel/debug/tracing/trace_pipe", "rb")
            while True:
                line = trace_pipe.readline()
                if line:
                    print(f"[TRACE] {line.decode('utf-8', errors='ignore').strip()}")
                    time.sleep(0.1)  # Add 100ms delay between prints

        except KeyboardInterrupt:
            trace_pipe.close()

def main():
   analyzer = PacketAnalyzer()
   analyzer.attach()
   api_url = config["dashboard_api_url"]
   
   from threading import Thread
   trace_thread = Thread(target=analyzer.print_trace_log, daemon=True)
   trace_thread.start()
   try:
       while True:
        #    clear_terminal()
           analyzer.bpf.perf_buffer_poll(timeout=100)
           
           if analyzer.latest_packet:
               p = analyzer.latest_packet
               logging.info("Packet Details:")
               logging.info(f"  Protocol: {p['protocol']}")
               logging.info(f"  Source IP: {p['src_ip']}")
               logging.info(f"  Destination IP: {p['dst_ip']}")
               logging.info(f"  Source Port: {p['src_port']}")
               logging.info(f"  Destination Port: {p['dst_port']}")
               logging.info(f"  Packet Length: {p['packet_len']} bytes")
               if p['packet_type'] == 0:
                   logging.info(f"  Seq Num: {p['seq_num']}, Ack Num: {p['ack_num']}")
                   logging.info(f"  TCP Flags: {p['tcp_flags']}")

               logging.info("\n[HTTP Data]")
               logging.info(f"HTTP Data Length: {p['http_data_len']}")
               logging.info(f"HTTP Content:{p['http_data']}")
               logging.info("---")

           deltas = analyzer.get_packet_deltas()
           for ip, delta in deltas.items():
               if delta > 0:
                   logging.info(f"IP: {ip}, New Packets: {delta}")

           total_packets = sum(analyzer.local_packet_cache.values())
           if total_packets > 0:
               formatted_count = helpers.format_packet_count(total_packets)
               logging.info(f"Total Packets: {formatted_count}")

               data = {"count": total_packets, "packets": analyzer.captured_packets}
               try:
                   response = requests.post(api_url, json=data)
                   if response.status_code != 201:
                       logging.error(f"Failed to send data to dashboard: {response.text}")
               except requests.exceptions.RequestException as e:
                   logging.error(f"Error connecting to dashboard API: {e}")

           time.sleep(60)
   except KeyboardInterrupt:
       logging.info("Stopping packet analyzer daemon.")
   finally:
       analyzer.cleanup()


if __name__ == "__main__":
    main()

