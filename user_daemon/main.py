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

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format="%(asctime)s [%(levelname)s] %(message)s")

class PacketAnalyzer:
    def __init__(self):
        self.function_name = config["function_name"]
        self.interface = config["network_interface"]
        self.packet_count_map = None
        self.local_packet_cache = {}  # Local cache for cumulative counts
        self.total_packet_count = 0
        self.captured_packets = []

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
        self.bpf = BPF(src_file=config["ebpf_program"], cflags=cflags)

        # Attach the event type to the perf buffer
        self.bpf["packet_events"].event_type = self.PacketInfo

    def attach(self):
        function_name = str(self.function_name)
        fn = self.bpf.load_func(function_name, BPF.XDP)
        self.bpf.attach_xdp(self.interface, fn, 0)
        self.packet_count_map = self.bpf.get_table("packet_count")


        # Set up perf buffer callback
        def print_packet_event(cpu, data, size):
            try:
                # Parse packet event
                event = ctypes.cast(data, ctypes.POINTER(self.PacketInfo)).contents


                # Convert IP addresses to human-readable format
                src_ip = socket.inet_ntoa(struct.pack("!I", event.src_ip))
                dst_ip = socket.inet_ntoa(struct.pack("!I", event.dst_ip))

                # Determine protocol name
                protocol_names = {0: "TCP", 1: "UDP", 2: "ICMP"}
                protocol_name = protocol_names.get(event.packet_type, "Unknown")

                # Log detailed packet information
                logging.info("Packet Details:")
                logging.info(f"  Protocol: {protocol_name}")
                logging.info(f"  Source: {src_ip}:{event.src_port}")
                logging.info(f"  Destination: {dst_ip}:{event.dst_port}")
                logging.info(f"  Packet Length: {event.packet_len} bytes")

                # Log TCP-specific information
                if event.packet_type == 0:
                    logging.info(f"  Seq Num: {event.seq_num}, Ack Num: {event.ack_num}")
                    logging.info(f"  TCP Flags: {event.tcp_flags}")

                logging.info("---")

                # Increment total packet count
                self.total_packet_count += 1
                # Store the packet in the captured packets list
                packet_dict = {
                    "protocol": protocol_name,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": event.src_port,
                    "dst_port": event.dst_port,
                    "packet_len": event.packet_len,
                    "seq_num": event.seq_num,
                    "ack_num": event.ack_num,
                    "tcp_flags": event.tcp_flags,
                    "packet_type": protocol_name[event.packet_type]
                }
                self.captured_packets.append(packet_dict)
            except Exception as e:
                logging.error(f"Error processing packet event: {e}")

        # Open perf buffer with the callback
        self.bpf["packet_events"].open_perf_buffer(print_packet_event)

    def get_packet_deltas(self):
        """
        Compute packet count deltas since the last poll.
        """
        deltas = {}
        for key, value in self.packet_count_map.items():
            src_ip = socket.inet_ntoa(struct.pack("!I", key.value))
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
        self.bpf.remove_xdp(self.interface, 0)
        self.bpf.cleanup()


def main():
    analyzer = PacketAnalyzer()
    analyzer.attach()
    api_url = config["dashboard_api_url"]


    logging.info("Starting packet analyzer daemon. Press Ctrl+C to stop.")

    try:
        while True:
            # Poll for perf buffer events
            analyzer.bpf.perf_buffer_poll(timeout=100)

            # Get and log packet deltas
            deltas = analyzer.get_packet_deltas()
            for ip, delta in deltas.items():
                logging.info(f"IP: {ip}, New Packets: {delta}")

            # Send cumulative counts to the dashboard
            total_packets = sum(analyzer.local_packet_cache.values())
            if total_packets > 0:
                formatted_count = helpers.format_packet_count(total_packets)
                logging.info(f"Total Packets: {formatted_count}")

                data = {
                    "count": total_packets,
                    "packets": analyzer.captured_packets
                    }
                try:
                    response = requests.post(api_url, json=data)
                    if response.status_code != 201:
                        logging.error(f"Failed to send data to dashboard: {response.text}")
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error connecting to dashboard API: {e}")

            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping packet analyzer daemon.")
    finally:
        analyzer.cleanup()


if __name__ == "__main__":
    main()
